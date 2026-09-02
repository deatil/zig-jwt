const std = @import("std");
const Allocator = std.mem.Allocator;

pub const max_modulus_bits = 4096;

pub const Uint = std.crypto.ff.Uint(max_modulus_bits);
pub const Modulus = std.crypto.ff.Modulus(max_modulus_bits);
pub const Fe = Modulus.Fe;

const BigInt = std.math.big.int.Managed;

pub const max_modulus_len = max_modulus_bits / 8;
pub const min_modulus_bits = 512;

pub fn byteLen(bit_count: usize) usize {
    return (bit_count + 7) / 8;
}

pub fn stripLeadingZeros(bytes: []const u8) []const u8 {
    var i: usize = 0;
    while (i < bytes.len and bytes[i] == 0) : (i += 1) {}
    return bytes[i..];
}

pub fn beToLimbs(comptime slot: usize, be: []const u8) [slot]u64 {
    var v = [_]u64{0} ** slot;
    var idx: usize = 0;
    var i: usize = be.len;
    while (i > 0) : (idx += 8) {
        i -= 1;
        const limb = idx >> 6;
        if (limb >= slot) break; // branch on public position, not on any value
        v[limb] |= @as(u64, be[i]) << @intCast(idx & 63);
    }
    return v;
}

const big_capacity = (2 * max_modulus_bits) / @bitSizeOf(std.math.big.Limb) + 4;

pub fn newBig(gpa: Allocator) !BigInt {
    return BigInt.initCapacity(gpa, big_capacity);
}

/// Big-endian unsigned bytes -> `BigInt`.
pub fn bigFromBytes(gpa: Allocator, bytes: []const u8) !BigInt {
    var x = try newBig(gpa);
    if (bytes.len == 0) {
        try x.set(0);
        return x;
    }

    try x.ensureCapacity(bytes.len / @sizeOf(std.math.big.Limb) + 2);
    var m = x.toMutable();
    m.readTwosComplement(bytes, bytes.len * 8, .big, .unsigned);
    x.setMetadata(m.positive, m.len);
    return x;
}

pub fn bigFromFe(gpa: Allocator, fe: Fe) !BigInt {
    var buf: [max_modulus_len]u8 = undefined;
    try fe.toBytes(&buf, .big);

    const new_buf = stripLeadingZeros(&buf);

    return bigFromBytes(gpa, new_buf);
}

/// Non-negative `BigInt` -> canonical `Fe` of `m` (fails if out of range).
pub fn feFromBig(m: Modulus, x: *const BigInt) !Fe {
    if (!x.isPositive() and !x.eqlZero()) return error.InvalidPrivateKey;
    if (x.bitCountAbs() > max_modulus_bits) return error.InvalidPrivateKey;
    var buf: [max_modulus_len]u8 = undefined;
    x.toConst().writeTwosComplement(&buf, .big);
    return Fe.fromBytes(m, &buf, .big);
}

pub fn bigModInverse(gpa: Allocator, e: *const BigInt, m: *const BigInt) !BigInt {
    // Invariants: t0*e ≡ r0, t1*e ≡ r1 (mod m).
    var r0 = try newBig(gpa);
    try r0.copy(m.toConst());
    var r1 = try newBig(gpa);
    try r1.copy(e.toConst());
    var t0 = try newBig(gpa);
    try t0.set(0);
    var t1 = try newBig(gpa);
    try t1.set(1);
    var quot = try newBig(gpa);
    var rem = try newBig(gpa);
    var tmp = try newBig(gpa);
    var new_t = try newBig(gpa);

    defer r0.deinit();
    defer r1.deinit();
    defer t0.deinit();
    defer t1.deinit();
    defer quot.deinit();
    defer tmp.deinit();
    defer new_t.deinit();

    while (!r1.eqlZero()) {
        try quot.divFloor(&rem, &r0, &r1);

        // (r0, r1) <- (r1, r0 mod r1)
        r0.swap(&r1);
        r1.swap(&rem);

        // (t0, t1) <- (t1, t0 - quot*t1)
        try tmp.mul(&quot, &t1);
        try new_t.sub(&t0, &tmp);

        t0.swap(&t1);
        t1.swap(&new_t);
    }

    // r0 = gcd(e, m); must be 1 for e to be invertible.
    if (r0.toConst().orderAgainstScalar(1) != .eq) return error.InvalidPrivateKey;

    // t0*e ≡ 1 (mod m); normalize t0 (possibly negative) into [0, m).
    try quot.divFloor(&rem, &t0, m);

    return rem;
}

pub fn reduceWide(m: Modulus, x: Uint) Fe {
    var xx = x;
    if (xx.limbs_len < m.v.limbs_len) {
        @memset(xx.limbs_buffer[xx.limbs_len..m.v.limbs_len], 0);
        xx.limbs_len = m.v.limbs_len;
    }
    return m.reduce(xx);
}

/// `r⁻¹ mod n` as big-endian bytes into `out` (returns the written slice), or
/// `null` if `r` is not a unit mod n. Extended-Euclid via `std.math.big.int` on
/// a stack arena — variable-time, but only ever on the public modulus and a
/// random `r`, never on secret key material.
pub fn invModN(n_be: []const u8, r_be: []const u8, out: *[max_modulus_len]u8) ?[]const u8 {
    var scratch: [96 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    const gpa = fba.allocator();
    var r_big = bigFromBytes(gpa, r_be) catch return null;
    var n_big = bigFromBytes(gpa, n_be) catch return null;
    var inv = bigModInverse(gpa, &r_big, &n_big) catch return null; // gcd != 1 -> null
    if (inv.bitCountAbs() > max_modulus_bits) return null;
    inv.toConst().writeTwosComplement(out, .big); // left-zero-padded to out.len
    return out[0..];
}

/// 1 if `x == y`, else 0 — branchless.
pub fn ctEqByte(x: u8, y: u8) u8 {
    const diff: u16 = x ^ y;
    return @truncate(((diff -% 1) >> 8) & 1);
}

/// `if (v == 1) a else b` for v in {0, 1} — branchless.
pub fn ctSelect(v: u8, a: usize, b: usize) usize {
    const mask = @as(usize, 0) -% v; // all-ones iff v == 1
    return (a & mask) | (b & ~mask);
}

/// Miller-Rabin rounds per candidate — see the section comment above for the
/// FIPS 186-5 Table B.1 rationale.
const mr_rounds = 64;

/// Odd primes below 1024 for the trial-division pre-sieve, generated at
/// comptime (sieve of Eratosthenes). Filters ~84% of random odd candidates
/// with cheap byte-wise remainders before any Miller-Rabin modexp runs.
const sieve_primes = blk: {
    @setEvalBranchQuota(20_000);
    const limit = 1024;
    var composite = [_]bool{false} ** limit;
    var count: usize = 0;
    var i: usize = 3;
    while (i < limit) : (i += 2) {
        if (composite[i]) continue;
        count += 1;
        var j = i * i;
        while (j < limit) : (j += 2 * i) composite[j] = true;
    }
    var list: [count]u16 = undefined;
    var idx: usize = 0;
    i = 3;
    while (i < limit) : (i += 2) {
        if (composite[i]) continue;
        list[idx] = i;
        idx += 1;
    }
    break :blk list;
};

/// Big-endian unsigned `bytes` mod `divisor` (u128 intermediate: safe for any
/// u64 divisor). Used for the pre-sieve and the p mod e reduction only —
/// variable-time, never touches a kept secret in a data-dependent way beyond
/// the (public-fate) reject/accept decision itself.
pub fn bytesMod(bytes: []const u8, divisor: u64) u64 {
    std.debug.assert(divisor != 0);
    var r: u64 = 0;
    for (bytes) |b| {
        r = @intCast(((@as(u128, r) << 8) | b) % divisor);
    }
    return r;
}

/// In-place big-endian right shift by `s` bits (zero-fill from the left).
pub fn shrBytesBe(buf: []u8, s: usize) void {
    const byte_sh = s / 8;
    const bit_sh: u4 = @intCast(s % 8);
    var i: usize = buf.len;
    while (i > 0) {
        i -= 1;
        const lo: u16 = if (i >= byte_sh) buf[i - byte_sh] else 0;
        const hi: u16 = if (i >= byte_sh + 1) buf[i - byte_sh - 1] else 0;
        buf[i] = @truncate(((hi << 8) | lo) >> bit_sh);
    }
}

/// Set bit `bit` (LSB = 0) of a big-endian byte string.
pub fn setBitBe(buf: []u8, bit: usize) void {
    buf[buf.len - 1 - bit / 8] |= @as(u8, 1) << @intCast(bit % 8);
}

/// Uniform random Miller-Rabin witness in [2, n-2] by rejection sampling
/// (mask to n's bit length, retry on out-of-range — expected < 2 draws).
pub fn randomWitness(m: Modulus, random: std.Random) Fe {
    const n_bits = m.bits();
    const n_len = byteLen(n_bits);
    const n_minus_1 = m.sub(m.zero, m.one());
    var buf: [max_modulus_len]u8 = undefined;
    defer std.crypto.secureZero(u8, buf[0..n_len]);
    while (true) {
        random.bytes(buf[0..n_len]);
        buf[0] &= @as(u8, 0xff) >> @intCast(8 * n_len - n_bits);
        const a = Fe.fromBytes(m, buf[0..n_len], .big) catch continue; // >= n: redraw
        if (a.isZero() or a.eql(m.one()) or a.eql(n_minus_1)) continue; // outside [2, n-2]
        return a;
    }
}

/// Miller-Rabin probable-prime test with `mr_rounds` random witnesses from
/// `random`. `m` must be an odd integer >= 5 (every `Modulus` is odd by
/// construction; callers here only ever pass >= 2^255). Returns false iff a
/// witness proves `m` composite.
pub fn isProbablePrime(m: Modulus, random: std.Random) bool {
    const n_len = byteLen(m.bits());

    // n - 1 = d * 2^s with d odd: n is odd, so n-1 is just n with the low
    // bit cleared, s = ctz(n-1) >= 1, d = (n-1) >> s.
    var d_buf: [max_modulus_len]u8 = undefined;
    defer std.crypto.secureZero(u8, d_buf[0..n_len]);
    m.toBytes(d_buf[0..n_len], .big) catch unreachable; // buffer is exactly byteLen(bits)
    d_buf[n_len - 1] &= 0xfe;
    var s: usize = 0;
    var i: usize = n_len;
    while (i > 0) {
        i -= 1;
        if (d_buf[i] == 0) {
            s += 8;
        } else {
            s += @ctz(d_buf[i]);
            break;
        }
    }
    shrBytesBe(d_buf[0..n_len], s);
    const d_bytes = stripLeadingZeros(d_buf[0..n_len]);

    const one = m.one();
    const n_minus_1 = m.sub(m.zero, one);

    var round: usize = 0;
    rounds: while (round < mr_rounds) : (round += 1) {
        const a = randomWitness(m, random);
        // a^d mod n — constant-time modexp (the exponent d is n-derived).
        var x = m.powWithEncodedExponent(a, d_bytes, .big) catch unreachable; // d is odd, never 0
        if (x.eql(one) or x.eql(n_minus_1)) continue :rounds;
        var j: usize = 1;
        while (j < s) : (j += 1) {
            x = m.sq(x);
            if (x.eql(n_minus_1)) continue :rounds;
            // A nontrivial square root of 1: composite for sure — stop early.
            if (x.eql(one)) return false;
        }
        return false; // never hit n-1: `a` witnesses compositeness
    }
    return true;
}

/// Draw random odd candidates of exactly `prime_bits` bits with the top two
/// bits set (so p·q of two such primes always reaches 2·`prime_bits` bits),
/// pre-sieve by trial division, enforce gcd(e, candidate-1) = 1, and
/// Miller-Rabin test until a probable prime lands in `out`
/// (`out.len == byteLen(prime_bits)`).
pub fn generatePrime(random: std.Random, prime_bits: usize, e: u64, out: []u8) void {
    std.debug.assert(out.len == byteLen(prime_bits));
    std.debug.assert(prime_bits >= 128); // callers: >= 256 (bits >= 512)
    const top_mask = @as(u8, 0xff) >> @intCast(8 * out.len - prime_bits);
    candidates: while (true) {
        random.bytes(out);
        out[0] &= top_mask;
        setBitBe(out, prime_bits - 1); // exact bit length…
        setBitBe(out, prime_bits - 2); // …and p·q >= 2^(2·prime_bits - 1)
        out[out.len - 1] |= 1; // odd

        // Trial-division pre-sieve. Candidates are >= 2^127, so a zero
        // remainder always means a proper factor, never candidate == prime.
        for (sieve_primes) |sp| {
            if (bytesMod(out, sp) == 0) continue :candidates;
        }

        // gcd(e, p-1) = 1, via (p-1) mod e: e | p-1 (rem 0) or a shared
        // factor both make e non-invertible mod λ(n) — reject either way.
        const p_mod_e = bytesMod(out, e);
        const p1_mod_e = (p_mod_e + e - 1) % e; // no overflow: e < 2^32
        if (p1_mod_e == 0 or std.math.gcd(e, p1_mod_e) != 1) continue :candidates;

        // Odd, >= 3, <= max_modulus_len bytes: Modulus.fromBytes can't fail.
        const m = Modulus.fromBytes(out, .big) catch unreachable;
        if (isProbablePrime(m, random)) return;
    }
}

/// FIPS 186-5 §A.1.3 closeness guard: reject q when the top 100 bits of p
/// and q coincide (a sufficient condition for |p − q| <= 2^(plen − 100),
/// which would expose n to Fermat factorization). Also subsumes p == q.
pub fn topBitsMatch(p: []const u8, q: []const u8) bool {
    std.debug.assert(p.len == q.len and p.len >= 13);
    if (!std.mem.eql(u8, p[0..12], q[0..12])) return false; // 96 bits
    return (p[12] ^ q[12]) & 0xf0 == 0; // + 4 more = 100 bits
}
