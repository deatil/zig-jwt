// SPDX-License-Identifier: MIT

//! The P-521 base field, GF(p) with p = 2^521 − 1 (a Mersenne prime).
//!
//! Representation: nine unsaturated limbs in radix 2^58, `l[0..8]` of 58 bits
//! and `l[8]` of 57 (8·58 + 57 = 521). Because 2^521 ≡ 1 (mod p), a product
//! term at limb position i + j ≥ 9 folds back to position i + j − 9 with a
//! factor 2 (2^(58·9) = 2^522 = 2·2^521 ≡ 2), and the carry out of the top
//! limb's bit 57 re-enters limb 0 unchanged. Reduction is therefore shifts and
//! adds only — no multiplication by a reduction constant, no Montgomery form.
//!
//! Every operation is branch-free and table-free in its inputs.
//!
//! ## Limb bounds (pinned by `field.zig` "carry bounds" tests)
//!
//! "Tight" — what every operation here returns: l[0], l[2..7] < 2^58,
//! l[1] < 2^58 + 2^9, l[8] < 2^57. The value may be ≥ p (up to < 2^522);
//! `canonical` brings it into [0, p) for encoding and comparison only.
//!
//! `mul`/`sq` accept limbs < 2^61 (each column is a sum of nine products
//! < 2^61 · 2^62 = 2^123, so < 2^126.2 — u128 holds it with room for the
//! carries). Tight inputs are far inside that. `add`/`sub` accept tight
//! inputs and carry before returning, so every result is tight again; `sub`
//! adds 4p (limbs 2^60 − 4, top 2^59 − 4), which exceeds any tight limb, so
//! no limb goes negative.

const std = @import("std");
const NonCanonicalError = std.crypto.errors.NonCanonicalError;
const NotSquareError = std.crypto.errors.NotSquareError;

const M58: u64 = (1 << 58) - 1;
const M57: u64 = (1 << 57) - 1;

/// 4p in limb form: added before a subtraction so no limb underflows.
const four_p: [9]u64 = .{ M58 << 2, M58 << 2, M58 << 2, M58 << 2, M58 << 2, M58 << 2, M58 << 2, M58 << 2, M57 << 2 };

/// An element of GF(2^521 − 1).
pub const Fe = struct {
    l: [9]u64,

    /// The field order p = 2^521 − 1.
    pub const field_order: u521 = std.math.maxInt(u521);
    /// Bits in the field order.
    pub const field_bits = 521;
    /// Bits a canonical encoding can carry.
    pub const saturated_bits = 528;
    /// Length of a serialized element (bytes).
    pub const encoded_length = 66;

    pub const zero: Fe = .{ .l = @splat(0) };
    pub const one: Fe = .{ .l = .{ 1, 0, 0, 0, 0, 0, 0, 0, 0 } };

    /// An element from an integer; `error.NonCanonical` if it is ≥ p.
    pub fn fromInt(comptime x: u528) NonCanonicalError!Fe {
        if (x >= field_order) return error.NonCanonical;
        var r: Fe = undefined;
        var v: u528 = x;
        inline for (0..8) |i| {
            r.l[i] = @truncate(v & M58);
            v >>= 58;
        }
        r.l[8] = @truncate(v);
        return r;
    }

    /// Decode 66 bytes. `error.NonCanonical` unless the value is < p (the
    /// top 7 bits of the 528-bit string must be zero and the value must not
    /// be p itself). The check is computed without branching on the bytes;
    /// the single branch is on the verdict, which the error reveals anyway.
    pub fn fromBytes(s_: [encoded_length]u8, endian: std.builtin.Endian) NonCanonicalError!Fe {
        var s = s_;
        if (endian == .big) std.mem.reverse(u8, &s);
        var r: Fe = undefined;
        inline for (0..9) |i| {
            const bit = 58 * i;
            const byte = bit / 8;
            const sh = bit % 8;
            var w: u128 = 0;
            inline for (0..9) |j| {
                if (byte + j < encoded_length) w |= @as(u128, s[byte + j]) << (8 * j);
            }
            const mask: u64 = if (i == 8) M57 else M58;
            r.l[i] = @as(u64, @truncate(w >> sh)) & mask;
        }
        // All limbs at their mask = the value p (the one non-canonical value
        // below 2^521).
        var not_p: u64 = 0;
        inline for (0..8) |i| not_p |= r.l[i] ^ M58;
        not_p |= r.l[8] ^ M57;
        const high = @as(u64, s[65] >> 1);
        const bad = (high | @intFromBool(not_p == 0)) != 0;
        if (bad) return error.NonCanonical;
        return r;
    }

    /// Encode as 66 bytes (canonical, value in [0, p)).
    pub fn toBytes(a: Fe, endian: std.builtin.Endian) [encoded_length]u8 {
        const c = a.canonical();
        var out: [encoded_length]u8 = @splat(0);
        var acc: u128 = 0;
        comptime var nbits = 0;
        comptime var k = 0;
        inline for (0..9) |i| {
            acc |= @as(u128, c[i]) << nbits;
            nbits += if (i == 8) 57 else 58;
            inline while (nbits >= 8) {
                out[k] = @truncate(acc);
                acc >>= 8;
                nbits -= 8;
                k += 1;
            }
        }
        out[k] = @truncate(acc);
        if (endian == .big) std.mem.reverse(u8, &out);
        return out;
    }

    /// The fully reduced limbs: value in [0, p), every limb within its mask.
    /// Valid for any input below 2^522, which every tight value is.
    fn canonical(a: Fe) [9]u64 {
        var r = a.l;
        inline for (0..2) |_| {
            inline for (0..8) |i| {
                r[i + 1] += r[i] >> 58;
                r[i] &= M58;
            }
            const c = r[8] >> 57;
            r[8] &= M57;
            r[0] += c;
        }
        // Now 0 ≤ v ≤ p. v == p iff v + 1 carries out of bit 521; then the
        // masked v + 1 is the canonical 0.
        var t: [9]u64 = undefined;
        var carry: u64 = 1;
        inline for (0..9) |i| {
            const s = r[i] + carry;
            const bits = if (i == 8) 57 else 58;
            t[i] = s & ((@as(u64, 1) << bits) - 1);
            carry = s >> bits;
        }
        const m = 0 -% carry;
        inline for (0..9) |i| r[i] = (t[i] & m) | (r[i] & ~m);
        return r;
    }

    /// Carry pass over limbs that may exceed their width (< 2^62 each):
    /// the result is tight.
    inline fn weak(l_: [9]u64) Fe {
        var r = l_;
        inline for (0..8) |i| {
            r[i + 1] += r[i] >> 58;
            r[i] &= M58;
        }
        const c = r[8] >> 57;
        r[8] &= M57;
        r[0] += c;
        r[1] += r[0] >> 58;
        r[0] &= M58;
        return .{ .l = r };
    }

    /// Carry a column vector (each < 2^127) into a tight element.
    inline fn reduceWide(c_: [9]u128) Fe {
        var c = c_;
        inline for (0..8) |i| {
            c[i + 1] += c[i] >> 58;
            c[i] &= M58;
        }
        const top = c[8] >> 57;
        c[8] &= M57;
        c[0] += top;
        c[1] += c[0] >> 58;
        c[0] &= M58;
        var r: Fe = undefined;
        inline for (0..9) |i| r.l[i] = @truncate(c[i]);
        return r;
    }

    pub fn add(a: Fe, b: Fe) Fe {
        var r: [9]u64 = undefined;
        inline for (0..9) |i| r[i] = a.l[i] + b.l[i];
        return weak(r);
    }

    pub fn sub(a: Fe, b: Fe) Fe {
        var r: [9]u64 = undefined;
        inline for (0..9) |i| r[i] = (a.l[i] + four_p[i]) - b.l[i];
        return weak(r);
    }

    pub fn neg(a: Fe) Fe {
        return zero.sub(a);
    }

    pub fn dbl(a: Fe) Fe {
        return a.add(a);
    }

    /// Multiply by a small public constant (< 2^3).
    pub fn mulSmall(a: Fe, comptime k: u64) Fe {
        comptime std.debug.assert(k < 8);
        var r: [9]u64 = undefined;
        inline for (0..9) |i| r[i] = a.l[i] * k;
        return weak(r);
    }

    pub fn mul(a: Fe, b: Fe) Fe {
        var b2: [9]u64 = undefined;
        inline for (0..9) |i| b2[i] = b.l[i] << 1;
        var c: [9]u128 = undefined;
        inline for (0..9) |k| {
            // Two accumulators per column (even and odd i): two independent
            // add/adc chains instead of one nine deep, so the multiplies
            // overlap. Same sum, same bound.
            var acc: [2]u128 = .{ 0, 0 };
            inline for (0..9) |i| {
                if (i <= k) {
                    acc[i & 1] += @as(u128, a.l[i]) * b.l[k - i];
                } else {
                    acc[i & 1] += @as(u128, a.l[i]) * b2[k + 9 - i];
                }
            }
            c[k] = acc[0] + acc[1];
        }
        return reduceWide(c);
    }

    pub fn sq(a: Fe) Fe {
        var a2: [9]u64 = undefined;
        var a4: [9]u64 = undefined;
        inline for (0..9) |i| {
            a2[i] = a.l[i] << 1;
            a4[i] = a.l[i] << 2;
        }
        var c: [9]u128 = @splat(0);
        inline for (0..9) |i| {
            inline for (i..9) |j| {
                const f = (if (i != j) 2 else 1) * (if (i + j >= 9) 2 else 1);
                const bj = switch (f) {
                    1 => a.l[j],
                    2 => a2[j],
                    4 => a4[j],
                    else => unreachable,
                };
                c[(i + j) % 9] += @as(u128, a.l[i]) * bj;
            }
        }
        return reduceWide(c);
    }

    /// `mul` forced inline at the call site: the point formulas use it so
    /// independent products overlap (LLVM keeps `mul` out of line otherwise).
    pub inline fn mulI(a: Fe, b: Fe) Fe {
        @setEvalBranchQuota(100_000);
        return @call(.always_inline, mul, .{ a, b });
    }

    /// `sq`, forced inline (see `mulI`).
    pub inline fn sqI(a: Fe) Fe {
        @setEvalBranchQuota(100_000);
        return @call(.always_inline, sq, .{a});
    }

    /// `n` successive squarings (n is public).
    pub fn sqn(a: Fe, comptime n: usize) Fe {
        var r = a;
        for (0..n) |_| r = r.sq();
        return r;
    }

    /// a^(p−2) = a⁻¹ (0 for 0), by a fixed addition chain: constant time.
    /// p − 2 = 2^521 − 3: bits 520..2 set, bit 1 clear, bit 0 set.
    pub fn invert(a: Fe) Fe {
        const x2 = a.sq().mul(a); // 2^2 − 1
        const x3 = x2.sq().mul(a); // 2^3 − 1
        const x4 = x2.sqn(2).mul(x2);
        const x7 = x4.sqn(3).mul(x3);
        const x8 = x4.sqn(4).mul(x4);
        const x16 = x8.sqn(8).mul(x8);
        const x32 = x16.sqn(16).mul(x16);
        const x64 = x32.sqn(32).mul(x32);
        const x128 = x64.sqn(64).mul(x64);
        const x256 = x128.sqn(128).mul(x128);
        const x512 = x256.sqn(256).mul(x256);
        const x519 = x512.sqn(7).mul(x7);
        return x519.sqn(2).mul(a); // 2^521 − 4 + 1
    }

    /// A square root. p ≡ 3 (mod 4), so it is a^((p+1)/4) = a^(2^519);
    /// `error.NotSquare` when a is not a quadratic residue.
    pub fn sqrt(a: Fe) NotSquareError!Fe {
        const r = a.sqn(519);
        if (!r.sq().equivalent(a)) return error.NotSquare;
        return r;
    }

    pub fn isSquare(a: Fe) bool {
        return if (a.sqrt()) |_| true else |_| false;
    }

    pub fn isZero(a: Fe) bool {
        const c = a.canonical();
        var acc: u64 = 0;
        inline for (0..9) |i| acc |= c[i];
        return acc == 0;
    }

    pub fn equivalent(a: Fe, b: Fe) bool {
        return a.sub(b).isZero();
    }

    pub fn isOdd(a: Fe) bool {
        return a.canonical()[0] & 1 != 0;
    }

    /// `a.* = b` when `c == 1`, unchanged when `c == 0`; no branch.
    pub fn cMov(a: *Fe, b: Fe, c: u1) void {
        const m = 0 -% @as(u64, c);
        inline for (0..9) |i| a.l[i] ^= (a.l[i] ^ b.l[i]) & m;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// The integer value of a (not necessarily reduced) element.
fn toU1024(a: Fe) u1100 {
    var v: u1100 = 0;
    inline for (0..9) |i| v += @as(u1100, a.l[i]) << (58 * i);
    return v;
}

const P: u1100 = Fe.field_order;

fn fromU(v: u1100) Fe {
    var r: Fe = undefined;
    var x = v % P;
    inline for (0..8) |i| {
        r.l[i] = @truncate(x & M58);
        x >>= 58;
    }
    r.l[8] = @truncate(x);
    return r;
}

fn randFe(r: std.Random) Fe {
    var b: [66]u8 = undefined;
    r.bytes(&b);
    var v: u1100 = 0;
    for (b) |x| v = (v << 8) | x;
    return fromU(v);
}

fn expectFe(want: u1100, got: Fe) !void {
    try testing.expectEqual(want % P, toU1024(got) % P);
}

fn isTight(a: Fe) bool {
    for (a.l[0..8], 0..) |x, i| if (x >= (@as(u64, 1) << 58) + (if (i == 1) @as(u64, 1 << 9) else 0)) return false;
    return a.l[8] < (@as(u64, 1) << 57);
}

test "field: differential against wide integer arithmetic" {
    var prng = std.Random.DefaultPrng.init(0x521);
    const r = prng.random();
    const edges = [_]u1100{ 0, 1, 2, P - 1, P - 2, (P + 1) / 2, 1 << 520, (1 << 520) - 1, 1 << 464, (1 << 464) - 1 };
    var i: usize = 0;
    while (i < 3000) : (i += 1) {
        const a = if (i < edges.len * edges.len) fromU(edges[i % edges.len]) else randFe(r);
        const b = if (i < edges.len * edges.len) fromU(edges[i / edges.len]) else randFe(r);
        const av = toU1024(a) % P;
        const bv = toU1024(b) % P;
        const m = a.mul(b);
        try expectFe((av * bv) % P, m);
        try testing.expect(isTight(m));
        const s = a.sq();
        try expectFe((av * av) % P, s);
        try testing.expect(isTight(s));
        const ad = a.add(b);
        try expectFe(av + bv, ad);
        try testing.expect(isTight(ad));
        const sb = a.sub(b);
        try expectFe(av + P - bv, sb);
        try testing.expect(isTight(sb));
        try expectFe(P - av, a.neg());
        try testing.expectEqual(av == bv, a.equivalent(b));
        try testing.expectEqual(av == 0, a.isZero());
        try testing.expectEqual(av & 1 == 1, a.isOdd());
        // Round trip through bytes, both endians.
        const be = a.toBytes(.big);
        var want_be: [66]u8 = undefined;
        std.mem.writeInt(u528, &want_be, @intCast(av), .big);
        try testing.expectEqualSlices(u8, &want_be, &be);
        try expectFe(av, try Fe.fromBytes(be, .big));
        try expectFe(av, try Fe.fromBytes(a.toBytes(.little), .little));
    }
}

test "field: invert and sqrt" {
    var prng = std.Random.DefaultPrng.init(0x5210);
    const r = prng.random();
    try testing.expect(Fe.zero.invert().isZero());
    for (0..40) |_| {
        const a = randFe(r);
        if (a.isZero()) continue;
        try testing.expect(a.mul(a.invert()).equivalent(Fe.one));
        const s = a.sq();
        const root = try s.sqrt();
        try testing.expect(root.equivalent(a) or root.equivalent(a.neg()));
    }
    // −1 is a non-residue when p ≡ 3 (mod 4).
    try testing.expectError(error.NotSquare, Fe.one.neg().sqrt());
}

test "field: fromBytes rejects p and anything at or above 2^521" {
    var b: [66]u8 = @splat(0xff);
    b[0] = 0x01; // = p
    try testing.expectError(error.NonCanonical, Fe.fromBytes(b, .big));
    b[65] = 0xfe; // p − 1
    _ = try Fe.fromBytes(b, .big);
    b = @splat(0);
    b[0] = 0x02; // 2^521
    try testing.expectError(error.NonCanonical, Fe.fromBytes(b, .big));
    b[0] = 0x80;
    try testing.expectError(error.NonCanonical, Fe.fromBytes(b, .big));
    try testing.expectError(error.NonCanonical, Fe.fromInt(Fe.field_order));
}

test "field: carry bounds at the worst-case limbs (no u128 overflow, values right)" {
    // Safety-checked arithmetic in Debug/ReleaseSafe turns any overflow in
    // the column sums or carries into a panic; the value check catches a
    // wrapped one in ReleaseFast.
    const max_tight: Fe = .{ .l = .{ M58, (1 << 58) + (1 << 9) - 1, M58, M58, M58, M58, M58, M58, M57 } };
    const max_mul_in: Fe = .{ .l = @splat((1 << 61) - 1) };
    const vt = toU1024(max_tight) % P;
    const vm = toU1024(max_mul_in) % P;
    try expectFe(vt * vt % P, max_tight.mul(max_tight));
    try expectFe(vt * vt % P, max_tight.sq());
    try expectFe(vm * vm % P, max_mul_in.mul(max_mul_in));
    try expectFe(vm * vm % P, max_mul_in.sq());
    try expectFe(vm * vt % P, max_mul_in.mul(max_tight));
    // add/sub/mulSmall chains from tight extremes stay tight.
    var x = max_tight;
    var xv = vt;
    for (0..64) |_| {
        x = x.add(max_tight);
        xv = (xv + vt) % P;
        try testing.expect(isTight(x));
        x = x.sub(max_tight).sub(max_tight);
        xv = (xv + 2 * P - 2 * vt) % P;
        try testing.expect(isTight(x));
        x = x.mulSmall(7);
        xv = xv * 7 % P;
        try testing.expect(isTight(x));
        x = x.mul(x);
        xv = xv * xv % P;
        try expectFe(xv, x);
    }
    // canonical on the largest tight value and on p itself.
    try expectFe(vt, try Fe.fromBytes(max_tight.toBytes(.big), .big));
    const p_limbs: Fe = .{ .l = .{ M58, M58, M58, M58, M58, M58, M58, M58, M57 } };
    try testing.expect(p_limbs.isZero());
}
