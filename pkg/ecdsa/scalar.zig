// SPDX-License-Identifier: MIT

//! The P-521 scalar field, integers mod the group order
//! n = 0x01ff…fa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409.
//!
//! n has no special form, so this is a plain Montgomery field: nine saturated
//! 64-bit limbs, R = 2^576, word-by-word (CIOS) reduction, one masked final
//! subtraction. Every operation is branch-free in its inputs; `invert` is
//! Fermat (x^(n−2)) with a 4-bit window over the PUBLIC exponent, so the
//! table index is a constant, not a secret.
//!
//! The std-shaped surface mirrors `std.crypto.ecc.P384.scalar`: a `Scalar`
//! type plus `CompressedScalar` helpers, `encoded_length` = 66.

const std = @import("std");
const ct = @import("ct.zig");
const NonCanonicalError = std.crypto.errors.NonCanonicalError;

/// Length of a serialized scalar (bytes).
pub const encoded_length = 66;
/// A serialized scalar.
pub const CompressedScalar = [encoded_length]u8;

/// The group order n.
pub const field_order: u521 = 0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409;

const Limbs = [9]u64;

fn limbsOf(comptime x: anytype) Limbs {
    var r: Limbs = undefined;
    var v: u576 = @intCast(x);
    for (0..9) |i| {
        r[i] = @truncate(v);
        v >>= 64;
    }
    return r;
}

const N: Limbs = limbsOf(field_order);

/// −n⁻¹ mod 2^64 (Newton iteration on the low limb).
const N0INV: u64 = blk: {
    var inv: u64 = 1;
    for (0..7) |_| inv = inv *% (2 -% N[0] *% inv);
    break :blk 0 -% inv;
};

/// R mod n and R² mod n, R = 2^576.
const R1: Limbs = limbsOf((@as(u1160, 1) << 576) % @as(u1160, field_order));
const R2: Limbs = blk: {
    @setEvalBranchQuota(100_000);
    break :blk limbsOf((@as(u1160, 1) << 1152) % @as(u1160, field_order));
};

/// t (< 2n, ten limbs with t[9] ∈ {0,1}) reduced into [0, n) by one masked
/// subtraction.
inline fn condSub(t: [10]u64) Limbs {
    var r: Limbs = undefined;
    var borrow: u64 = 0;
    inline for (0..9) |i| {
        const d = @as(u128, t[i]) -% N[i] -% borrow;
        r[i] = @truncate(d);
        borrow = @truncate((d >> 64) & 1);
    }
    // Underflow overall iff t[9] < borrow, i.e. t < n: keep t.
    const under: u64 = @truncate(((@as(u128, t[9]) -% borrow) >> 64) & 1);
    const keep = 0 -% under;
    var out: Limbs = undefined;
    inline for (0..9) |i| out[i] = (t[i] & keep) | (r[i] & ~keep);
    return out;
}

/// Montgomery product a·b·R⁻¹ mod n, for a < R and b < n.
fn montMul(a: Limbs, b: Limbs) Limbs {
    var t: [11]u64 = @splat(0);
    for (0..9) |i| {
        var c: u64 = 0;
        inline for (0..9) |j| {
            const x = @as(u128, t[j]) + @as(u128, a[j]) * b[i] + c;
            t[j] = @truncate(x);
            c = @truncate(x >> 64);
        }
        var x = @as(u128, t[9]) + c;
        t[9] = @truncate(x);
        t[10] = @truncate(x >> 64);
        const m = t[0] *% N0INV;
        x = @as(u128, t[0]) + @as(u128, m) * N[0];
        c = @truncate(x >> 64);
        inline for (1..9) |j| {
            x = @as(u128, t[j]) + @as(u128, m) * N[j] + c;
            t[j - 1] = @truncate(x);
            c = @truncate(x >> 64);
        }
        x = @as(u128, t[9]) + c;
        t[8] = @truncate(x);
        t[9] = t[10] + @as(u64, @truncate(x >> 64));
        t[10] = 0;
    }
    return condSub(t[0..10].*);
}

/// Load 66 bytes into limbs (little-endian limb order).
fn load(s_: [encoded_length]u8, endian: std.builtin.Endian) Limbs {
    var s = s_;
    if (endian == .big) std.mem.reverse(u8, &s);
    var r: Limbs = undefined;
    inline for (0..8) |i| r[i] = std.mem.readInt(u64, s[8 * i ..][0..8], .little);
    r[8] = @as(u64, s[64]) | (@as(u64, s[65]) << 8);
    return r;
}

/// 1 iff limbs < n, computed without a branch.
fn ltN(a: Limbs) u1 {
    var borrow: u64 = 0;
    inline for (0..9) |i| {
        const d = @as(u128, a[i]) -% N[i] -% borrow;
        borrow = @truncate((d >> 64) & 1);
    }
    return @truncate(borrow);
}

/// An element of Z/nZ, held in Montgomery form.
pub const Scalar = struct {
    m: Limbs,

    pub const zero: Scalar = .{ .m = @splat(0) };
    pub const one: Scalar = .{ .m = R1 };

    /// Decode a canonical scalar (< n); `error.NonCanonical` otherwise. The
    /// range check is branch-free; the verdict is declassified for ctgrind
    /// (the error reveals it) and branched on once.
    pub fn fromBytes(s: CompressedScalar, endian: std.builtin.Endian) NonCanonicalError!Scalar {
        var ok: u8 = 0;
        const r = fromBytesCt(&s, endian, &ok);
        ct.declassify(&ok);
        if (ok == 0) return error.NonCanonical;
        return r;
    }

    /// `fromBytes` without the branch: `ok.*` = 1 iff the input is < n.
    /// The returned scalar is the reduced value either way.
    pub fn fromBytesCt(s: *const CompressedScalar, endian: std.builtin.Endian, ok: *u8) Scalar {
        const l = load(s.*, endian);
        ok.* = ltN(l);
        return .{ .m = montMul(l, R2) };
    }

    /// Any 66-byte string, reduced mod n.
    pub fn fromBytesReduce(s: CompressedScalar, endian: std.builtin.Endian) Scalar {
        return .{ .m = montMul(load(s, endian), R2) };
    }

    /// A 64-byte string (e.g. a SHA-512 digest), reduced mod n.
    pub fn fromBytes64(s: [64]u8, endian: std.builtin.Endian) Scalar {
        var w: CompressedScalar = @splat(0);
        switch (endian) {
            .big => w[2..].* = s,
            .little => w[0..64].* = s,
        }
        return fromBytesReduce(w, endian);
    }

    /// The canonical encoding.
    pub fn toBytes(a: Scalar, endian: std.builtin.Endian) CompressedScalar {
        const l = montMul(a.m, .{ 1, 0, 0, 0, 0, 0, 0, 0, 0 });
        var out: CompressedScalar = undefined;
        inline for (0..8) |i| std.mem.writeInt(u64, out[8 * i ..][0..8], l[i], .little);
        out[64] = @truncate(l[8]);
        out[65] = @truncate(l[8] >> 8);
        if (endian == .big) std.mem.reverse(u8, &out);
        return out;
    }

    pub fn isZero(a: Scalar) bool {
        var acc: u64 = 0;
        inline for (0..9) |i| acc |= a.m[i];
        return acc == 0;
    }

    /// 1 iff zero, no branch.
    pub fn isZeroCt(a: Scalar) u1 {
        var acc: u64 = 0;
        inline for (0..9) |i| acc |= a.m[i];
        return @truncate(((acc | (0 -% acc)) >> 63) ^ 1);
    }

    pub fn equivalent(a: Scalar, b: Scalar) bool {
        var acc: u64 = 0;
        inline for (0..9) |i| acc |= a.m[i] ^ b.m[i];
        return acc == 0;
    }

    pub fn add(a: Scalar, b: Scalar) Scalar {
        var t: [10]u64 = undefined;
        var c: u64 = 0;
        inline for (0..9) |i| {
            const x = @as(u128, a.m[i]) + b.m[i] + c;
            t[i] = @truncate(x);
            c = @truncate(x >> 64);
        }
        t[9] = c;
        return .{ .m = condSub(t) };
    }

    pub fn sub(a: Scalar, b: Scalar) Scalar {
        var r: Limbs = undefined;
        var borrow: u64 = 0;
        inline for (0..9) |i| {
            const d = @as(u128, a.m[i]) -% b.m[i] -% borrow;
            r[i] = @truncate(d);
            borrow = @truncate((d >> 64) & 1);
        }
        const m = 0 -% borrow;
        var c: u64 = 0;
        inline for (0..9) |i| {
            const x = @as(u128, r[i]) + (N[i] & m) + c;
            r[i] = @truncate(x);
            c = @truncate(x >> 64);
        }
        return .{ .m = r };
    }

    pub fn neg(a: Scalar) Scalar {
        return zero.sub(a);
    }

    pub fn dbl(a: Scalar) Scalar {
        return a.add(a);
    }

    pub fn mul(a: Scalar, b: Scalar) Scalar {
        return .{ .m = montMul(a.m, b.m) };
    }

    pub fn sq(a: Scalar) Scalar {
        return a.mul(a);
    }

    /// a⁻¹ (0 for 0): a^(n−2), constant time in `a`.
    pub fn invert(a: Scalar) Scalar {
        const e: u528 = field_order - 2;
        var tbl: [16]Scalar = undefined;
        tbl[0] = one;
        tbl[1] = a;
        for (2..16) |i| tbl[i] = tbl[i - 1].mul(a);
        var r = one;
        var pos: usize = 132;
        while (pos > 0) {
            pos -= 1;
            r = r.sq().sq().sq().sq();
            // The exponent is a public constant: indexing by it is not a
            // secret-dependent access.
            const nib: u4 = @truncate(e >> @intCast(4 * pos));
            if (nib != 0) r = r.mul(tbl[nib]);
        }
        return r;
    }

    /// A uniformly random non-zero scalar. `io.randomSecure` is fail-closed
    /// (CONVENTIONS.md §2.2).
    pub fn random(io: std.Io) error{EntropyUnavailable}!Scalar {
        var b: CompressedScalar = undefined;
        defer std.crypto.secureZero(u8, &b);
        while (true) {
            io.randomSecure(&b) catch return error.EntropyUnavailable;
            b[0] &= 0x01;
            var ok: u8 = 0;
            const s = fromBytesCt(&b, .big, &ok);
            ok &= ~@as(u8, s.isZeroCt());
            ct.declassify(&ok);
            if (ok != 0) return s;
        }
    }
};

/// Reject a scalar ≥ n.
pub fn rejectNonCanonical(s: CompressedScalar, endian: std.builtin.Endian) NonCanonicalError!void {
    _ = try Scalar.fromBytes(s, endian);
}

/// (a · b) mod n.
pub fn mul(a: CompressedScalar, b: CompressedScalar, endian: std.builtin.Endian) NonCanonicalError!CompressedScalar {
    return (try Scalar.fromBytes(a, endian)).mul(try Scalar.fromBytes(b, endian)).toBytes(endian);
}

/// (a · b + c) mod n.
pub fn mulAdd(a: CompressedScalar, b: CompressedScalar, c: CompressedScalar, endian: std.builtin.Endian) NonCanonicalError!CompressedScalar {
    const x = (try Scalar.fromBytes(a, endian)).mul(try Scalar.fromBytes(b, endian));
    return x.add(try Scalar.fromBytes(c, endian)).toBytes(endian);
}

/// (a + b) mod n.
pub fn add(a: CompressedScalar, b: CompressedScalar, endian: std.builtin.Endian) NonCanonicalError!CompressedScalar {
    return (try Scalar.fromBytes(a, endian)).add(try Scalar.fromBytes(b, endian)).toBytes(endian);
}

/// −s mod n.
pub fn neg(s: CompressedScalar, endian: std.builtin.Endian) NonCanonicalError!CompressedScalar {
    return (try Scalar.fromBytes(s, endian)).neg().toBytes(endian);
}

/// (a − b) mod n.
pub fn sub(a: CompressedScalar, b: CompressedScalar, endian: std.builtin.Endian) NonCanonicalError!CompressedScalar {
    return (try Scalar.fromBytes(a, endian)).sub(try Scalar.fromBytes(b, endian)).toBytes(endian);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const NN: u1200 = field_order;

fn valueOf(a: Scalar) u1200 {
    var v: u1200 = 0;
    for (a.toBytes(.big)) |b| v = (v << 8) | b;
    return v;
}

fn scalarOf(v: u1200) Scalar {
    var b: CompressedScalar = undefined;
    std.mem.writeInt(u528, &b, @intCast(v % NN), .big);
    return Scalar.fromBytes(b, .big) catch unreachable;
}

test "scalar: constants" {
    try testing.expectEqual(@as(u64, 0), N[0] *% (0 -% N0INV) -% 1);
    try testing.expect(scalarOf(1).equivalent(Scalar.one));
    try testing.expectEqual(@as(u1200, 1), valueOf(Scalar.one));
}

test "scalar: differential against wide integer arithmetic" {
    var prng = std.Random.DefaultPrng.init(0x5211);
    const r = prng.random();
    const edges = [_]u1200{ 0, 1, 2, NN - 1, NN - 2, NN / 2, 1 << 520, (1 << 512) - 1 };
    for (0..1500) |i| {
        var av: u1200 = undefined;
        var bv: u1200 = undefined;
        if (i < edges.len * edges.len) {
            av = edges[i % edges.len];
            bv = edges[i / edges.len];
        } else {
            av = r.int(u528) % NN;
            bv = r.int(u528) % NN;
        }
        const a = scalarOf(av);
        const b = scalarOf(bv);
        try testing.expectEqual(av * bv % NN, valueOf(a.mul(b)));
        try testing.expectEqual((av + bv) % NN, valueOf(a.add(b)));
        try testing.expectEqual((av + NN - bv) % NN, valueOf(a.sub(b)));
        try testing.expectEqual((NN - av) % NN, valueOf(a.neg()));
        try testing.expectEqual(av == 0, a.isZero());
        try testing.expectEqual(@intFromBool(av == 0), a.isZeroCt());
        // Wide reduction of an arbitrary 528-bit string.
        const w = r.int(u528);
        var wb: CompressedScalar = undefined;
        std.mem.writeInt(u528, &wb, w, .big);
        try testing.expectEqual(@as(u1200, w) % NN, valueOf(Scalar.fromBytesReduce(wb, .big)));
        try testing.expectEqual(@as(u1200, w) % NN, valueOf(Scalar.fromBytesReduce(@bitCast(std.mem.nativeToLittle(u528, w)), .little)));
    }
}

test "scalar: invert" {
    var prng = std.Random.DefaultPrng.init(0x5212);
    const r = prng.random();
    try testing.expect(Scalar.zero.invert().isZero());
    for (0..20) |_| {
        const a = scalarOf(r.int(u528));
        if (a.isZero()) continue;
        try testing.expect(a.mul(a.invert()).equivalent(Scalar.one));
    }
}

test "scalar: fromBytes refuses n and above, accepts n − 1" {
    var b: CompressedScalar = undefined;
    std.mem.writeInt(u528, &b, field_order, .big);
    try testing.expectError(error.NonCanonical, Scalar.fromBytes(b, .big));
    std.mem.writeInt(u528, &b, field_order - 1, .big);
    _ = try Scalar.fromBytes(b, .big);
    std.mem.writeInt(u528, &b, std.math.maxInt(u528), .big);
    try testing.expectError(error.NonCanonical, Scalar.fromBytes(b, .big));
    var ok: u8 = 9;
    _ = Scalar.fromBytesCt(&b, .big, &ok);
    try testing.expectEqual(@as(u8, 0), ok);
}
