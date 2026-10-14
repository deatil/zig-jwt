// SPDX-License-Identifier: MIT

//! The NIST P-521 group (secp521r1, FIPS 186-5 / SP 800-186 §3.2.1.5):
//! y² = x³ − 3x + b over GF(2^521 − 1), prime order n, cofactor 1.
//!
//! Points are projective (X : Y : Z); `add`, `dbl` and `addMixed` use the
//! complete formulas of Renes–Costello–Batina 2016 (eprint 2015/1060,
//! Algorithms 4, 5 and 6 for a = −3): no exceptional cases.
//!
//! Scalar multiplication runs in Jacobian coordinates (`Jac`), whose cheaper
//! formulas are not complete:
//!   * `mul` (secret scalar): reduced mod n and folded to min(s, n − s), then
//!     signed 5-bit windows from the top over a 16-entry affine table, every
//!     lookup a masked scan of the whole table. `mulCt` proves that the only
//!     exceptional cases left are the identity ones, and blends them.
//!   * `mulBaseCtUnburned` (secret scalar, P = G: key derivation and the ECDSA
//!     nonce commitment): the fixed-base comb `combMulBaseCt` over the
//!     generated `base_table.zig`, constant time the same way.
//!   * `mulPublic` / `mulDoubleBasePublic` (public scalars only, signature
//!     verification): width-5 NAF, and the comb table for G; VARIABLE TIME.
//!
//! The surface mirrors `std.crypto.ecc.P384` with 66-byte scalars and
//! coordinates, so code generic over std's curves reads the same.

const std = @import("std");
const field = @import("field.zig");
const ct = @import("ct.zig");
const burn = @import("burn.zig");
const scalar_mod = @import("scalar.zig");

const errors = std.crypto.errors;
const EncodingError = errors.EncodingError;
const IdentityElementError = errors.IdentityElementError;
const NonCanonicalError = errors.NonCanonicalError;
const NotSquareError = errors.NotSquareError;

/// A P-521 point in projective coordinates.
pub const P521 = struct {
    x: Fe,
    y: Fe,
    z: Fe = Fe.one,

    /// The base field.
    pub const Fe = field.Fe;
    /// The scalar field (the group order n).
    pub const scalar = scalar_mod;

    /// The curve constant b.
    pub const B = Fe.fromInt(0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00) catch unreachable;

    /// The base point G.
    pub const basePoint: P521 = .{
        .x = Fe.fromInt(0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66) catch unreachable,
        .y = Fe.fromInt(0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650) catch unreachable,
        .z = Fe.one,
    };

    /// The neutral element.
    pub const identityElement: P521 = .{ .x = Fe.zero, .y = Fe.one, .z = Fe.zero };

    /// Reject the neutral element.
    pub fn rejectIdentity(p: P521) IdentityElementError!void {
        if (p.z.isZero()) return error.IdentityElement;
    }

    /// 1 iff `p` is the neutral element, without a branch.
    fn isIdentityCt(p: P521) u1 {
        return @intFromBool(p.z.isZero());
    }

    /// A point from affine coordinates, after checking the curve equation.
    /// (0, 0) is accepted as the affine encoding of the identity, as std does.
    pub fn fromAffineCoordinates(p: AffineCoordinates) EncodingError!P521 {
        const on_curve = @intFromBool(rhs(p.x).equivalent(p.y.sq()));
        const is_identity = @intFromBool(p.x.isZero()) & @intFromBool(p.y.isZero());
        if ((on_curve | is_identity) == 0) return error.InvalidEncoding;
        var ret: P521 = .{ .x = p.x, .y = p.y, .z = Fe.one };
        ret.cMov(identityElement, is_identity);
        return ret;
    }

    /// x³ − 3x + b.
    fn rhs(x: Fe) Fe {
        return x.sq().mul(x).sub(x.mulSmall(3)).add(B);
    }

    /// A point from serialized affine coordinates.
    pub fn fromSerializedAffineCoordinates(xs: [66]u8, ys: [66]u8, endian: std.builtin.Endian) (NonCanonicalError || EncodingError)!P521 {
        const x = try Fe.fromBytes(xs, endian);
        const y = try Fe.fromBytes(ys, endian);
        return fromAffineCoordinates(.{ .x = x, .y = y });
    }

    /// Recover y from x and the parity of y.
    pub fn recoverY(x: Fe, is_odd: bool) NotSquareError!Fe {
        var y = try rhs(x).sqrt();
        const yn = y.neg();
        y.cMov(yn, @intFromBool(is_odd) ^ @intFromBool(y.isOdd()));
        return y;
    }

    /// Decode a SEC1 point: `0x04 ‖ X ‖ Y` (133 bytes), `0x02/0x03 ‖ X`
    /// (67 bytes), or `0x00` (the identity, as std accepts it — key decoders
    /// on top of this refuse it). Coordinates must be canonical (< p) and the
    /// point on the curve; cofactor 1, so on the curve means in the group.
    pub fn fromSec1(s: []const u8) (EncodingError || NotSquareError || NonCanonicalError)!P521 {
        if (s.len < 1) return error.InvalidEncoding;
        const encoded = s[1..];
        switch (s[0]) {
            0 => {
                if (encoded.len != 0) return error.InvalidEncoding;
                return identityElement;
            },
            2, 3 => {
                if (encoded.len != 66) return error.InvalidEncoding;
                const x = try Fe.fromBytes(encoded[0..66].*, .big);
                const y = try recoverY(x, s[0] == 3);
                return .{ .x = x, .y = y };
            },
            4 => {
                if (encoded.len != 132) return error.InvalidEncoding;
                const x = try Fe.fromBytes(encoded[0..66].*, .big);
                const y = try Fe.fromBytes(encoded[66..132].*, .big);
                return fromAffineCoordinates(.{ .x = x, .y = y });
            },
            else => return error.InvalidEncoding,
        }
    }

    /// Compressed SEC1 encoding (67 bytes).
    pub fn toCompressedSec1(p: P521) [67]u8 {
        var out: [67]u8 = undefined;
        const xy = p.affineCoordinates();
        out[0] = if (xy.y.isOdd()) 3 else 2;
        out[1..].* = xy.x.toBytes(.big);
        return out;
    }

    /// Uncompressed SEC1 encoding (133 bytes).
    pub fn toUncompressedSec1(p: P521) [133]u8 {
        var out: [133]u8 = undefined;
        out[0] = 4;
        const xy = p.affineCoordinates();
        out[1..67].* = xy.x.toBytes(.big);
        out[67..133].* = xy.y.toBytes(.big);
        return out;
    }

    /// A random point (a random multiple of G).
    pub fn random(io: std.Io) error{EntropyUnavailable}!P521 {
        var s = (try scalar.Scalar.random(io)).toBytes(.big);
        defer std.crypto.secureZero(u8, &s);
        var out: P521 = undefined;
        mulInto(&out, basePoint, &s, .big) catch unreachable;
        return out;
    }

    /// −p.
    pub fn neg(p: P521) P521 {
        return .{ .x = p.x, .y = p.y.neg(), .z = p.z };
    }

    /// 2p (RCB Algorithm 6, a = −3).
    pub fn dbl(p: P521) P521 {
        var t0 = p.x.sq();
        const t1 = p.y.sq();
        var t2 = p.z.sq();
        var t3 = p.x.mul(p.y);
        t3 = t3.dbl();
        var z3 = p.x.mul(p.z);
        z3 = z3.dbl();
        var y3 = B.mul(t2);
        y3 = y3.sub(z3);
        var x3 = y3.dbl();
        y3 = x3.add(y3);
        x3 = t1.sub(y3);
        y3 = t1.add(y3);
        y3 = x3.mul(y3);
        x3 = x3.mul(t3);
        t3 = t2.dbl();
        t2 = t2.add(t3);
        z3 = B.mul(z3);
        z3 = z3.sub(t2);
        z3 = z3.sub(t0);
        t3 = z3.dbl();
        z3 = z3.add(t3);
        t3 = t0.dbl();
        t0 = t3.add(t0);
        t0 = t0.sub(t2);
        t0 = t0.mul(z3);
        y3 = y3.add(t0);
        t0 = p.y.mul(p.z);
        t0 = t0.dbl();
        z3 = t0.mul(z3);
        x3 = x3.sub(z3);
        z3 = t0.mul(t1);
        z3 = z3.mulSmall(4);
        return .{ .x = x3, .y = y3, .z = z3 };
    }

    /// p + q (RCB Algorithm 4, a = −3; complete).
    pub fn add(p: P521, q: P521) P521 {
        var t0 = p.x.mul(q.x);
        var t1 = p.y.mul(q.y);
        var t2 = p.z.mul(q.z);
        var t3 = p.x.add(p.y);
        var t4 = q.x.add(q.y);
        t3 = t3.mul(t4);
        t4 = t0.add(t1);
        t3 = t3.sub(t4);
        t4 = p.y.add(p.z);
        var x3 = q.y.add(q.z);
        t4 = t4.mul(x3);
        x3 = t1.add(t2);
        t4 = t4.sub(x3);
        x3 = p.x.add(p.z);
        var y3 = q.x.add(q.z);
        x3 = x3.mul(y3);
        y3 = t0.add(t2);
        y3 = x3.sub(y3);
        var z3 = B.mul(t2);
        x3 = y3.sub(z3);
        z3 = x3.dbl();
        x3 = x3.add(z3);
        z3 = t1.sub(x3);
        x3 = t1.add(x3);
        y3 = B.mul(y3);
        t1 = t2.dbl();
        t2 = t1.add(t2);
        y3 = y3.sub(t2);
        y3 = y3.sub(t0);
        t1 = y3.dbl();
        y3 = t1.add(y3);
        t1 = t0.dbl();
        t0 = t1.add(t0);
        t0 = t0.sub(t2);
        t1 = t4.mul(y3);
        t2 = t0.mul(y3);
        y3 = x3.mul(z3);
        y3 = y3.add(t2);
        x3 = t3.mul(x3);
        x3 = x3.sub(t1);
        z3 = t4.mul(z3);
        t1 = t3.mul(t0);
        z3 = z3.add(t1);
        return .{ .x = x3, .y = y3, .z = z3 };
    }

    /// p + q with q affine (RCB Algorithm 5). q must not be the identity
    /// unless given as (0, 0), which this handles by a masked move.
    pub fn addMixed(p: P521, q: AffineCoordinates) P521 {
        var t0 = p.x.mul(q.x);
        var t1 = p.y.mul(q.y);
        var t3 = q.x.add(q.y);
        var t4 = p.x.add(p.y);
        t3 = t3.mul(t4);
        t4 = t0.add(t1);
        t3 = t3.sub(t4);
        t4 = q.y.mul(p.z);
        t4 = t4.add(p.y);
        var y3 = q.x.mul(p.z);
        y3 = y3.add(p.x);
        var z3 = B.mul(p.z);
        var x3 = y3.sub(z3);
        z3 = x3.dbl();
        x3 = x3.add(z3);
        z3 = t1.sub(x3);
        x3 = t1.add(x3);
        y3 = B.mul(y3);
        t1 = p.z.dbl();
        var t2 = t1.add(p.z);
        y3 = y3.sub(t2);
        y3 = y3.sub(t0);
        t1 = y3.dbl();
        y3 = t1.add(y3);
        t1 = t0.dbl();
        t0 = t1.add(t0);
        t0 = t0.sub(t2);
        t1 = t4.mul(y3);
        t2 = t0.mul(y3);
        y3 = x3.mul(z3);
        y3 = y3.add(t2);
        x3 = t3.mul(x3);
        x3 = x3.sub(t1);
        z3 = t4.mul(z3);
        t1 = t3.mul(t0);
        z3 = z3.add(t1);
        var ret: P521 = .{ .x = x3, .y = y3, .z = z3 };
        ret.cMov(p, @intFromBool(q.x.isZero()) & @intFromBool(q.y.isZero()));
        return ret;
    }

    /// p − q.
    pub fn sub(p: P521, q: P521) P521 {
        return p.add(q.neg());
    }

    /// p − q with q affine.
    pub fn subMixed(p: P521, q: AffineCoordinates) P521 {
        return p.addMixed(q.neg());
    }

    /// Affine coordinates; the identity maps to (0, 0). One field inversion,
    /// constant time.
    pub fn affineCoordinates(p: P521) AffineCoordinates {
        const zinv = p.z.invert();
        // z = 0 gives zinv = 0 and so (0, 0) on its own.
        return .{ .x = p.x.mul(zinv), .y = p.y.mul(zinv) };
    }

    /// Whether both represent the same point (projective cross-multiply).
    pub fn equivalent(a: P521, b: P521) bool {
        const x_eq = a.x.mul(b.z).equivalent(b.x.mul(a.z));
        const y_eq = a.y.mul(b.z).equivalent(b.y.mul(a.z));
        return x_eq and y_eq;
    }

    fn cMov(p: *P521, a: P521, c: u1) void {
        p.x.cMov(a.x, c);
        p.y.cMov(a.y, c);
        p.z.cMov(a.z, c);
    }

    fn precompute(p: P521, comptime count: usize) [1 + count]P521 {
        var pc: [1 + count]P521 = undefined;
        pc[0] = identityElement;
        pc[1] = p;
        var i: usize = 2;
        while (i <= count) : (i += 1) {
            pc[i] = if (i % 2 == 0) pc[i / 2].dbl() else pc[i - 1].add(p);
        }
        return pc;
    }

    /// The constant-time core: s (little-endian, any 66 bytes) · p.
    ///
    /// Jacobian coordinates (`Jac`: doubling 3M + 5S against RCB's 10M + 3S)
    /// with a 16-entry affine table (mixed addition 7M + 4S) and signed 5-bit
    /// digits, 106 windows. Those formulas are not complete, so the
    /// exceptional cases are ruled out instead of handled: s is reduced mod n
    /// and replaced by s' = min(s, n − s) ≤ (n − 1)/2 (the product negated
    /// back at the end). With the digits d_i of s', the accumulator before
    /// adding d_i·p is 32k·p with k ≥ 0 and 32k ≤ s' + 17 < n − 16, so
    /// 32k ≡ ±d_i (mod n) would need 32k ∓ d_i = 0, i.e. k = d_i = 0. What is
    /// left is the identity on either side: d_i = 0 (keep the accumulator)
    /// and an accumulator that is still the identity (leading zero windows:
    /// take the table entry). Both are masked blends on a secret flag, never
    /// a branch.
    fn mulCt(p: P521, s_raw: *const [66]u8) P521 {
        const sc = scalar_mod.Scalar.fromBytesReduce(s_raw.*, .little);
        var s = sc.toBytes(.little);
        defer std.crypto.secureZero(u8, &s);
        var ns = sc.neg().toBytes(.little);
        defer std.crypto.secureZero(u8, &ns);
        // flip = all ones iff n − s < s; then s' = n − s and the result is negated.
        const flip = blackBox(ltMask(&ns, &s));
        for (&s, ns) |*a, b| a.* = (b & @as(u8, @truncate(flip))) | (a.* & ~@as(u8, @truncate(flip)));

        // Signed digits, low to high (the comb's recoding): magnitude 0..16 and
        // a negate mask per window. Secret; zeroed on return.
        var mags: [fb_t]u64 = undefined;
        var negs: [fb_t]u64 = undefined;
        defer std.crypto.secureZero(u64, &mags);
        defer std.crypto.secureZero(u64, &negs);
        var carry: u64 = 0;
        for (0..fb_t) |i| {
            const x = window5(&s, i * fb_w) + carry; // 0 .. 2^w
            const is_neg: u64 = @intFromBool(x >= fb_half);
            carry = is_neg;
            const negmask = blackBox(0 -% is_neg);
            mags[i] = ((fb_twow - x) & negmask) | (x & ~negmask);
            negs[i] = negmask;
        }

        const pc = precompute(p, 16);
        // The table is public (built from the public point); one inversion.
        const tab = batchAffine(16, pc[1..17]);
        var q = Jac.identity;
        // All ones while q is still the identity; secret (leading zeros).
        var q_id: u64 = blackBox(~@as(u64, 0));
        var i: usize = fb_t;
        while (i > 0) {
            i -= 1;
            // `i` is public: the first window skips the doublings of the
            // identity, every scalar alike.
            if (i != fb_t - 1) q = q.dbl().dbl().dbl().dbl().dbl();
            const m = mags[i];
            var g: AffineCoordinates = .{ .x = Fe.zero, .y = Fe.zero };
            for (0..16) |j| {
                const mask = blackBox(0 -% @as(u64, @intFromBool(@as(u64, j + 1) == m)));
                blend(&g.x, tab[j].x, mask);
                blend(&g.y, tab[j].y, mask);
            }
            blend(&g.y, g.y.neg(), negs[i]);
            var r = q.addAffine(g);
            const g_jac: Jac = .{ .x = g.x, .y = g.y, .z = Fe.one };
            r.blendFrom(g_jac, q_id);
            const nz = blackBox(0 -% @as(u64, @intFromBool(m != 0)));
            q.blendFrom(r, nz);
            q_id &= ~nz;
        }
        blend(&q.y, q.y.neg(), flip);
        var out = q.toProjective();
        out.blendFrom(identityElement, q_id);
        return out;
    }

    /// All ones iff a < b (66-byte little-endian integers), branch-free.
    fn ltMask(a: *const [66]u8, b: *const [66]u8) u64 {
        var borrow: u64 = 0;
        for (0..9) |k| {
            const x = limb(a, k);
            const y = limb(b, k);
            const d = @as(u128, x) -% y -% borrow;
            borrow = @truncate((d >> 64) & 1);
        }
        return 0 -% borrow;
    }

    fn limb(a: *const [66]u8, k: usize) u64 {
        if (k < 8) return std.mem.readInt(u64, a[8 * k ..][0..8], .little);
        return @as(u64, a[64]) | @as(u64, a[65]) << 8;
    }

    fn blendFrom(p: *P521, a: P521, mask: u64) void {
        blend(&p.x, a.x, mask);
        blend(&p.y, a.y, mask);
        blend(&p.z, a.z, mask);
    }

    /// Affine forms of `n` projective points, none the identity, with one
    /// field inversion (Montgomery's trick). Constant time.
    fn batchAffine(comptime n: usize, pts: *const [n]P521) [n]AffineCoordinates {
        var acc: [n]Fe = undefined;
        acc[0] = pts[0].z;
        for (1..n) |i| acc[i] = acc[i - 1].mul(pts[i].z);
        var inv = acc[n - 1].invert();
        var out: [n]AffineCoordinates = undefined;
        var i: usize = n;
        while (i > 1) {
            i -= 1;
            const zi = inv.mul(acc[i - 1]);
            inv = inv.mul(pts[i].z);
            out[i] = .{ .x = pts[i].x.mul(zi), .y = pts[i].y.mul(zi) };
        }
        out[0] = .{ .x = pts[0].x.mul(inv), .y = pts[0].y.mul(inv) };
        return out;
    }

    /// Multiply by a (secret) scalar, constant time. `error.IdentityElement`
    /// if `p` or the result is the identity. std's shape (scalar by value);
    /// `mulInto` is the dead-stack-clean form.
    pub fn mul(p: P521, s_: [66]u8, endian: std.builtin.Endian) IdentityElementError!P521 {
        var out: P521 = undefined;
        try mulInto(&out, p, &s_, endian);
        return out;
    }

    /// `mul` with the scalar by pointer and the product into `out` (zeroed
    /// on error). Burned (`burn.mul_burn`).
    pub fn mulInto(out: *P521, p: P521, s: *const [66]u8, endian: std.builtin.Endian) IdentityElementError!void {
        return burn.run(burn.mul_burn, IdentityElementError!void, mulIntoBody, .{ out, &p, s, endian });
    }

    fn mulIntoBody(out: *P521, p: *const P521, s: *const [66]u8, endian: std.builtin.Endian) IdentityElementError!void {
        errdefer out.* = identityElement;
        try p.rejectIdentity();
        var le = s.*;
        defer std.crypto.secureZero(u8, &le);
        if (endian == .big) std.mem.reverse(u8, &le);
        out.* = mulCt(p.*, &le);
        // The identity verdict on the product: revealed by the error.
        var id: u8 = out.isIdentityCt();
        ct.declassify(&id);
        if (id != 0) return error.IdentityElement;
    }

    /// The constant-time `s·G` for callers already running under a burn
    /// with a scalar already range-checked (ECDSA key derivation and the
    /// nonce commitment): no identity check, no burn of its own. `s` is
    /// little-endian. Not for direct use; `mulInto` is the API.
    /// The fixed-base comb (`combMulBaseCt`); `mulCt(basePoint, s)` is the
    /// same point by another road, pinned by the differential test below.
    pub fn mulBaseCtUnburned(s: *const [66]u8) P521 {
        return combMulBaseCt(&base_table, s);
    }

    /// Fixed-base `s·G` over a precomputed table (`base_table`): the scalar
    /// as `fb_t` signed 5-bit digits, one mixed addition per digit and no
    /// doublings — 106 additions against `mulCt`'s 524 doublings and 132
    /// additions. Constant time: the digit recoding is branch-free, every
    /// lookup scans all 16 entries of its window with a `blackBox`-laundered
    /// mask (so LLVM cannot lower the select to a secret-indexed jump or a
    /// CMOV on the digit — p256's `combMulBaseFast` measured both in
    /// ReleaseFast disasm before its barrier), the negation and the "digit was
    /// zero" keep are masked blends, and the table index `[i][j]` comes from
    /// the public loop counters only. Any 66 bytes: 106·5 = 530 bits cover
    /// 2^528, and the top window carries no digit out (comptime-checked
    /// below). `tab` is a parameter so a test can hand it a corrupted table
    /// and prove the differential has teeth.
    fn combMulBaseCt(tab: *const BaseTable, s: *const [66]u8) P521 {
        var acc = identityElement;
        var carry: u64 = 0;
        for (0..fb_t) |i| {
            const x = window5(s, i * fb_w) + carry; // 0 .. 2^w
            const is_neg: u64 = @intFromBool(x >= fb_half);
            carry = is_neg;
            const negmask = blackBox(0 -% is_neg);
            // |d| = is_neg ? 2^w − x : x, in 0 .. 2^(w−1).
            const m = ((fb_twow - x) & negmask) | (x & ~negmask);
            var g: AffineCoordinates = .{ .x = Fe.zero, .y = Fe.zero };
            for (0..fb_teeth) |j| {
                const mask = blackBox(0 -% @as(u64, @intFromBool(@as(u64, j + 1) == m)));
                blend(&g.x, tab[i][j].x, mask);
                blend(&g.y, tab[i][j].y, mask);
            }
            blend(&g.y, g.y.neg(), negmask);
            // Always add (fixed schedule); keep the sum iff the digit was
            // non-zero (m = 0 left g = (0, 0), not a point).
            const sum = acc.addMixed(g);
            const keep = blackBox(0 -% @as(u64, @intFromBool(m != 0)));
            blend(&acc.x, sum.x, keep);
            blend(&acc.y, sum.y, keep);
            blend(&acc.z, sum.z, keep);
        }
        return acc;
    }

    /// Bits [shift, shift + 5) of a little-endian 66-byte scalar. `shift` is
    /// public (a loop counter).
    fn window5(s: *const [66]u8, shift: usize) u64 {
        const byte = shift / 8;
        const lo: u64 = s[byte];
        const hi: u64 = if (byte + 1 < 66) s[byte + 1] else 0;
        return ((lo | hi << 8) >> @intCast(shift % 8)) & fb_wmask;
    }

    /// Width-5 NAF of a little-endian 66-byte scalar: digits odd in
    /// [−15, 15] or 0, any two non-zero digits at least 5 apart. Variable
    /// time (public scalars only).
    fn wnaf5(s: [66]u8) [wnaf_len]i8 {
        var k: u530 = std.mem.readInt(u528, &s, .little);
        var e: [wnaf_len]i8 = @splat(0);
        var i: usize = 0;
        // k < 2^528, so the digits end by position 528.
        while (k != 0) : (i += 1) {
            if (k & 1 != 0) {
                const m: i8 = @intCast(k & 31);
                const d: i8 = if (m >= 16) m - 32 else m;
                e[i] = d;
                if (d > 0) k -= @intCast(d) else k += @intCast(-d);
            }
            k >>= 1;
        }
        return e;
    }

    /// The odd multiples p, 3p, …, 15p in affine form (`p` not the identity).
    fn oddMultiples(p: P521) [8]AffineCoordinates {
        const pc = precompute(p, 15);
        var odd: [8]P521 = undefined;
        for (&odd, 0..) |*o, i| o.* = pc[2 * i + 1];
        return batchAffine(8, &odd);
    }

    /// s·p for a public point and scalar by width-5 NAF, as a Jacobian point.
    fn wnafMulVt(p: P521, s: [66]u8) Jac {
        const tab = oddMultiples(p);
        const e = wnaf5(s);
        var q = Jac.identity;
        var pos: usize = e.len;
        while (pos > 0) {
            pos -= 1;
            q = q.dblVt();
            const d = e[pos];
            if (d > 0) q = q.addAffineVt(tab[@intCast(@divExact(d - 1, 2))]) else if (d < 0) q = q.addAffineVt(tab[@intCast(@divExact(-d - 1, 2))].neg());
        }
        return q;
    }

    /// s·G over the fixed-base table, variable time: no doublings at all.
    fn combMulBaseVt(s: [66]u8) Jac {
        var acc = Jac.identity;
        var carry: u64 = 0;
        for (0..fb_t) |i| {
            const x = window5(&s, i * fb_w) + carry;
            if (x == 0) {
                carry = 0;
                continue;
            }
            if (x >= fb_half) {
                carry = 1;
                if (x == fb_twow) continue; // digit 0, carry out
                acc = acc.addAffineVt(base_table[i][@intCast(fb_twow - x - 1)].neg());
            } else {
                carry = 0;
                acc = acc.addAffineVt(base_table[i][@intCast(x - 1)]);
            }
        }
        return acc;
    }

    /// Multiply by a PUBLIC scalar, IN VARIABLE TIME (verification only).
    pub fn mulPublic(p: P521, s_: [66]u8, endian: std.builtin.Endian) IdentityElementError!P521 {
        var s = s_;
        if (endian == .big) std.mem.reverse(u8, &s);
        try p.rejectIdentity();
        const q = wnafMulVt(p, s).toProjectiveVt();
        try q.rejectIdentity();
        return q;
    }

    /// p1·s1 + p2·s2 for PUBLIC scalars, IN VARIABLE TIME (verification).
    /// When p1 is G (ECDSA verification) its half runs over the fixed-base
    /// table.
    pub fn mulDoubleBasePublic(p1: P521, s1_: [66]u8, p2: P521, s2_: [66]u8, endian: std.builtin.Endian) IdentityElementError!P521 {
        var s1 = s1_;
        var s2 = s2_;
        if (endian == .big) {
            std.mem.reverse(u8, &s1);
            std.mem.reverse(u8, &s2);
        }
        try p1.rejectIdentity();
        try p2.rejectIdentity();
        const is_g = p1.z.equivalent(Fe.one) and p1.x.equivalent(basePoint.x) and p1.y.equivalent(basePoint.y);
        const a = if (is_g) combMulBaseVt(s1) else wnafMulVt(p1, s1);
        const q = a.addVt(wnafMulVt(p2, s2)).toProjectiveVt();
        try q.rejectIdentity();
        return q;
    }
};

/// Jacobian (X : Y : Z), x = X/Z², y = Y/Z³: the internal form of the
/// scalar-multiplication loops. The formulas (a = −3; EFD dbl-2001-b,
/// madd-2007-bl, add-2007-bl) are NOT complete: the constant-time callers
/// rule the exceptional cases out (see `mulCt`), the `Vt` variants branch on
/// them (public inputs only). The identity is (1 : 1 : 0), which `dbl` keeps.
const Jac = struct {
    x: Fe,
    y: Fe,
    z: Fe,

    const Fe = field.Fe;
    const identity: Jac = .{ .x = Fe.one, .y = Fe.one, .z = Fe.zero };

    /// 2p, 3M + 5S.
    fn dbl(p: Jac) Jac {
        const delta = p.z.sqI();
        const gamma = p.y.sqI();
        const beta4 = p.x.mulI(gamma).mulSmall(4);
        const alpha = p.x.sub(delta).mulI(p.x.add(delta)).mulSmall(3);
        const x3 = alpha.sqI().sub(beta4.dbl());
        const z3 = p.y.add(p.z).sqI().sub(gamma).sub(delta);
        const y3 = alpha.mulI(beta4.sub(x3)).sub(gamma.sqI().mulSmall(4).dbl());
        return .{ .x = x3, .y = y3, .z = z3 };
    }

    /// p + q, q affine; 7M + 4S. Wrong (not merely slow) when p is the
    /// identity, q = ±p, or q is (0, 0): the callers exclude those.
    fn addAffine(p: Jac, q: AffineCoordinates) Jac {
        const z1z1 = p.z.sqI();
        const ux2 = q.x.mulI(z1z1);
        const s2 = q.y.mulI(p.z).mulI(z1z1);
        const h = ux2.sub(p.x);
        const r = s2.sub(p.y).dbl();
        return maddTail(p, z1z1, h, r);
    }

    inline fn maddTail(p: Jac, z1z1: Fe, h: Fe, r: Fe) Jac {
        const hh = h.sqI();
        const i = hh.mulSmall(4);
        const j = h.mulI(i);
        const v = p.x.mulI(i);
        const x3 = r.sqI().sub(j).sub(v.dbl());
        const y3 = r.mulI(v.sub(x3)).sub(p.y.mulI(j).dbl());
        const z3 = p.z.add(h).sqI().sub(z1z1).sub(hh);
        return .{ .x = x3, .y = y3, .z = z3 };
    }

    fn isIdentityVt(p: Jac) bool {
        return p.z.isZero();
    }

    fn dblVt(p: Jac) Jac {
        if (p.isIdentityVt()) return identity;
        return p.dbl();
    }

    /// `addAffine` with the exceptional cases branched on: public data only.
    fn addAffineVt(p: Jac, q: AffineCoordinates) Jac {
        if (p.isIdentityVt()) return .{ .x = q.x, .y = q.y, .z = Fe.one };
        const z1z1 = p.z.sqI();
        const ux2 = q.x.mulI(z1z1);
        const s2 = q.y.mulI(p.z).mulI(z1z1);
        const h = ux2.sub(p.x);
        const r = s2.sub(p.y).dbl();
        if (h.isZero()) return if (r.isZero()) p.dbl() else identity;
        return maddTail(p, z1z1, h, r);
    }

    /// p + q, both Jacobian, variable time (11M + 5S).
    fn addVt(p: Jac, q: Jac) Jac {
        if (p.isIdentityVt()) return q;
        if (q.isIdentityVt()) return p;
        const z1z1 = p.z.sqI();
        const z2z2 = q.z.sqI();
        const u_1 = p.x.mulI(z2z2);
        const u_2 = q.x.mulI(z1z1);
        const s_1 = p.y.mulI(q.z).mulI(z2z2);
        const s_2 = q.y.mulI(p.z).mulI(z1z1);
        const h = u_2.sub(u_1);
        const r = s_2.sub(s_1).dbl();
        if (h.isZero()) return if (r.isZero()) p.dbl() else identity;
        const i = h.dbl().sqI();
        const j = h.mulI(i);
        const v = u_1.mulI(i);
        const x3 = r.sqI().sub(j).sub(v.dbl());
        const y3 = r.mulI(v.sub(x3)).sub(s_1.mulI(j).dbl());
        const z3 = p.z.add(q.z).sqI().sub(z1z1).sub(z2z2).mulI(h);
        return .{ .x = x3, .y = y3, .z = z3 };
    }

    /// (X·Z : Y : Z³) — the same point in `P521`'s projective form; Z = 0
    /// gives a Z = 0 point (the caller maps it to `identityElement`).
    fn toProjective(p: Jac) P521 {
        return .{ .x = p.x.mulI(p.z), .y = p.y, .z = p.z.sqI().mulI(p.z) };
    }

    fn toProjectiveVt(p: Jac) P521 {
        if (p.isIdentityVt()) return P521.identityElement;
        return p.toProjective();
    }

    fn blendFrom(p: *Jac, a: Jac, mask: u64) void {
        blend(&p.x, a.x, mask);
        blend(&p.y, a.y, mask);
        blend(&p.z, a.z, mask);
    }
};

/// Room for a width-5 NAF of any 66-byte scalar (at most 529 digits).
const wnaf_len = 530;

// ── fixed-base comb table ───────────────────────────────────────────────────

const fb_w = 5;
const fb_t = 106; // ⌈(528 + 1) / 5⌉: every 66-byte scalar, plus the top carry
const fb_teeth = 1 << (fb_w - 1); // magnitudes 1 .. 16
const fb_half: u64 = 1 << (fb_w - 1);
const fb_twow: u64 = 1 << fb_w;
const fb_wmask: u64 = fb_twow - 1;

comptime {
    // The top window holds bits 525..527 of the scalar (66 bytes = 528 bits),
    // so x ≤ 7 + 1 < fb_half there: no carry, and so no digit, escapes.
    std.debug.assert(fb_t * fb_w >= 528 + 1);
    std.debug.assert((1 << (528 - (fb_t - 1) * fb_w)) - 1 + 1 < fb_half);
}

/// `tab[i][j] = (j + 1)·2^(5i)·G`, affine. Public constant.
pub const BaseTable = [fb_t][fb_teeth]AffineCoordinates;

/// The fixed-base table for G (see `combMulBaseCt`).
/// Generated by `tools/gen_base_table.py` (independent Python affine
/// arithmetic) rather than built at comptime: the comptime build cost every
/// compile of the module ~1 minute and ~2 GB (2026-10-10).
pub const base_table: BaseTable = @import("base_table.zig").table;

/// Optimization barrier: launder a value through an empty inline asm so LLVM
/// loses what it knows about it (p256's `blackBox`, montint `b199192`).
inline fn blackBox(x: u64) u64 {
    return asm volatile (""
        : [ret] "=r" (-> u64),
        : [x] "0" (x),
    );
}

/// `dst = (dst & ~mask) | (src & mask)`, `mask` 0 or all ones.
inline fn blend(dst: *field.Fe, src: field.Fe, mask: u64) void {
    for (&dst.l, src.l) |*d, v| d.* = (v & mask) | (d.* & ~mask);
}

/// What `ecdh` can fail with.
pub const EcdhError = IdentityElementError || NonCanonicalError || EncodingError || NotSquareError;

/// ECDH (SP 800-56A §5.7.1.2 / SEC 1 §3.3.1): the x-coordinate of
/// `secret · peer`, 66 bytes big-endian. `secret` must be in [1, n − 1]
/// (`error.NonCanonical` above, `error.IdentityElement` for 0); `peer_sec1`
/// is a compressed or uncompressed SEC1 point, validated (canonical, on the
/// curve, not the identity). std's shape (secret by value, result returned);
/// `ecdhInto` is the dead-stack-clean form.
pub fn ecdh(secret: [66]u8, peer_sec1: []const u8) EcdhError![66]u8 {
    var out: [66]u8 = undefined;
    try ecdhInto(&out, &secret, peer_sec1);
    return out;
}

/// `ecdh` with the secret by pointer and the shared secret into `out`
/// (zeroed on error). Burned (`burn.mul_burn`); constant time in `secret`.
pub fn ecdhInto(out: *[66]u8, secret: *const [66]u8, peer_sec1: []const u8) EcdhError!void {
    return burn.run(burn.mul_burn, EcdhError!void, ecdhBody, .{ out, secret, peer_sec1 });
}

fn ecdhBody(out: *[66]u8, secret: *const [66]u8, peer_sec1: []const u8) EcdhError!void {
    errdefer out.* = @splat(0);
    const peer = try P521.fromSec1(peer_sec1);
    try peer.rejectIdentity();
    // Range verdicts on the secret: revealed by the error, declassified.
    var ok: u8 = 0;
    const s = scalar_mod.Scalar.fromBytesCt(secret, .big, &ok);
    var zero: u8 = s.isZeroCt();
    ct.declassify(&ok);
    ct.declassify(&zero);
    if (ok == 0) return error.NonCanonical;
    if (zero != 0) return error.IdentityElement;
    var le = secret.*;
    defer std.crypto.secureZero(u8, &le);
    std.mem.reverse(u8, &le);
    const q = P521.mulCt(peer, &le);
    // Never the identity for s in [1, n − 1] and a point of prime order;
    // checked anyway, on a verdict the error would reveal.
    var id: u8 = q.isIdentityCt();
    ct.declassify(&id);
    if (id != 0) return error.IdentityElement;
    out.* = q.affineCoordinates().x.toBytes(.big);
}

/// A point in affine coordinates.
pub const AffineCoordinates = struct {
    x: P521.Fe,
    y: P521.Fe,

    /// The identity in affine form, (0, 0) — what `affineCoordinates`
    /// returns for it.
    pub const identityElement: AffineCoordinates = .{ .x = P521.Fe.zero, .y = P521.Fe.zero };

    pub fn neg(p: AffineCoordinates) AffineCoordinates {
        return .{ .x = p.x, .y = p.y.neg() };
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn nBytes() [66]u8 {
    var b: [66]u8 = undefined;
    std.mem.writeInt(u528, &b, scalar_mod.field_order, .big);
    return b;
}

test "group: G is on the curve and has order n" {
    _ = try P521.fromAffineCoordinates(P521.basePoint.affineCoordinates());
    try testing.expectError(error.IdentityElement, P521.basePoint.mul(nBytes(), .big));
    var nm1 = nBytes();
    nm1[65] -= 1; // n − 1: −G
    const q = try P521.basePoint.mul(nm1, .big);
    try testing.expect(q.equivalent(P521.basePoint.neg()));
    try testing.expectError(error.IdentityElement, P521.basePoint.mulPublic(nBytes(), .big));
}

test "group: complete addition (doubling via add, identity both sides)" {
    const g = P521.basePoint;
    try testing.expect(g.add(g).equivalent(g.dbl()));
    try testing.expect(g.add(P521.identityElement).equivalent(g));
    try testing.expect(P521.identityElement.add(g).equivalent(g));
    try testing.expect(g.sub(g).equivalent(P521.identityElement));
    try testing.expect(P521.identityElement.dbl().z.isZero());
    const g2 = g.dbl();
    try testing.expect(g2.add(g).equivalent(g.add(g2)));
    try testing.expect(g2.addMixed(g.affineCoordinates()).equivalent(g2.add(g)));
    try testing.expect(g2.addMixed(AffineCoordinates.identityElement).equivalent(g2));
}

test "group: constant-time, vartime and double-base multiplies agree" {
    var prng = std.Random.DefaultPrng.init(0x5213);
    const r = prng.random();
    for (0..6) |_| {
        var a: [66]u8 = undefined;
        var b: [66]u8 = undefined;
        r.bytes(&a);
        r.bytes(&b);
        a[0] &= 1;
        b[0] &= 1;
        const pa = try P521.basePoint.mul(a, .big);
        try testing.expect(pa.equivalent(try P521.basePoint.mulPublic(a, .big)));
        const pb = try pa.mul(b, .big);
        const ab = scalar_mod.mul(a, b, .big) catch continue; // ≥ n: probability 2^-260
        const pab = try P521.basePoint.mul(ab, .big);
        try testing.expect(pb.equivalent(pab));
        const dbp = try P521.mulDoubleBasePublic(P521.basePoint, a, pa, b, .big);
        try testing.expect(dbp.equivalent(pa.add(pb)));
        // Little-endian input is the same scalar.
        var al = a;
        std.mem.reverse(u8, &al);
        try testing.expect(pa.equivalent(try P521.basePoint.mul(al, .little)));
    }
}

test "group: SEC1 round trips and refusals" {
    const g = P521.basePoint;
    const u = g.toUncompressedSec1();
    const c = g.toCompressedSec1();
    try testing.expect((try P521.fromSec1(&u)).equivalent(g));
    try testing.expect((try P521.fromSec1(&c)).equivalent(g));
    const g3 = g.dbl().add(g);
    try testing.expect((try P521.fromSec1(&g3.toCompressedSec1())).equivalent(g3));
    // Off the curve.
    var bad = u;
    bad[132] ^= 1;
    try testing.expectError(error.InvalidEncoding, P521.fromSec1(&bad));
    // Wrong lengths / prefixes.
    try testing.expectError(error.InvalidEncoding, P521.fromSec1(u[0..132]));
    try testing.expectError(error.InvalidEncoding, P521.fromSec1(&.{}));
    bad = u;
    bad[0] = 5;
    try testing.expectError(error.InvalidEncoding, P521.fromSec1(&bad));
    // x = p: non-canonical.
    var nc: [67]u8 = @splat(0xff);
    nc[0] = 2;
    nc[1] = 1;
    try testing.expectError(error.NonCanonical, P521.fromSec1(&nc));
    // The identity encoding decodes to the identity (std's behaviour).
    try testing.expect((try P521.fromSec1(&.{0})).z.isZero());
}

test "comb: combMulBaseCt(s) == mulCt(G, s) on edge and random 66-byte scalars, and a corrupted table fails it" {
    const G = P521.basePoint;
    var cases: [8][66]u8 = undefined;
    cases[0] = @splat(0); // 0·G = O
    cases[1] = @splat(0);
    cases[1][0] = 1;
    cases[2] = nBytes(); // n (big-endian) → reversed below to little-endian
    std.mem.reverse(u8, &cases[2]);
    cases[3] = cases[2];
    cases[3][0] -%= 1; // n − 1 (n is odd: no borrow)
    cases[4] = @splat(0xff); // 2^528 − 1, beyond n: still s·G
    cases[5] = @splat(0);
    cases[5][65] = 0x01; // 2^520
    cases[6] = @splat(0x10); // every window's digit hits the carry path
    cases[7] = @splat(0x0f);
    for (cases) |s| try testing.expect(P521.combMulBaseCt(&base_table, &s).equivalent(P521.mulCt(G, &s)));

    var prng = std.Random.DefaultPrng.init(0x9521_c0b);
    const iters: usize = if (@import("builtin").mode == .debug) 24 else 400;
    for (0..iters) |_| {
        var s: [66]u8 = undefined;
        prng.random().bytes(&s);
        try testing.expect(P521.combMulBaseCt(&base_table, &s).equivalent(P521.mulCt(G, &s)));
    }

    // Teeth: one entry of one window off by G, and a scalar that selects it.
    var bad = base_table;
    bad[7][3] = P521.basePoint.add(.{ .x = bad[7][3].x, .y = bad[7][3].y }).affineCoordinates();
    var s: [66]u8 = @splat(0);
    // digit 4 (magnitude 4 → entry j = 3) in window 7: bits 35..39.
    s[4] = 4 << 3;
    try testing.expect(!P521.combMulBaseCt(&bad, &s).equivalent(P521.mulCt(G, &s)));
    try testing.expect(P521.combMulBaseCt(&base_table, &s).equivalent(P521.mulCt(G, &s)));
}

test "comb: base_table entries are (j+1)·2^(5i)·G (spot checks against mulPublic)" {
    const G = P521.basePoint;
    for ([_][2]usize{ .{ 0, 0 }, .{ 0, 15 }, .{ 1, 0 }, .{ 50, 9 }, .{ 104, 15 }, .{ 105, 0 } }) |ij| {
        var s: [66]u8 = @splat(0);
        // (j+1)·2^(5i), little-endian bytes.
        const bit = 5 * ij[0];
        const v: u16 = @as(u16, @intCast(ij[1] + 1)) << @intCast(bit % 8);
        s[bit / 8] = @truncate(v);
        if (bit / 8 + 1 < 66) s[bit / 8 + 1] = @truncate(v >> 8);
        const want = (try G.mulPublic(s, .little)).affineCoordinates();
        const got = base_table[ij[0]][ij[1]];
        try testing.expect(want.x.equivalent(got.x) and want.y.equivalent(got.y));
    }
}

/// Test reference: the previous ladder — RCB complete formulas, unsigned
/// 4-bit windows, no reduction, no table conversion — for any 66-byte
/// little-endian scalar. Slow and simple; nothing here shares code with the
/// Jacobian paths it checks.
fn mulRcbReference(p: P521, s: [66]u8) P521 {
    const pc = P521.precompute(p, 15);
    var q = P521.identityElement;
    var pos: usize = 132;
    while (pos > 0) {
        pos -= 1;
        q = q.dbl().dbl().dbl().dbl();
        const nib = (s[pos >> 1] >> @as(u3, @intCast((pos & 1) * 4))) & 0xf;
        q = q.add(pc[nib]);
    }
    return q;
}

/// Same point: both the identity, or the same uncompressed SEC1 bytes
/// (`equivalent` would call a (0 : 0 : 0) garbage point equal to anything).
fn expectSamePoint(want: P521, got: P521) !void {
    const wid = want.z.isZero();
    try testing.expectEqual(wid, got.z.isZero());
    if (wid) return;
    try testing.expectEqualSlices(u8, &want.toUncompressedSec1(), &got.toUncompressedSec1());
}

/// Edge scalars (little-endian): 0, 1, 2, 15, 16, 17, n − 1, n, n + 1,
/// 2n − 1, 2^528 − 1, 2^520, nibble patterns, a lone top nibble.
fn edgeScalars() [14][66]u8 {
    var c: [14][66]u8 = @splat(@splat(0));
    c[1][0] = 1;
    c[2][0] = 2;
    c[3][0] = 15;
    c[4][0] = 16;
    c[5][0] = 17;
    var n = nBytes();
    std.mem.reverse(u8, &n);
    c[6] = n;
    c[6][0] -%= 1; // n is odd: no borrow
    c[7] = n;
    c[8] = n;
    c[8][0] +%= 1;
    const two_n = std.mem.readInt(u528, &n, .little) * 2 - 1;
    std.mem.writeInt(u528, &c[9], two_n, .little);
    c[10] = @splat(0xff);
    c[11][65] = 0x01;
    c[12] = @splat(0x10);
    c[13] = @splat(0x0f);
    return c;
}

test "jacobian: mulCt == RCB reference on edge and random scalars, G and another point" {
    var prng = std.Random.DefaultPrng.init(0x521_7ac0);
    const r = prng.random();
    var t: [66]u8 = undefined;
    r.bytes(&t);
    t[65] &= 1;
    const pts = [_]P521{ P521.basePoint, mulRcbReference(P521.basePoint, t) };
    for (pts) |p| {
        for (edgeScalars()) |s| try expectSamePoint(mulRcbReference(p, s), P521.mulCt(p, &s));
        const iters: usize = if (@import("builtin").mode == .debug) 8 else 100;
        for (0..iters) |_| {
            var s: [66]u8 = undefined;
            r.bytes(&s);
            // Mix full-width scalars with ones that have leading zero windows.
            if (r.boolean()) @memset(s[r.uintLessThan(usize, 66)..], 0);
            try expectSamePoint(mulRcbReference(p, s), P521.mulCt(p, &s));
        }
    }
}

test "jacobian: mulPublic and mulDoubleBasePublic == RCB reference, incl. doubling and cancelling sums" {
    var prng = std.Random.DefaultPrng.init(0x521_7ac1);
    const r = prng.random();
    const G = P521.basePoint;
    const G2 = G.dbl(); // a non-G first point: the wNAF path for p1 too
    for (edgeScalars()) |s| {
        const want = mulRcbReference(G2, s);
        if (want.z.isZero()) {
            try testing.expectError(error.IdentityElement, G2.mulPublic(s, .little));
        } else try expectSamePoint(want, try G2.mulPublic(s, .little));
    }
    const iters: usize = if (@import("builtin").mode == .debug) 6 else 60;
    for (0..iters) |_| {
        var a: [66]u8 = undefined;
        var b: [66]u8 = undefined;
        r.bytes(&a);
        r.bytes(&b);
        if (r.boolean()) @memset(a[r.uintLessThan(usize, 66)..], 0);
        const q = mulRcbReference(G, b);
        for ([_]P521{ G, G2 }) |p1| {
            const want = mulRcbReference(p1, a).add(mulRcbReference(q, b));
            try expectSamePoint(want, try P521.mulDoubleBasePublic(p1, a, q, b, .little));
        }
    }
    // a·G + a·G: the final sum doubles. a·G + (n − a)·G: it cancels.
    var a: [66]u8 = @splat(0);
    a[0] = 0x2b;
    a[40] = 0x77;
    try expectSamePoint(mulRcbReference(G, a).dbl(), try P521.mulDoubleBasePublic(G, a, G, a, .little));
    var n = nBytes();
    std.mem.reverse(u8, &n);
    var na: [66]u8 = undefined;
    std.mem.writeInt(u528, &na, std.mem.readInt(u528, &n, .little) - std.mem.readInt(u528, &a, .little), .little);
    try testing.expectError(error.IdentityElement, P521.mulDoubleBasePublic(G, a, G, na, .little));
    try testing.expectError(error.IdentityElement, P521.mulDoubleBasePublic(G2, a, G2, na, .little));
    // addAffineVt's exceptional branches, pinned directly: q = p doubles,
    // q = −p cancels.
    const g_aff = G.affineCoordinates();
    const gj: Jac = .{ .x = g_aff.x, .y = g_aff.y, .z = P521.Fe.one };
    try expectSamePoint(G.dbl(), gj.addAffineVt(g_aff).toProjectiveVt());
    try testing.expect(gj.addAffineVt(g_aff.neg()).isIdentityVt());
}

test "jacobian: wnaf5 digits rebuild the scalar and keep the NAF shape" {
    var prng = std.Random.DefaultPrng.init(0x521_7ac2);
    var cases: [40][66]u8 = undefined;
    for (edgeScalars(), 0..) |s, i| cases[i] = s;
    for (cases[14..]) |*s| prng.random().bytes(s);
    for (cases) |s| {
        const e = P521.wnaf5(s);
        var acc: i1100 = 0;
        var last: ?usize = null;
        var pos: usize = e.len;
        while (pos > 0) {
            pos -= 1;
            acc *= 2;
            acc += e[pos];
            const d = e[pos];
            if (d != 0) {
                try testing.expect(@mod(d, 2) == 1 and d >= -15 and d <= 15);
                if (last) |l| try testing.expect(l - pos >= 5);
                last = pos;
            }
        }
        try testing.expectEqual(@as(i1100, std.mem.readInt(u528, &s, .little)), acc);
    }
}
