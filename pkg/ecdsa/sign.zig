// SPDX-License-Identifier: MIT

//! ECDSA over P-521 (FIPS 186-5 §6.4) with deterministic nonces per RFC 6979
//! (§3.2; §3.6's additional data when `noise` is given).
//!
//! `Ecdsa(Hash)` mirrors the surface of `std.crypto.sign.ecdsa.Ecdsa(Curve,
//! Hash)` — `KeyPair`, `SecretKey`, `PublicKey`, `Signature` (raw and DER),
//! `Signer`/`Verifier`, `sign(msg, noise)`, `verify(msg, pk)` — so a consumer
//! written against std's `EcdsaP384Sha384` takes `EcdsaP521Sha512` by
//! swapping the type. std's generic cannot be instantiated for P-521: its
//! scalar reduction stops at 64 bytes and its DER encoder writes a one-byte
//! SEQUENCE length, which a 139-byte P-521 signature overflows.
//!
//! Differences from std, all deliberate:
//!   * nonces are RFC 6979 exactly (std mixes the noise in another way), so
//!     `sign(msg, null)` reproduces RFC 6979 A.2.7 and OpenSSL's
//!     `nonce-type:1` byte for byte;
//!   * `fromSecretKey` refuses a secret ≥ n (`error.NonCanonical`), where std
//!     defers that to the first signature;
//!   * `PublicKey.fromSec1` refuses the identity encoding;
//!   * `fromDer` is strict DER (minimal lengths and integers, no trailing
//!     bytes), and handles the two-byte SEQUENCE length P-521 needs;
//!   * dead-stack shapes (CONVENTIONS.md §2.1.1): `KeyPair` methods take
//!     `*const KeyPair`, every secret path is burned, and `*Into` twins
//!     return secrets through `out`.
//!
//! Constant time: the secret key, the nonce, `k⁻¹` and every intermediate of
//! signing go through branch-free code (`group.mulCt`, `Scalar`, HMAC). The
//! branches that remain are on values the API reveals — a secret's range
//! verdict (an error), `r = 0`/`s = 0` (published in the signature) and the
//! RFC 6979 retry when a candidate is ≥ n (probability < 2^-259) — and are
//! declassified for ctgrind (`ct.zig`). Verification is variable time on
//! public inputs.

const std = @import("std");
const group = @import("group.zig");
const scalar = @import("scalar.zig");
const burn = @import("burn.zig");
const ct = @import("ct.zig");

const P521 = group.P521;
const Scalar = scalar.Scalar;
const errors = std.crypto.errors;
const IdentityElementError = errors.IdentityElementError;
const NonCanonicalError = errors.NonCanonicalError;
const EncodingError = errors.EncodingError;
const SignatureVerificationError = errors.SignatureVerificationError;
const NotSquareError = errors.NotSquareError;

/// ECDSA-P521 with SHA-512 (ssh `ecdsa-sha2-nistp521`, JWS `ES512`, X.509
/// `ecdsa-with-SHA512`).
pub const EcdsaP521Sha512 = Ecdsa(std.crypto.hash.sha2.Sha512);

/// The errors a signature can fail with.
pub const SignError = IdentityElementError || NonCanonicalError;

/// ECDSA over P-521 with any hash whose digest is at most 65 bytes (a longer
/// one would need bits2int's truncation, which no listed scheme uses).
pub fn Ecdsa(comptime Hash: type) type {
    comptime std.debug.assert(Hash.digest_length <= 65);
    const Hmac = std.crypto.auth.hmac.Hmac(Hash);

    return struct {
        /// Length of the optional additional data mixed into the nonce.
        pub const noise_length = scalar.encoded_length;

        /// An ECDSA secret key: a big-endian scalar in [1, n − 1].
        pub const SecretKey = struct {
            pub const encoded_length = scalar.encoded_length;
            bytes: scalar.CompressedScalar,

            /// Wrap 66 bytes (validated when the key is used, as std does).
            // secret-api-ok: std's shape; the bytes are only wrapped, nothing is computed, and `KeyPair.fromSecretKeyInto` is the pointer path
            pub fn fromBytes(bytes: [encoded_length]u8) !SecretKey {
                return .{ .bytes = bytes };
            }

            // secret-api-ok: std's shape; a field read with no computation
            pub fn toBytes(sk: SecretKey) [encoded_length]u8 {
                return sk.bytes;
            }
        };

        /// An ECDSA public key.
        pub const PublicKey = struct {
            pub const compressed_sec1_encoded_length = 67;
            pub const uncompressed_sec1_encoded_length = 133;
            p: P521,

            /// Decode a SEC1 point (compressed or uncompressed); the identity
            /// is refused.
            pub fn fromSec1(sec1: []const u8) (EncodingError || NotSquareError || NonCanonicalError || IdentityElementError)!PublicKey {
                const p = try P521.fromSec1(sec1);
                try p.rejectIdentity();
                return .{ .p = p };
            }

            pub fn toCompressedSec1(pk: PublicKey) [compressed_sec1_encoded_length]u8 {
                return pk.p.toCompressedSec1();
            }

            pub fn toUncompressedSec1(pk: PublicKey) [uncompressed_sec1_encoded_length]u8 {
                return pk.p.toUncompressedSec1();
            }
        };

        /// An ECDSA signature (r, s), each a 66-byte big-endian scalar.
        pub const Signature = struct {
            pub const encoded_length = 2 * scalar.encoded_length;
            /// 0x30 0x81 L ‖ (0x02 L r)(0x02 L s): each INTEGER is at most
            /// 66 content bytes (a 66-byte r has top byte ≤ 0x01, so it never
            /// needs a sign byte; a 65-byte one may, making 66 again).
            pub const der_encoded_length_max = 3 + 2 * (2 + 66);

            r: scalar.CompressedScalar,
            s: scalar.CompressedScalar,

            pub fn verifier(sig: Signature, public_key: PublicKey) Verifier.InitError!Verifier {
                return Verifier.init(sig, public_key);
            }

            pub const VerifyError = Verifier.InitError || Verifier.VerifyError;

            pub fn verify(sig: Signature, msg: []const u8, public_key: PublicKey) VerifyError!void {
                var st = try sig.verifier(public_key);
                st.update(msg);
                return st.verify();
            }

            pub fn verifyPrehashed(sig: Signature, msg_hash: [Hash.digest_length]u8, public_key: PublicKey) VerifyError!void {
                var st = try sig.verifier(public_key);
                return st.verifyPrehashed(msg_hash);
            }

            /// r ‖ s.
            pub fn toBytes(sig: Signature) [encoded_length]u8 {
                return sig.r ++ sig.s;
            }

            pub fn fromBytes(bytes: [encoded_length]u8) Signature {
                return .{ .r = bytes[0..66].*, .s = bytes[66..132].* };
            }

            /// DER `SEQUENCE { INTEGER r, INTEGER s }`, minimal encoding.
            pub fn toDer(sig: Signature, buf: *[der_encoded_length_max]u8) []u8 {
                var body: [der_encoded_length_max]u8 = undefined;
                var n: usize = 0;
                for ([_]*const [66]u8{ &sig.r, &sig.s }) |v| {
                    var t = std.mem.trimStart(u8, v, &.{0});
                    if (t.len == 0) t = v[65..66];
                    const pad: usize = t[0] >> 7;
                    body[n] = 0x02;
                    body[n + 1] = @intCast(t.len + pad);
                    n += 2;
                    if (pad == 1) {
                        body[n] = 0;
                        n += 1;
                    }
                    @memcpy(body[n..][0..t.len], t);
                    n += t.len;
                }
                var h: usize = 0;
                buf[0] = 0x30;
                if (n < 0x80) {
                    buf[1] = @intCast(n);
                    h = 2;
                } else {
                    buf[1] = 0x81;
                    buf[2] = @intCast(n);
                    h = 3;
                }
                @memcpy(buf[h..][0..n], body[0..n]);
                return buf[0 .. h + n];
            }

            /// One strict-DER INTEGER, non-negative, fitting 66 bytes.
            fn readInt(der: []const u8, pos: *usize, out: *[66]u8) EncodingError!void {
                const i = pos.*;
                if (der.len - i < 2 or der[i] != 0x02) return error.InvalidEncoding;
                const len = der[i + 1];
                if (len == 0 or len >= 0x80 or der.len - i - 2 < len) return error.InvalidEncoding;
                const v = der[i + 2 ..][0..len];
                if (v[0] & 0x80 != 0) return error.InvalidEncoding; // negative
                if (v[0] == 0 and (len == 1 or v[1] & 0x80 == 0)) {
                    // A leading zero is allowed only as the sign byte; zero
                    // itself is the single byte 0x00.
                    if (len != 1) return error.InvalidEncoding;
                }
                const mag = if (v[0] == 0 and len > 1) v[1..] else v;
                if (mag.len > 66) return error.InvalidEncoding;
                out.* = @splat(0);
                @memcpy(out[66 - mag.len ..], mag);
                pos.* = i + 2 + len;
            }

            /// Strict DER: the SEQUENCE length in its minimal form (short
            /// below 128, `0x81 L` from 128), minimal INTEGERs, no trailing
            /// bytes.
            pub fn fromDer(der: []const u8) EncodingError!Signature {
                if (der.len < 2 or der[0] != 0x30) return error.InvalidEncoding;
                var pos: usize = undefined;
                var len: usize = undefined;
                if (der[1] < 0x80) {
                    len = der[1];
                    pos = 2;
                } else if (der[1] == 0x81) {
                    if (der.len < 3 or der[2] < 0x80) return error.InvalidEncoding;
                    len = der[2];
                    pos = 3;
                } else return error.InvalidEncoding;
                if (der.len != pos + len) return error.InvalidEncoding;
                var sig: Signature = undefined;
                try readInt(der, &pos, &sig.r);
                try readInt(der, &pos, &sig.s);
                if (pos != der.len) return error.InvalidEncoding;
                return sig;
            }
        };

        /// Incremental signer. Holds the secret key until finalized;
        /// `finalize` wipes it.
        pub const Signer = struct {
            h: Hash,
            secret_key: SecretKey,
            noise: ?[noise_length]u8,

            pub fn update(self: *Signer, data: []const u8) void {
                self.h.update(data);
            }

            /// Burned (`burn.sign_burn`); the signer's secret state is wiped.
            pub fn finalize(self: *Signer) SignError!Signature {
                var out: Signature = undefined;
                try burn.run(burn.sign_burn, SignError!void, finalizeBody, .{ self, &out });
                return out;
            }

            fn finalizeBody(self: *Signer, out: *Signature) SignError!void {
                defer std.crypto.secureZero(u8, std.mem.asBytes(self));
                var h: [Hash.digest_length]u8 = undefined;
                self.h.final(&h);
                return signCore(out, &self.secret_key.bytes, &h, if (self.noise) |*n| n else null);
            }
        };

        /// Incremental verifier.
        pub const Verifier = struct {
            h: Hash,
            r: Scalar,
            s: Scalar,
            public_key: PublicKey,

            pub const InitError = IdentityElementError || NonCanonicalError;
            pub const VerifyError = IdentityElementError || NonCanonicalError || SignatureVerificationError;

            fn init(sig: Signature, public_key: PublicKey) InitError!Verifier {
                const r = try Scalar.fromBytes(sig.r, .big);
                const s = try Scalar.fromBytes(sig.s, .big);
                if (r.isZero() or s.isZero()) return error.IdentityElement;
                return .{ .h = Hash.init(.{}), .r = r, .s = s, .public_key = public_key };
            }

            pub fn update(self: *Verifier, data: []const u8) void {
                self.h.update(data);
            }

            /// Variable time; every input is public.
            fn verifyPrehashed(self: *Verifier, msg_hash: [Hash.digest_length]u8) VerifyError!void {
                const e = hashToScalar(&msg_hash);
                const w = self.s.invert();
                const u_1 = e.mul(w).toBytes(.little);
                const u_2 = self.r.mul(w).toBytes(.little);
                const q = P521.mulDoubleBasePublic(P521.basePoint, u_1, self.public_key.p, u_2, .little) catch
                    return error.SignatureVerificationFailed;
                const x = q.affineCoordinates().x.toBytes(.big);
                if (!Scalar.fromBytesReduce(x, .big).equivalent(self.r)) return error.SignatureVerificationFailed;
            }

            pub fn verify(self: *Verifier) VerifyError!void {
                var h: [Hash.digest_length]u8 = undefined;
                self.h.final(&h);
                return self.verifyPrehashed(h);
            }
        };

        /// A key pair. Methods take `*const KeyPair` (no by-value copy of
        /// the secret half in the caller's frame); `kp.sign(...)` reads the
        /// same as with std.
        pub const KeyPair = struct {
            pub const seed_length = noise_length;
            public_key: PublicKey,
            secret_key: SecretKey,

            /// Derive a key pair from a secret seed: RFC 6979's HMAC-DRBG
            /// with x = 0x01⁶⁶, h = 0⁶⁶ and the seed as additional data, the
            /// first candidate in [1, n − 1] (the shape of std's derivation).
            pub fn generateDeterministic(seed: [seed_length]u8) SignError!KeyPair {
                var out: KeyPair = undefined;
                try generateDeterministicInto(&out, &seed);
                return out;
            }

            /// `generateDeterministic` with the seed by pointer and the pair
            /// into `out` (zeroed on error).
            pub fn generateDeterministicInto(out: *KeyPair, seed: *const [seed_length]u8) SignError!void {
                return burn.run(burn.sign_burn, SignError!void, generateDeterministicBody, .{ out, seed });
            }

            fn generateDeterministicBody(out: *KeyPair, seed: *const [seed_length]u8) SignError!void {
                errdefer std.crypto.secureZero(u8, std.mem.asBytes(out));
                const x: [66]u8 = @splat(0x01);
                const h: [66]u8 = @splat(0);
                var drbg: Drbg = .init(&x, &h, seed);
                defer std.crypto.secureZero(u8, std.mem.asBytes(&drbg));
                var d: Scalar = undefined;
                drbg.candidate(&d);
                out.secret_key.bytes = d.toBytes(.big);
                return fromSecretKeyBody(out, &out.secret_key);
            }

            /// A fresh random key pair. The seed comes from `entropy.fill`
            /// (fail-closed: aborts rather than degrade, CONVENTIONS.md §2.2).
            /// std's shape (returned by value); `generateInto` is the pointer
            /// twin.
            pub fn generate(io: std.Io) KeyPair {
                var kp: KeyPair = undefined;
                generateInto(&kp, io);
                return kp;
            }

            pub fn generateInto(out: *KeyPair, io: std.Io) void {
                var seed: [seed_length]u8 = undefined;
                defer std.crypto.secureZero(u8, &seed);
                while (true) {
                    io.random(&seed);
                    generateDeterministicInto(out, &seed) catch continue;
                    return;
                }
            }

            /// The key pair of `secret_key`; `error.NonCanonical` if it is
            /// ≥ n, `error.IdentityElement` if it is 0.
            pub fn fromSecretKey(secret_key: SecretKey) SignError!KeyPair {
                var out: KeyPair = undefined;
                try fromSecretKeyInto(&out, &secret_key);
                return out;
            }

            pub fn fromSecretKeyInto(out: *KeyPair, secret_key: *const SecretKey) SignError!void {
                return burn.run(burn.sign_burn, SignError!void, fromSecretKeyBody, .{ out, secret_key });
            }

            fn fromSecretKeyBody(out: *KeyPair, secret_key: *const SecretKey) SignError!void {
                errdefer std.crypto.secureZero(u8, std.mem.asBytes(out));
                try checkSecret(&secret_key.bytes);
                var le = secret_key.bytes;
                defer std.crypto.secureZero(u8, &le);
                std.mem.reverse(u8, &le);
                const q = P521.mulBaseCtUnburned(&le);
                out.secret_key = secret_key.*;
                out.public_key = .{ .p = q };
            }

            /// Sign `msg`. `noise` null: deterministic (RFC 6979); random
            /// noise: RFC 6979 §3.6 additional data, which hardens against
            /// fault attacks.
            pub fn sign(key_pair: *const KeyPair, msg: []const u8, noise: ?[noise_length]u8) SignError!Signature {
                var h: [Hash.digest_length]u8 = undefined;
                Hash.hash(msg, &h, .{});
                return key_pair.signPrehashed(h, noise);
            }

            /// Sign a digest computed with `Hash`.
            pub fn signPrehashed(key_pair: *const KeyPair, msg_hash: [Hash.digest_length]u8, noise: ?[noise_length]u8) SignError!Signature {
                var out: Signature = undefined;
                try signPrehashedInto(&out, key_pair, &msg_hash, if (noise) |*n| n else null);
                return out;
            }

            /// `signPrehashed` into `out`, noise by pointer. Burned.
            pub fn signPrehashedInto(out: *Signature, key_pair: *const KeyPair, msg_hash: *const [Hash.digest_length]u8, noise: ?*const [noise_length]u8) SignError!void {
                return burn.run(burn.sign_burn, SignError!void, signCore, .{ out, &key_pair.secret_key.bytes, msg_hash, noise });
            }

            /// An incremental signer over this key pair. It holds the secret
            /// key and is returned by value; `signerInto` is the
            /// dead-stack-clean form.
            // secret-api-ok: std's shape; a struct copy (no computation below this frame), the copy in the result is what `signerInto` avoids
            pub fn signer(key_pair: *const KeyPair, noise: ?[noise_length]u8) !Signer {
                var out: Signer = undefined;
                signerInto(&out, key_pair, if (noise) |*n| n else null);
                return out;
            }

            // secret-api-ok: a struct copy into `out`; nothing runs below this frame but `Hash.init`
            pub fn signerInto(out: *Signer, key_pair: *const KeyPair, noise: ?*const [noise_length]u8) void {
                out.* = .{ .h = Hash.init(.{}), .secret_key = key_pair.secret_key, .noise = if (noise) |n| n.* else null };
            }
        };

        /// bits2int(h) mod n. The digest is at most 65 bytes, so no
        /// truncation applies (RFC 6979 §2.3.2).
        fn hashToScalar(h: *const [Hash.digest_length]u8) Scalar {
            var w: [66]u8 = @splat(0);
            w[66 - Hash.digest_length ..].* = h.*;
            return Scalar.fromBytesReduce(w, .big);
        }

        /// RFC 6979 §3.2 HMAC-DRBG, qlen = 521, rlen = 528.
        const Drbg = struct {
            k: [Hmac.mac_length]u8,
            v: [Hmac.mac_length]u8,

            fn init(x: *const [66]u8, h1: *const [66]u8, extra: ?*const [66]u8) Drbg {
                var self: Drbg = .{ .k = @splat(0), .v = @splat(1) };
                inline for (.{ 0x00, 0x01 }) |tag| {
                    var m = Hmac.init(&self.k);
                    m.update(&self.v);
                    m.update(&.{tag});
                    m.update(x);
                    m.update(h1);
                    if (extra) |e| m.update(e);
                    m.final(&self.k);
                    Hmac.create(&self.v, &self.v, &self.k);
                }
                return self;
            }

            /// Steps (h.1)–(h.3): the next candidate in [1, n − 1]. A
            /// candidate out of range re-keys and retries; that branch is on
            /// a bit whose probability is < 2^-259, declassified.
            fn candidate(self: *Drbg, out: *Scalar) void {
                const blocks = (66 + Hmac.mac_length - 1) / Hmac.mac_length;
                var t: [blocks * Hmac.mac_length]u8 = undefined;
                defer std.crypto.secureZero(u8, &t);
                while (true) {
                    for (0..blocks) |i| {
                        Hmac.create(&self.v, &self.v, &self.k);
                        t[i * Hmac.mac_length ..][0..Hmac.mac_length].* = self.v;
                    }
                    // bits2int: the leftmost 521 bits of T = T[0..66] >> 7.
                    var kb: [66]u8 = undefined;
                    defer std.crypto.secureZero(u8, &kb);
                    var carry: u8 = 0;
                    for (0..66) |i| {
                        kb[i] = (t[i] >> 7) | carry;
                        carry = t[i] << 1;
                    }
                    var ok: u8 = 0;
                    out.* = Scalar.fromBytesCt(&kb, .big, &ok);
                    ok &= ~@as(u8, out.isZeroCt());
                    ct.declassify(&ok); // RFC 6979 retry bit (probability < 2^-259)
                    if (ok != 0) return;
                    self.reseed();
                }
            }

            /// Step (h.3)'s re-key: K = HMAC_K(V ‖ 0x00), V = HMAC_K(V).
            fn reseed(self: *Drbg) void {
                var m = Hmac.init(&self.k);
                m.update(&self.v);
                m.update(&.{0x00});
                m.final(&self.k);
                Hmac.create(&self.v, &self.v, &self.k);
            }
        };

        /// Range check of a secret scalar: [1, n − 1]. The verdict is
        /// declassified — the error reveals it.
        fn checkSecret(d: *const [66]u8) SignError!void {
            var ok: u8 = 0;
            const s = Scalar.fromBytesCt(d, .big, &ok);
            var zero: u8 = s.isZeroCt();
            ct.declassify(&ok);
            ct.declassify(&zero);
            if (ok == 0) return error.NonCanonical;
            if (zero != 0) return error.IdentityElement;
        }

        /// The signature for one nonce; `false` if r or s came out 0 (the
        /// caller draws the next nonce). r and s are the published
        /// signature, so testing them is not a leak; declassified.
        fn signWithNonce(out: *Signature, d: *const Scalar, e: *const Scalar, k: *const Scalar) bool {
            var kle = k.toBytes(.little);
            defer std.crypto.secureZero(u8, &kle);
            const big_r = P521.mulBaseCtUnburned(&kle);
            var r = Scalar.fromBytesReduce(big_r.affineCoordinates().x.toBytes(.big), .big);
            const s = k.invert().mul(e.add(r.mul(d.*)));
            var bad: u8 = r.isZeroCt() | s.isZeroCt();
            ct.declassify(&bad);
            if (bad != 0) return false;
            out.r = r.toBytes(.big);
            out.s = s.toBytes(.big);
            ct.declassify(&out.r);
            ct.declassify(&out.s);
            r = Scalar.zero;
            return true;
        }

        /// Sign a digest: RFC 6979 nonces until r, s ≠ 0.
        fn signCore(out: *Signature, d_bytes: *const [66]u8, h: *const [Hash.digest_length]u8, noise: ?*const [noise_length]u8) SignError!void {
            try checkSecret(d_bytes);
            var d = Scalar.fromBytesReduce(d_bytes.*, .big);
            defer std.crypto.secureZero(u8, std.mem.asBytes(&d));
            const e = hashToScalar(h);
            const h1 = e.toBytes(.big); // bits2octets(h)
            var drbg: Drbg = .init(d_bytes, &h1, noise);
            defer std.crypto.secureZero(u8, std.mem.asBytes(&drbg));
            var k: Scalar = undefined;
            defer std.crypto.secureZero(u8, std.mem.asBytes(&k));
            while (true) {
                drbg.candidate(&k);
                if (signWithNonce(out, &d, &e, &k)) return;
                drbg.reseed();
            }
        }

        /// Sign a digest with a caller-chosen nonce (CAVP SigGen vectors).
        /// Test-only: a reused or biased nonce reveals the key, so outside a
        /// test build the declaration is `void` and cannot be called. (A
        /// `@compileError` in the body instead fails `check-testonly`, whose
        /// probe references every public function of the published module.)
        pub const signPrehashedWithNonceForTesting = if (@import("builtin").is_test) signWithNonceForTesting else {};

        fn signWithNonceForTesting(out: *Signature, d_bytes: *const [66]u8, h: *const [Hash.digest_length]u8, k_bytes: *const [66]u8) SignError!void {
            try checkSecret(d_bytes);
            const d = Scalar.fromBytesReduce(d_bytes.*, .big);
            const k = try Scalar.fromBytes(k_bytes.*, .big);
            const e = hashToScalar(h);
            if (!signWithNonce(out, &d, &e, &k)) return error.IdentityElement;
        }
    };
}
