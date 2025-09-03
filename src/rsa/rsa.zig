const std = @import("std");
const fmt = std.fmt;
const ff = std.crypto.ff;
const testing = std.testing;
const base64 = std.base64;
const Allocator = std.mem.Allocator;

pub const der = @import("der.zig");
pub const oids = @import("oid.zig");

pub const max_modulus_bits = 4096;
pub const max_modulus_len = max_modulus_bits / 8;

pub const pss_salt_length_auto = 0;

const oid_rsa_publickey = "1.2.840.113549.1.1.1";

const Modulus = std.crypto.ff.Modulus(max_modulus_bits);
const Fe = Modulus.Fe;

pub const PublicKey = struct {
    n: Modulus,
    e: Fe,

    const Self = @This();

    pub fn size(self: Self) usize {
        return byteLen(self.n.bits());
    }

    pub fn fromBytes(mod: []const u8, exp: []const u8) !PublicKey {
        const n = try Modulus.fromBytes(mod, .big);
        if (n.bits() <= 512) return error.InsecureBitCount;
        const e = try Fe.fromBytes(n, exp, .big);

        if (std.debug.runtime_safety) {
            // > the RSA public exponent e is an integer between 3 and n - 1 satisfying
            // > GCD(e,\lambda(n)) = 1, where \lambda(n) = LCM(r_1 - 1, ..., r_u - 1)
            const e_v = e.toPrimitive(u32) catch return error.Exponent;
            if (!e.isOdd()) return error.Exponent;
            if (e_v < 3) return error.Exponent;
            if (n.v.compare(e.v) == .lt) return error.Exponent;
        }

        return .{
            .n = n,
            .e = e,
        };
    }

    pub fn fromDer(bytes: []const u8) !PublicKey {
        var parser = der.Parser{ .bytes = bytes };

        const seq = try parser.expectSequence();
        defer parser.seek(seq.slice.end);

        const modulus = try parser.expectPrimitive(.integer);
        const pub_exp = try parser.expectPrimitive(.integer);

        // try parser.expectEnd(seq.slice.end);
        // try parser.expectEnd(bytes.len);

        return Self.fromBytes(parser.view(modulus), parser.view(pub_exp));
    }

    pub fn fromPKCS8Der(bytes: []const u8) !PublicKey {
        var parser = der.Parser{ .bytes = bytes };
        const seq = try parser.expectSequence();

        const oid_seq = try parser.expectSequence();
        const oid = try parser.expectOid();

        try checkRSAPublickeyOid(oid);

        parser.seek(oid_seq.slice.end);
        const pubkey = try parser.expectBitstring();

        _ = seq;

        return Self.fromDer(pubkey.bytes);
    }

    pub fn fromDerAuto(bytes: []const u8) !PublicKey {
        const pk = Self.fromPKCS8Der(bytes) catch {
            return Self.fromDer(bytes);
        };

        return pk;
    }

    /// Encrypt a short message using RSAES-PKCS1-v1_5.
    pub fn encryptPkcsv1_5(self: Self, msg: []const u8, out: []u8) ![]const u8 {
        // align variable names with spec
        const k = byteLen(self.n.bits());
        if (out.len < k) return error.BufferTooSmall;
        if (msg.len > k - 11) return error.MessageTooLong;

        // EM = 0x00 || 0x02 || PS || 0x00 || M.
        var em = out[0..k];
        em[0] = 0;
        em[1] = 2;

        const ps = em[2..][0 .. k - msg.len - 3];
        // Section: 7.2.1
        // PS consists of pseudo-randomly generated nonzero octets.
        for (ps) |*v| {
            v.* = std.crypto.random.uintLessThan(u8, 0xff) + 1;
        }

        em[em.len - msg.len - 1] = 0;
        @memcpy(em[em.len - msg.len ..][0..msg.len], msg);

        const m = try Fe.fromBytes(self.n, em, .big);
        const e = try self.n.powPublic(m, self.e);
        try e.toBytes(em, .big);
        return em;
    }

    /// Encrypt a short message using Optimal Asymmetric Encryption Padding (RSAES-OAEP).
    pub fn encryptOaep(
        self: Self,
        comptime Hash: type,
        msg: []const u8,
        label: []const u8,
        out: []u8,
    ) ![]const u8 {
        // align variable names with spec
        const k = byteLen(self.n.bits());
        if (out.len < k) return error.BufferTooSmall;

        if (msg.len > k - 2 * Hash.digest_length - 2) return error.MessageTooLong;

        // EM = 0x00 || maskedSeed || maskedDB.
        var em = out[0..k];
        em[0] = 0;
        const seed = em[1..][0..Hash.digest_length];
        std.crypto.random.bytes(seed);

        // DB = lHash || PS || 0x01 || M.
        var db = em[1 + seed.len ..];
        const lHash = labelHash(Hash, label);
        @memcpy(db[0..lHash.len], &lHash);
        @memset(db[lHash.len .. db.len - msg.len - 2], 0);
        db[db.len - msg.len - 1] = 1;
        @memcpy(db[db.len - msg.len ..], msg);

        var mgf_buf: [max_modulus_len]u8 = undefined;

        const db_mask = mgf1(Hash, seed, mgf_buf[0..db.len]);
        for (db, db_mask) |*v, m| v.* ^= m;

        const seed_mask = mgf1(Hash, db, mgf_buf[0..seed.len]);
        for (seed, seed_mask) |*v, m| v.* ^= m;

        const m = try Fe.fromBytes(self.n, em, .big);
        const e = try self.n.powPublic(m, self.e);
        try e.toBytes(em, .big);
        return em;
    }
};

pub const SecretKey = struct {
    public_key: PublicKey,
    d: Fe,
    primes: [2]Fe,

    // Precomputed contains precomputed values that speed up private
    // operations, if available.
    precomputed: ?PrecomputedValues = null,

    const Self = @This();

    pub fn fromBytes(n: []const u8, e: []const u8, dbytes: []const u8, p: Fe, q: Fe) !SecretKey {
        const public = try PublicKey.fromBytes(n, e);

        const d = try Fe.fromBytes(public.n, dbytes, .big);

        // > The RSA private exponent d is a positive integer less than n
        // > satisfying e * d == 1 (mod \lambda(n)),
        if (!d.isOdd()) return error.Exponent;
        if (d.v.compare(public.n.v) != .lt) return error.Exponent;

        const primes = [2]Fe{ p, q };

        return .{
            .public_key = public,
            .d = d,
            .primes = primes,
        };
    }

    pub fn fromDer(bytes: []const u8) !SecretKey {
        var parser = der.Parser{ .bytes = bytes };
        const seq = try parser.expectSequence();
        const version = try parser.expectInt(u8);

        const mod = try parser.expectPrimitive(.integer);
        const pub_exp = try parser.expectPrimitive(.integer);
        const sec_exp = try parser.expectPrimitive(.integer);

        const n = parser.view(mod);
        const e = parser.view(pub_exp);

        const public = try PublicKey.fromBytes(n, e);

        const prime1 = try parser.expectPrimitive(.integer);
        const prime2 = try parser.expectPrimitive(.integer);
        const exp1 = try parser.expectPrimitive(.integer);
        const exp2 = try parser.expectPrimitive(.integer);
        const coeff = try parser.expectPrimitive(.integer);
        _ = .{ exp1, exp2, coeff };

        switch (version) {
            0 => {},
            1 => {
                _ = try parser.expectSequenceOf();
                while (!parser.eof()) {
                    _ = try parser.expectSequence();
                    const ri = try parser.expectPrimitive(.integer);
                    const di = try parser.expectPrimitive(.integer);
                    const ti = try parser.expectPrimitive(.integer);
                    _ = .{ ri, di, ti };
                }
            },
            else => return error.InvalidVersion,
        }

        _ = seq;

        const p = try Fe.fromBytes(public.n, parser.view(prime1), .big);
        const q = try Fe.fromBytes(public.n, parser.view(prime2), .big);

        // check that n = p * q
        const expected_zero = public.n.mul(p, q);
        if (!expected_zero.isZero()) return error.KeyMismatch;

        const dbytes = parser.view(sec_exp);

        if (std.debug.runtime_safety) {
            // TODO: check that d * e is one mod p-1 and mod q-1. Note d and e were bound
            // const de = secret.d.mul(public.e);
            // const one = public.n.one();

            // if (public.n.mul(de, p).compare(one) != .eq) return error.KeyMismatch;
            // if (public.n.mul(de, q).compare(one) != .eq) return error.KeyMismatch;
        }

        return Self.fromBytes(n, e, dbytes, p, q);
    }

    pub fn fromPKCS8Der(bytes: []const u8) !SecretKey {
        var parser = der.Parser{ .bytes = bytes };
        _ = try parser.expectSequence();

        const version = try parser.expectInt(u8);
        if (version != 0) {
            return error.PKCS8VersionError;
        }

        const oid_seq = try parser.expectSequence();
        const oid = try parser.expectOid();

        try checkRSAPublickeyOid(oid);

        parser.seek(oid_seq.slice.end);
        const prikey = try parser.expect(.universal, false, .octetstring);

        return Self.fromDer(parser.view(prikey));
    }

    pub fn fromDerAuto(bytes: []const u8) !SecretKey {
        const sk = Self.fromPKCS8Der(bytes) catch {
            return Self.fromDer(bytes);
        };

        return sk;
    }

    pub fn decryptPkcsv1_5(self: Self, ciphertext: []const u8, out: []u8) ![]const u8 {
        const k = byteLen(self.public_key.n.bits());
        if (out.len < k) return error.BufferTooSmall;

        const em = out[0..k];

        const m = try Fe.fromBytes(self.public_key.n, ciphertext, .big);
        const e = try self.public_key.n.pow(m, self.d);
        try e.toBytes(em, .big);

        // Care shall be taken to ensure that an opponent cannot
        // distinguish these error conditions, whether by error
        // message or timing.
        const msg_start = ct.lastIndexOfScalar(em, 0) orelse em.len;
        const ps_len = em.len - msg_start;
        if (ct.@"or"(em[0] != 0, ct.@"or"(em[1] != 2, ps_len < 8))) {
            return error.Inconsistent;
        }

        return em[msg_start + 1 ..];
    }

    pub fn decryptOaep(
        self: Self,
        comptime Hash: type,
        ciphertext: []const u8,
        label: []const u8,
        out: []u8,
    ) ![]u8 {
        // align variable names with spec
        const k = byteLen(self.public_key.n.bits());
        if (out.len < k) return error.BufferTooSmall;

        const mod = try Fe.fromBytes(self.public_key.n, ciphertext, .big);
        const exp = self.public_key.n.pow(mod, self.d) catch unreachable;
        const em = out[0..k];
        try exp.toBytes(em, .big);

        const y = em[0];
        const seed = em[1..][0..Hash.digest_length];
        const db = em[1 + Hash.digest_length ..];

        var mgf_buf: [max_modulus_len]u8 = undefined;

        const seed_mask = mgf1(Hash, db, mgf_buf[0..seed.len]);
        for (seed, seed_mask) |*v, m| v.* ^= m;

        const db_mask = mgf1(Hash, seed, mgf_buf[0..db.len]);
        for (db, db_mask) |*v, m| v.* ^= m;

        const expected_hash = labelHash(Hash, label);
        const actual_hash = db[0..expected_hash.len];

        // Care shall be taken to ensure that an opponent cannot
        // distinguish these error conditions, whether by error
        // message or timing.
        const msg_start = ct.indexOfScalarPos(em, expected_hash.len + 1, 1) orelse 0;
        if (ct.@"or"(y != 0, ct.@"or"(msg_start == 0, !ct.memEql(&expected_hash, actual_hash)))) {
            return error.Inconsistent;
        }

        return em[msg_start + 1 ..];
    }

    /// decrypt short plaintext with secret key.
    pub fn decrypt(self: Self, plaintext: []const u8, out: []u8) !void {
        const n = self.public_key.n;
        const k = byteLen(n.bits());
        if (plaintext.len > k) {
            return error.MessageTooLong;
        }

        const msg_as_int = try Fe.fromBytes(n, plaintext, .big);
        const enc_as_int = try n.pow(msg_as_int, self.d);
        try enc_as_int.toBytes(out, .big);
    }

    pub fn validate(self: Self) !void {
        _ = self;
    }

    // Precompute performs some calculations that speed up private key operations
    // in the future.
    pub fn precompute(self: *Self) !void {
        if (self.precomputed != null) {
            return;
        }

        const big_one = Modulus.one();
        const big_zero = Modulus.zero;

        var dp = try Modulus.fromUint(self.d).sub(self.primes[0], big_one);
        dp = try Modulus.fromUint(dp).add(self.d, big_zero);

        var dq = try Modulus.fromUint(self.d).sub(self.primes[1], big_one);
        dq = try Modulus.fromUint(dq).add(self.d, big_zero);

        const qinv = Modulus.one();

        const precomputed: PrecomputedValues = .{
            .dp = dp,
            .dq = dq,
            .qinv = qinv,

            .crt_values = [2]CRTValue{
                .{
                    .exp = Modulus.one(),
                    .coeff = Modulus.one(),
                    .t = Modulus.one(),
                },
                .{
                    .exp = Modulus.one(),
                    .coeff = Modulus.one(),
                    .t = Modulus.one(),
                },
            },
        };

        self.precomputed = precomputed;
    }
};

pub const KeyPair = struct {
    public_key: PublicKey,
    secret_key: SecretKey,

    const Self = @This();

    /// Return the public key corresponding to the secret key.
    pub fn fromSecretKey(secret_key: SecretKey) !KeyPair {
        return .{
            .secret_key = secret_key,
            .public_key = secret_key.public_key,
        };
    }

    pub fn signPkcsv1_5(self: Self, comptime Hash: type, msg: []const u8, out: []u8) !PKCS1v1_5(Hash).Signature {
        var st = try self.signerPkcsv1_5(Hash);
        st.update(msg);
        return st.finalize(out);
    }

    pub fn signerPkcsv1_5(self: Self, comptime Hash: type) !PKCS1v1_5(Hash).Signer {
        return PKCS1v1_5(Hash).Signer.init(self.secret_key);
    }

    pub fn signOaep(
        self: Self,
        comptime Hash: type,
        msg: []const u8,
        salt: ?[]const u8,
        out: []u8,
    ) !Pss(Hash).Signature {
        var st = try self.signerOaep(Hash, salt);
        st.update(msg);
        return st.finalize(out);
    }

    /// Salt must outlive returned `PSS.Signer`.
    pub fn signerOaep(self: Self, comptime Hash: type, salt: ?[]const u8) !Pss(Hash).Signer {
        return Pss(Hash).Signer.init(self.secret_key, salt);
    }
};

pub const PrecomputedValues = struct {
    dp: Fe, // D mod (P-1)
    dq: Fe, // D mod (Q-1)
    qinv: Fe, // Q^-1 mod P

    // CRTValues is used for the 3rd and subsequent primes. Due to a
    // historical accident, the CRT for the first two primes is handled
    // differently in PKCS #1 and interoperability is sufficiently
    // important that we mirror this.
    crt_values: [2]CRTValue,
};

pub const CRTValue = struct {
    exp: Fe, // D mod (prime-1).
    coeff: Fe, // R·Coeff ≡ 1 mod Prime.
    r: Fe, // product of primes prior to this (inc p and q).
};

fn checkRSAPublickeyOid(oid: []const u8) !void {
    var buf: [256]u8 = undefined;
    var stream: std.Io.Writer = .fixed(&buf);
    try oids.decode(oid, &stream);

    const oid_string = stream.buffered();
    if (!std.mem.eql(u8, oid_string, oid_rsa_publickey)) {
        return error.RSAOidError;
    }

    return;
}

/// Signature Scheme with Appendix v1.5 (RSASSA-PKCS1-v1_5)
pub fn PKCS1v1_5(comptime Hash: type) type {
    return struct {
        const PkcsT = @This();

        pub const Signature = struct {
            bytes: []u8,

            const Self = @This();

            pub fn verifier(self: Self, public_key: PublicKey) !Verifier {
                return Verifier.init(self, public_key);
            }

            pub fn verify(self: Self, msg: []const u8, public_key: PublicKey) !void {
                var st = Verifier.init(self, public_key);
                st.update(msg);
                return st.verify();
            }

            /// Return the raw signature bytes.
            pub fn toBytes(self: Self) []u8 {
                return self.bytes;
            }

            /// Create a signature from a bytes.
            pub fn fromBytes(bytes: []u8) Self {
                return Signature{
                    .bytes = bytes,
                };
            }
        };

        pub const Signer = struct {
            h: Hash,
            secret_key: SecretKey,

            const Self = @This();

            pub fn init(secret_key: SecretKey) Signer {
                return .{
                    .h = Hash.init(.{}),
                    .secret_key = secret_key,
                };
            }

            pub fn update(self: *Self, data: []const u8) void {
                self.h.update(data);
            }

            pub fn finalize(self: *Self, out: []u8) !PkcsT.Signature {
                const k = byteLen(self.secret_key.public_key.n.bits());

                var hash: [Hash.digest_length]u8 = undefined;
                self.h.final(&hash);

                const em = try PkcsT.emsaEncode(hash, out[0..k]);

                try self.secret_key.decrypt(em, em);

                return Signature.fromBytes(em);
            }
        };

        pub const Verifier = struct {
            h: Hash,
            sig: []u8,
            public_key: PublicKey,

            const Self = @This();

            fn init(sig: PkcsT.Signature, public_key: PublicKey) Verifier {
                return Verifier{
                    .h = Hash.init(.{}),
                    .sig = sig.bytes,
                    .public_key = public_key,
                };
            }

            pub fn update(self: *Self, data: []const u8) void {
                self.h.update(data);
            }

            pub fn verify(self: *Self) !void {
                const pk = self.public_key;
                const s = try Fe.fromBytes(pk.n, self.sig, .big);
                const emm = try pk.n.powPublic(s, pk.e);

                var em_buf: [max_modulus_len]u8 = undefined;
                const em = em_buf[0..byteLen(pk.n.bits())];
                try emm.toBytes(em, .big);

                var hash: [Hash.digest_length]u8 = undefined;
                self.h.final(&hash);

                var em_buf2: [max_modulus_len]u8 = undefined;
                const em2 = em_buf2[0..byteLen(pk.n.bits())];
                const expected = try PkcsT.emsaEncode(hash, em2);

                if (!std.mem.eql(u8, expected, em)) {
                    return error.Inconsistent;
                }
            }
        };

        /// PKCS Encrypted Message Signature Appendix
        fn emsaEncode(hash: [Hash.digest_length]u8, out: []u8) ![]u8 {
            const digest_header = comptime PkcsT.digestHeader();
            const tLen = digest_header.len + Hash.digest_length;
            const emLen = out.len;
            if (emLen < tLen + 11) return error.ModulusTooShort;
            if (out.len < emLen) return error.BufferTooSmall;

            var res = out[0..emLen];
            res[0] = 0;
            res[1] = 1;
            const padding_len = emLen - tLen - 3;
            @memset(res[2..][0..padding_len], 0xff);
            res[2 + padding_len] = 0;
            @memcpy(res[2 + padding_len + 1 ..][0..digest_header.len], digest_header);
            @memcpy(res[res.len - hash.len ..], &hash);

            return res;
        }

        /// DER encoded header. Sequence of digest algo + digest.
        fn digestHeader() []const u8 {
            const sha2 = std.crypto.hash.sha2;
            // Section 9.2 Notes 1.
            return switch (Hash) {
                std.crypto.hash.Sha1 => &hexToBytes(
                    \\30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14
                ),
                sha2.Sha224 => &hexToBytes(
                    \\30 2d 30 0d 06 09 60 86 48 01 65 03 04 02 04
                    \\05 00 04 1c
                ),
                sha2.Sha256 => &hexToBytes(
                    \\30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00
                    \\04 20
                ),
                sha2.Sha384 => &hexToBytes(
                    \\30 41 30 0d 06 09 60 86 48 01 65 03 04 02 02 05 00
                    \\04 30
                ),
                sha2.Sha512 => &hexToBytes(
                    \\30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00
                    \\04 40
                ),
                // sha2.Sha512224 => &hexToBytes(
                //     \\30 2d 30 0d 06 09 60 86 48 01 65 03 04 02 05
                //     \\05 00 04 1c
                // ),
                // sha2.Sha512256 => &hexToBytes(
                //     \\30 31 30 0d 06 09 60 86 48 01 65 03 04 02 06
                //     \\05 00 04 20
                // ),
                else => @compileError("unknown Hash " ++ @typeName(Hash)),
            };
        }
    };
}

/// Probabilistic Signature Scheme (RSASSA-PSS)
pub fn Pss(comptime Hash: type) type {
    // RFC 4055 S3.1
    const default_salt_len = Hash.digest_length;

    return struct {
        const PssT = @This();

        pub const Signature = struct {
            bytes: []u8,

            const Self = @This();

            pub fn verifier(self: Self, public_key: PublicKey) !Verifier {
                return Verifier.init(self, public_key);
            }

            pub fn verify(self: Self, msg: []const u8, public_key: PublicKey, salt_len: ?usize) !void {
                var st = Verifier.init(self, public_key, salt_len orelse default_salt_len);
                st.update(msg);
                return st.verify();
            }

            /// Return the raw signature bytes.
            pub fn toBytes(self: Self) []u8 {
                return self.bytes;
            }

            /// Create a signature from a bytes.
            pub fn fromBytes(bytes: []u8) Self {
                return Signature{
                    .bytes = bytes,
                };
            }
        };

        pub const Signer = struct {
            h: Hash,
            secret_key: SecretKey,
            salt: ?[]const u8,

            const Self = @This();

            pub fn init(secret_key: SecretKey, salt: ?[]const u8) Signer {
                return .{
                    .h = Hash.init(.{}),
                    .secret_key = secret_key,
                    .salt = salt,
                };
            }

            pub fn update(self: *Self, data: []const u8) void {
                self.h.update(data);
            }

            pub fn finalize(self: *Self, out: []u8) !PssT.Signature {
                var hashed: [Hash.digest_length]u8 = undefined;
                self.h.final(&hashed);

                const salt = if (self.salt) |s| s else brk: {
                    var res: [default_salt_len]u8 = undefined;
                    std.crypto.random.bytes(&res);
                    break :brk &res;
                };

                const em_bits = self.secret_key.public_key.n.bits() - 1;
                const em = try PssT.emsaPSSEncode(hashed, salt, em_bits, out);

                try self.secret_key.decrypt(em, em);

                return .{ .bytes = em };
            }
        };

        pub const Verifier = struct {
            h: Hash,
            sig: []u8,
            public_key: PublicKey,
            salt_len: usize,

            const Self = @This();

            fn init(sig: PssT.Signature, public_key: PublicKey, salt_len: usize) Verifier {
                return Verifier{
                    .h = Hash.init(.{}),
                    .sig = sig.bytes,
                    .public_key = public_key,
                    .salt_len = salt_len,
                };
            }

            pub fn update(self: *Self, data: []const u8) void {
                self.h.update(data);
            }

            pub fn verify(self: *Self) !void {
                const pk = self.public_key;

                var em_buf: [max_modulus_len]u8 = undefined;
                const em_bits = pk.n.bits() - 1;
                const em_len = std.math.divCeil(usize, em_bits, 8) catch unreachable;
                const em = em_buf[0..em_len];

                const s = try Fe.fromBytes(pk.n, self.sig, .big);
                const emm = try pk.n.powPublic(s, pk.e);
                try emm.toBytes(em, .big);

                var mHash: [Hash.digest_length]u8 = undefined;
                self.h.final(&mHash);

                const mod_bits = self.public_key.n.bits();
                try PssT.emsaPSSVerify(&mHash, em, mod_bits - 1, self.salt_len);
            }
        };

        /// PSS Encrypted Message Signature Appendix
        fn emsaPSSEncode(msg_hash: [Hash.digest_length]u8, salt: []const u8, em_bits: usize, out: []u8) ![]u8 {
            // emLen = \ceil(emBits/8)
            const em_len = ((em_bits - 1) / 8) + 1;
            const s_len = salt.len;

            if (em_len < Hash.digest_length + s_len + 2) return error.ErrMsgTooLong;

            // EM = maskedDB || H || 0xbc
            var em = out[0..em_len];
            em[em.len - 1] = 0xbc;

            // M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
            // H = Hash(M')
            const hash = em[em.len - 1 - Hash.digest_length ..][0..Hash.digest_length];
            var hasher = Hash.init(.{});
            hasher.update(&([_]u8{0} ** 8));
            hasher.update(&msg_hash);
            hasher.update(salt);
            hasher.final(hash);

            // DB = PS || 0x01 || salt
            var db = em[0 .. em_len - Hash.digest_length - 1];
            @memset(db[0 .. db.len - s_len - 1], 0);
            db[db.len - s_len - 1] = 1;
            @memcpy(db[db.len - s_len ..], salt);

            var mgf_buf: [max_modulus_len]u8 = undefined;
            const mgf_len = em_len - Hash.digest_length - 1;
            const mgf_out = mgf_buf[0 .. ((mgf_len - 1) / Hash.digest_length + 1) * Hash.digest_length];
            var dbMask = mgf1(Hash, hash, mgf_out);
            dbMask = dbMask[0..mgf_len];

            var i: usize = 0;
            while (i < dbMask.len) : (i += 1) {
                db[i] = db[i] ^ dbMask[i];
            }

            // Set the leftmost 8emLen - emBits bits of the leftmost octet
            // in maskedDB to zero.
            const shift = std.math.comptimeMod(8 * em_len - em_bits, 8);
            const mask = @as(u8, 0xff) >> shift;
            db[0] &= mask;

            return em;
        }

        fn emsaPSSVerify(mHash: []const u8, em: []const u8, emBit: usize, slen: usize) !void {
            var sLen = slen;

            // 1.   If the length of M is greater than the input limitation for
            //      the hash function (2^61 - 1 octets for SHA-1), output
            //      "inconsistent" and stop.
            // All the cryptographic hash functions in the standard library have a limit of >= 2^61 - 1.
            // Even then, this check is only there for paranoia. In the context of TLS certificates, emBit cannot exceed 4096.
            if (emBit >= 1 << 61) {
                return error.InvalidSignature;
            }

            // emLen = \ceil(emBits/8)
            const emLen = ((emBit - 1) / 8) + 1;
            std.debug.assert(emLen == em.len);

            // 2.   Let mHash = Hash(M), an octet string of length hLen.
            const hlen = Hash.digest_length;
            if (hlen != mHash.len) {
                return error.InvalidSignature;
            }

            // 3.   If emLen < hLen + sLen + 2, output "inconsistent" and stop.
            if (emLen < Hash.digest_length + sLen + 2) {
                return error.InvalidSignature;
            }

            // 4.   If the rightmost octet of EM does not have hexadecimal value
            //      0xbc, output "inconsistent" and stop.
            if (em[em.len - 1] != 0xbc) {
                return error.InvalidSignature;
            }

            // 5.   Let maskedDB be the leftmost emLen - hLen - 1 octets of EM,
            //      and let H be the next hLen octets.
            const maskedDB = em[0..(emLen - Hash.digest_length - 1)];
            const h = em[(emLen - Hash.digest_length - 1)..(emLen - 1)][0..Hash.digest_length];

            // 6.   If the leftmost 8emLen - emBits bits of the leftmost octet in
            //      maskedDB are not all equal to zero, output "inconsistent" and
            //      stop.
            const zero_bits = emLen * 8 - emBit;
            var mask: u8 = maskedDB[0];
            var i: usize = 0;
            while (i < 8 - zero_bits) : (i += 1) {
                mask = mask >> 1;
            }
            if (mask != 0) {
                return error.InvalidSignature;
            }

            // 7.   Let dbMask = MGF(H, emLen - hLen - 1).
            const mgf_len = emLen - Hash.digest_length - 1;
            var mgf_out_buf: [512]u8 = undefined;
            if (mgf_len > mgf_out_buf.len) { // Modulus > 4096 bits
                return error.InvalidSignature;
            }

            const mgf_out = mgf_out_buf[0 .. ((mgf_len - 1) / Hash.digest_length + 1) * Hash.digest_length];
            var dbMask = mgf1(Hash, h, mgf_out);
            dbMask = dbMask[0..mgf_len];

            // 8.   Let DB = maskedDB \xor dbMask.
            i = 0;
            while (i < dbMask.len) : (i += 1) {
                dbMask[i] = maskedDB[i] ^ dbMask[i];
            }

            // 9.   Set the leftmost 8emLen - emBits bits of the leftmost octet
            //      in DB to zero.
            i = 0;
            mask = 0;
            while (i < 8 - zero_bits) : (i += 1) {
                mask = mask << 1;
                mask += 1;
            }
            dbMask[0] = dbMask[0] & mask;

            if (sLen == pss_salt_length_auto) {
                if (std.mem.indexOfScalar(u8, dbMask, 0x01)) |ps_len| {
                    sLen = dbMask.len - ps_len - 1;
                } else {
                    return error.ErrorVerification;
                }
            }

            // 10.  If the emLen - hLen - sLen - 2 leftmost octets of DB are not
            //      zero or if the octet at position emLen - hLen - sLen - 1 (the
            //      leftmost position is "position 1") does not have hexadecimal
            //      value 0x01, output "inconsistent" and stop.
            const ps_len = emLen - Hash.digest_length - sLen - 2;
            for (dbMask[0..ps_len]) |e| {
                if (e != 0x00) {
                    return error.InvalidSignature;
                }
            }

            if (dbMask[ps_len] != 0x01) {
                return error.InvalidSignature;
            }

            // 11.  Let salt be the last sLen octets of DB.
            const salt = dbMask[(dbMask.len - sLen)..];

            // 12.  Let
            //         M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt ;
            //      M' is an octet string of length 8 + hLen + sLen with eight
            //      initial zero octets.
            // 13.  Let H' = Hash(M'), an octet string of length hLen.
            var h_p: [Hash.digest_length]u8 = undefined;
            var hasher = Hash.init(.{});
            hasher.update(&([_]u8{0} ** 8));
            hasher.update(mHash);
            hasher.update(salt);
            hasher.final(&h_p);

            // 14.  If H = H', output "consistent".  Otherwise, output
            //      "inconsistent".
            if (!std.mem.eql(u8, h, &h_p)) {
                return error.InvalidSignature;
            }
        }
    };
}

pub fn byteLen(bits: usize) usize {
    return std.math.divCeil(usize, bits, 8) catch unreachable;
}

/// Mask generation function. Currently the only one defined.
fn mgf1(comptime Hash: type, seed: []const u8, out: []u8) []u8 {
    var c: [@sizeOf(u32)]u8 = undefined;
    var tmp: [Hash.digest_length]u8 = undefined;

    var i: usize = 0;
    var counter: u32 = 0;
    while (i < out.len) : (counter += 1) {
        var hasher = Hash.init(.{});
        hasher.update(seed);
        std.mem.writeInt(u32, &c, counter, .big);
        hasher.update(&c);

        const left = out.len - i;
        if (left >= Hash.digest_length) {
            // optimization: write straight to `out`
            hasher.final(out[i..][0..Hash.digest_length]);
            i += Hash.digest_length;
        } else {
            hasher.final(&tmp);
            @memcpy(out[i..][0..left], tmp[0..left]);
            i += left;
        }
    }

    return out;
}

test mgf1 {
    const Hash = std.crypto.hash.sha2.Sha256;
    var out: [Hash.digest_length * 2 + 1]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        &hexToBytes(
            \\ed 1b 84 6b b9 26 39 00  c8 17 82 ad 08 eb 17 01
            \\fa 8c 72 21 c6 57 63 77  31 7f 5c e8 09 89 9f
        ),
        mgf1(Hash, "asdf", out[0 .. Hash.digest_length - 1]),
    );
    try std.testing.expectEqualSlices(
        u8,
        &hexToBytes(
            \\ed 1b 84 6b b9 26 39 00  c8 17 82 ad 08 eb 17 01
            \\fa 8c 72 21 c6 57 63 77  31 7f 5c e8 09 89 9f 5a
            \\22 F2 80 D5 28 08 F4 93  83 76 00 DE 09 E4 EC 92
            \\4A 2C 7C EF 0D F7 7B BE  8F 7F 12 CB 8F 33 A6 65
            \\AB
        ),
        mgf1(Hash, "asdf", &out),
    );
}

/// For OAEP.
inline fn labelHash(comptime Hash: type, label: []const u8) [Hash.digest_length]u8 {
    if (label.len == 0) {
        // magic constants from NIST
        const sha2 = std.crypto.hash.sha2;
        switch (Hash) {
            std.crypto.hash.Sha1 => return hexToBytes(
                \\da39a3ee 5e6b4b0d 3255bfef 95601890
                \\afd80709
            ),
            sha2.Sha256 => return hexToBytes(
                \\e3b0c442 98fc1c14 9afbf4c8 996fb924
                \\27ae41e4 649b934c a495991b 7852b855
            ),
            sha2.Sha384 => return hexToBytes(
                \\38b060a7 51ac9638 4cd9327e b1b1e36a
                \\21fdb711 14be0743 4c0cc7bf 63f6e1da
                \\274edebf e76f65fb d51ad2f1 4898b95b
            ),
            sha2.Sha512 => return hexToBytes(
                \\cf83e135 7eefb8bd f1542850 d66d8007
                \\d620e405 0b5715dc 83f4a921 d36ce9ce
                \\47d0d13c 5d85f2b0 ff8318d2 877eec2f
                \\63b931bd 47417a81 a538327a f927da3e
            ),
            // just use the empty hash...
            else => {},
        }
    }
    var res: [Hash.digest_length]u8 = undefined;
    Hash.hash(label, &res, .{});
    return res;
}

const ct = if (std.options.side_channels_mitigations == .none) ct_unprotected else ct_protected;

const ct_unprotected = struct {
    fn lastIndexOfScalar(slice: []const u8, value: u8) ?usize {
        return std.mem.lastIndexOfScalar(u8, slice, value);
    }

    fn indexOfScalarPos(slice: []const u8, start_index: usize, value: u8) ?usize {
        return std.mem.indexOfScalarPos(u8, slice, start_index, value);
    }

    fn memEql(a: []const u8, b: []const u8) bool {
        return std.mem.eql(u8, a, b);
    }

    fn @"and"(a: bool, b: bool) bool {
        return a and b;
    }

    fn @"or"(a: bool, b: bool) bool {
        return a or b;
    }
};

const ct_protected = struct {
    fn lastIndexOfScalar(slice: []const u8, value: u8) ?usize {
        var res: ?usize = null;
        var i: usize = slice.len;
        while (i != 0) {
            i -= 1;
            if (@intFromBool(res == null) & @intFromBool(slice[i] == value) == 1) res = i;
        }
        return res;
    }

    fn indexOfScalarPos(slice: []const u8, start_index: usize, value: u8) ?usize {
        var res: ?usize = null;
        for (slice[start_index..], start_index..) |c, j| {
            if (c == value) res = j;
        }
        return res;
    }

    fn memEql(a: []const u8, b: []const u8) bool {
        var res: u1 = 1;
        for (a, b) |a_elem, b_elem| {
            res &= @intFromBool(a_elem == b_elem);
        }
        return res == 1;
    }

    fn @"and"(a: bool, b: bool) bool {
        return (@intFromBool(a) & @intFromBool(b)) == 1;
    }

    fn @"or"(a: bool, b: bool) bool {
        return (@intFromBool(a) | @intFromBool(b)) == 1;
    }
};

test ct {
    const c = ct_unprotected;
    try std.testing.expectEqual(true, c.@"or"(true, false));
    try std.testing.expectEqual(true, c.@"and"(true, true));
    try std.testing.expectEqual(true, c.memEql("Asdf", "Asdf"));
    try std.testing.expectEqual(false, c.memEql("asdf", "Asdf"));
    try std.testing.expectEqual(3, c.indexOfScalarPos("asdff", 1, 'f'));
    try std.testing.expectEqual(4, c.lastIndexOfScalar("asdff", 'f'));
}

fn removeNonHex(comptime hex: []const u8) []const u8 {
    var res: [hex.len]u8 = undefined;
    var i: usize = 0;
    for (hex) |c| {
        if (std.ascii.isHex(c)) {
            res[i] = c;
            i += 1;
        }
    }
    return res[0..i];
}

/// For readable copy/pasting from hex viewers.
fn hexToBytes(comptime hex: []const u8) [removeNonHex(hex).len / 2]u8 {
    const hex2 = comptime removeNonHex(hex);
    comptime var res: [hex2.len / 2]u8 = undefined;
    _ = comptime std.fmt.hexToBytes(&res, hex2) catch unreachable;
    return res;
}

test hexToBytes {
    const hex =
        \\e3b0c442 98fc1c14 9afbf4c8 996fb924
        \\27ae41e4 649b934c a495991b 7852b855
    ;
    try std.testing.expectEqual(
        [_]u8{
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
        },
        hexToBytes(hex),
    );
}

const TestHash = std.crypto.hash.sha2.Sha256;

fn testKeypair() !KeyPair {
    const keypair_bytes = @embedFile("testdata/id_rsa.der");

    const sk = try SecretKey.fromDer(keypair_bytes);
    const kp = try KeyPair.fromSecretKey(sk);

    try std.testing.expectEqual(2048, kp.public_key.n.bits());

    return kp;
}

test "rsa PKCS1-v1_5 encrypt and decrypt" {
    const kp = try testKeypair();

    const msg = "rsa PKCS1-v1_5 encrypt and decrypt";
    var out: [max_modulus_len]u8 = undefined;
    const enc = try kp.public_key.encryptPkcsv1_5(msg, &out);

    var out2: [max_modulus_len]u8 = undefined;
    const dec = try kp.secret_key.decryptPkcsv1_5(enc, &out2);

    try std.testing.expectEqualSlices(u8, msg, dec);

    try std.testing.expectEqual(256, kp.public_key.size());

    // ==========

    const check2 = "907052e0ee7f8f92990751c3432c73a3450a7dece61ba1876169875dc9b28b4aa40699c8377141ed021a92c1ab623d734e8cf1010814eb7fc26321c7b037cc467c0f2b9029c4fc082387c7dedb718dda3251b3b2a7f06871d446be2df051e2013d3726af7002a5e487559cf36ea6a11bacdfb12dc35cc9285bfed8906fac3c0c8a1a69bbdc8f834e5f1a766e13792dcc202bf48e7eb6aca78f8df4904b59d2d09b5eaaf58903217b1d0d21fb66e5e44836b422500a2c9d5e0f37232544dc32a0d1ec33e32c4b113057441097f936a6e7b4f49be6b7fb7240b0f982aee9b3fde4708fb7dfe365b9576bcd0fd0120a50658c76c2e0361b82fbf60a423b363dd354";
    var enc2: [256]u8 = undefined;
    const enc2_res = try fmt.hexToBytes(&enc2, check2);

    var out22: [max_modulus_len]u8 = undefined;
    const dec2 = try kp.secret_key.decryptPkcsv1_5(enc2_res, &out22);

    try std.testing.expectEqualSlices(u8, msg, dec2);
}

test "rsa OAEP encrypt and decrypt" {
    const kp = try testKeypair();

    const msg = "rsa OAEP encrypt and decrypt";
    const label = "";
    var out: [max_modulus_len]u8 = undefined;
    const enc = try kp.public_key.encryptOaep(TestHash, msg, label, &out);

    var out2: [max_modulus_len]u8 = undefined;
    const dec = try kp.secret_key.decryptOaep(TestHash, enc, label, &out2);

    try std.testing.expectEqualSlices(u8, msg, dec);

    // ==========

    const check2 = "76d93565b187e15d2b94b5c1ef9b715edde4c26a90e3045ada5ddad49718761ecd9dacc67ec4136d4b3ca9d236a0cd595bc6a14adde39bc4b75efbab0daa980d1525efd87ce526c66f9e225ddfdb85a2cffcf05bdd9ddff9a82f8a269339287cdac42a6a54580c6d2d7bcd07b332e304208e6f122c13f154abd56557eeb00b31a58df79ffec019dbe8681f4fe819c96fa4e030bdb63203c45ab9458d12660158bb9b0ef1a0c35a9954a73f89e59819fe7f2612d5728d863ce2d1e551a3da1fcc3e8f42c31e7da7918ff0ea9ed4b4e63e60ff066132b846ba9642d5ca9394fe99bf5bca1ce28ffcb81e54da28bced0eb85d046c7ccf150b2a3492b79abe72dd02";
    var enc2: [256]u8 = undefined;
    const enc2_res = try fmt.hexToBytes(&enc2, check2);

    var out22: [max_modulus_len]u8 = undefined;
    const dec2 = try kp.secret_key.decryptOaep(TestHash, enc2_res, label, &out22);

    try std.testing.expectEqualSlices(u8, msg, dec2);
}

test "rsa PKCS1-v1_5 signature" {
    const kp = try testKeypair();

    const msg = "rsa PKCS1-v1_5 signature";
    var out: [max_modulus_len]u8 = undefined;

    const signature = try kp.signPkcsv1_5(TestHash, msg, &out);
    try signature.verify(msg, kp.public_key);

    // ==========

    const check2 = "2ad0059bbd6d7e90c4c6e570611548e9125f6e36e94a0b331015aa960976b237f07ca880a44e52efb9d8aba96e63838f73d0aef9c18d9bf0728ece0bc94833bbfbb9cd57a9cca2133ce6eb872cb7f3747ffa89e94634ab589085f6a113c8e31a149ff6177d91d98f5e1af91ba3a4e4e9339d5bf50474f0c18483d0ee8ac1079a1dac9408e00a64907a9a43bce4273a5573c9f0d4814f0271eec465791f500b33ac1059899ee0ee643a3b9b6abe0980675dd8a3be26d61bef3f11f5ab5e9129276f6a8ddb9be958b3ea6413e38d79a5e9c025c0b488b8e4234b3d0807da36eb82d2c19f9fd95a71a4aff2f5219ba0e3b0df994c3129204d0e9c48d1e47bfb2edd";
    var sig2: [256]u8 = undefined;
    const sig2_res = try fmt.hexToBytes(&sig2, check2);

    const signature2 = PKCS1v1_5(TestHash).Signature.fromBytes(sig2_res);
    try signature2.verify(msg, kp.public_key);
}

test "rsa PKCS1-v1_5 signature fail" {
    const kp = try testKeypair();

    const msg = "rsa PKCS1-v1_5 signature";

    const check2 = "3ad0059bbd6d7e90c4c6e570611548e9125f6e36e94a0b331015aa960976b237f07ca880a44e52efb9d8aba96e63838f73d0aef9c18d9bf0728ece0bc94833bbfbb9cd57a9cca2133ce6eb872cb7f3747ffa89e94634ab589085f6a113c8e31a149ff6177d91d98f5e1af91ba3a4e4e9339d5bf50474f0c18483d0ee8ac1079a1dac9408e00a64907a9a43bce4273a5573c9f0d4814f0271eec465791f500b33ac1059899ee0ee643a3b9b6abe0980675dd8a3be26d61bef3f11f5ab5e9129276f6a8ddb9be958b3ea6413e38d79a5e9c025c0b488b8e4234b3d0807da36eb82d2c19f9fd95a71a4aff2f5219ba0e3b0df994c3129204d0e9c48d1e47bfb2edd";
    var sig2: [256]u8 = undefined;
    const sig2_res = try fmt.hexToBytes(&sig2, check2);

    const signature2 = PKCS1v1_5(TestHash).Signature.fromBytes(sig2_res);

    var need_true: bool = false;
    _ = signature2.verify(msg, kp.public_key) catch {
        need_true = true;
    };
    try testing.expectEqual(true, need_true);
}

test "rsa PSS signature" {
    const kp = try testKeypair();

    const msg = "rsa PSS signature";
    var out: [max_modulus_len]u8 = undefined;

    const salts = [_][]const u8{ "asdf", "" };
    for (salts) |salt| {
        const signature = try kp.signOaep(TestHash, msg, salt, &out);
        try signature.verify(msg, kp.public_key, salt.len);
    }

    const signature = try kp.signOaep(TestHash, msg, null, &out); // random salt
    try signature.verify(msg, kp.public_key, null);

    // ==========

    const check2 = "6ae741a696a9eb8e79139ad9f8def16b4314fcda2cbca108d70e8555f5b2cbee2adc65bb91ec334e817108914d04cdcb8dd915dabfe5f2fb591e72c26553085e9731ccffa682539230bde35b4f43284be424a2f6b5f424649e2624454c3f9d93518f7d6fde6288962a50aace7f826d85ec23de2c2c6ddb470a20a4ad21c6f39c838a28a062d4359ffa00de3170ec018118bcd5e7ec6c6f658d1373caf0d1fdf4671058c2a67cfeb8b673188d34a28d9b0741e21ed5ef2ab7863b817271441ea4373601cb1064e654f9b88b4f9b83d9754fee19bf5e1924da49caafd34aafcbde9cd8d16ec5282e8f3abab2817664f6a4ff5f18e4d77c5a7f80df9f5538fd8c53";
    var sig2: [256]u8 = undefined;
    const sig2_res = try fmt.hexToBytes(&sig2, check2);

    const signature2 = Pss(TestHash).Signature.fromBytes(sig2_res);
    try signature2.verify(msg, kp.public_key, null);
}

fn base64Decode(alloc: Allocator, input: []const u8) ![]const u8 {
    const decoder = base64.standard.Decoder;
    const decode_len = try decoder.calcSizeForSlice(input);

    const buffer = try alloc.alloc(u8, decode_len);
    _ = decoder.decode(buffer, input) catch {
        return "";
    };

    return buffer[0..];
}

test "Signer with pkcs8 key" {
    const alloc = testing.allocator;

    const prikey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDh/nCDmXaEqxN416b9XjV8acmbqA52uPzKbesWQRT/BPxEO2dKAURk5CkcSBDskvfzFR9TRjeDppjD1BPSEnuYKnP0SvmotoxcnBnHMfMBqGV8DSJyppu8k4y9C3MPq5C/rA8TJm0NNaJCL0BfAGkeyw+elgYifbRlm42VfYGsKVyIeEI9Qghk5Cf8yapMPfWNLKOhChXsyGExMBMonHZeseFH7UNwonNAFJMAaelhVqqmwBFqn6fBGKmvedRO7HIaiEFNKaMna6xJ5Bccjds4MhF7UC5PIdx4Bt7CfxvjrbIRYoBF2l30CNBblIhU992zPkHoaVhDkt1gq3OdO7LvAgMBAAECggEBALCJrWTv7ahnZ3efpqAIBuogTVBd8KaHjVmokds5jehFAbdfXClwYfgaT477MNVNXYmzN1w63sTl0DIxqiYRMCFHEHuGUg6cQ3tYqb50Y2spG9XTANTlF4UxEeDfX8ue7xz7kG8aNlf6TL084iEUVgmrAJGWikZJQjGZWPmtKC3OTeJY5Bev5qHVuMRe+XEM5aQc3ph+lXlOF0Qp0Eg8YRWprrev2faH6prMqu2JGomoac6sfM4QJhtEViF7Gw0XPthPTbF19IefuAwi9psMM/9CnQ+MTWN2i6IxoUdicsFuC+Wdlb3K5V/+uldNSr+ePEhcya+YTLK9IOcVwWKQHykCgYEA8XvuEribf+t0ZPtfxr+DC9nZHXbVoFx0/ARpSG+P/fp3Hn3rO9iYQ6OtZ9mEXTzf+dhYTaRWq6PbCOz6i0It+J8QSBdxU9OcQ4871mDe41IvSc1CCGMW4PeIYtNQEK0zrqhN7SMtKyUd7yAsYRCrIzMc7NjE2qJvFw5kh7xC3Q0CgYEA75Qjn5daNYSAOa/ILdOs5J/8oIaO27RNK/fSKm/btsMsyum8+YP/mWmm1MXBzG9WEKzZv5yEKOWCEVJYVsFQsGt9yLYW2WIKU5UxiuU0F1RImF/dphIbYOh7oGC3WfYKk2f+K7ftjc196ZkEkDuE2Xh1h75/67Mzztx1DbXj6OsCgYBcDRfFfyWXb5Og4smxo1M680H2H1RzmorlfnD7sbs733wE3Y8L8xanwf7Z9WqleA0Q2k1e22RGbWGTV3JyHzoS6d90+6qxf5qzjigLIkYUdUGdambfd5ZDD1ioA1Ej6kInM/TwjlYreiyc+LCyF36FHnjKOB9iEEU0jsH3k+YRCQKBgHMVLPuHX6zfhhyvxK/Gw4FbHKYbnNoKxRs+wvThoKAtJwIdv0n4TzppVttUV2CVhrkh3sM9MvrWLGGXtZmO6Oyl5dkZJuarQpydyRuYOCqQsQKI4lbY0c/+PQxwCQMsvi3KwXxMsM7yC+6/M0L5ZDp2s7ZOGvKktVlD6vJ4Eg+bAoGARnGGprSBW8dAb/s53r0paPh4k/bySrXdGEprLwk6g3S8+aylcmjUdjcIq4dEb4A/nv12dx1Sc4y99c62R0zi+TT6FYBIFDMz3HNVzO0Jr6SgC6CNVotL0D725CioR5U1NyTHHRLZth69HLuEZCZQlPJCbePXMRRHmOl1svzcVuo=";
    const pubkey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";

    const prikey_bytes = try base64Decode(alloc, prikey);
    const pubkey_bytes = try base64Decode(alloc, pubkey);

    defer alloc.free(prikey_bytes);
    defer alloc.free(pubkey_bytes);

    const pri_key = try SecretKey.fromPKCS8Der(prikey_bytes);
    const pub_key = try PublicKey.fromPKCS8Der(pubkey_bytes);

    const msg = "rsa PSS signature";
    var out: [max_modulus_len]u8 = undefined;

    var sig = Pss(TestHash).Signer.init(pri_key, null);
    sig.update(msg);
    const signed = try sig.finalize(&out);

    const signed_bytes = signed.toBytes();
    try testing.expectEqual(true, signed_bytes.len > 0);

    try signed.verify(msg, pub_key, null);
}

test "Signer with pkcs8 key or pkcs1 key" {
    {
        // pkcs1 der key
        const prikey = "MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAyMaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdEKdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gMIvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDnFcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvYmEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghjFuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+UI5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNTOvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL04aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0KcnckbmDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ryeBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq";
        const pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";

        try test_sign_with_key_der(prikey, pubkey);
    }

    {
        // pkcs8 der key
        const prikey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDh/nCDmXaEqxN416b9XjV8acmbqA52uPzKbesWQRT/BPxEO2dKAURk5CkcSBDskvfzFR9TRjeDppjD1BPSEnuYKnP0SvmotoxcnBnHMfMBqGV8DSJyppu8k4y9C3MPq5C/rA8TJm0NNaJCL0BfAGkeyw+elgYifbRlm42VfYGsKVyIeEI9Qghk5Cf8yapMPfWNLKOhChXsyGExMBMonHZeseFH7UNwonNAFJMAaelhVqqmwBFqn6fBGKmvedRO7HIaiEFNKaMna6xJ5Bccjds4MhF7UC5PIdx4Bt7CfxvjrbIRYoBF2l30CNBblIhU992zPkHoaVhDkt1gq3OdO7LvAgMBAAECggEBALCJrWTv7ahnZ3efpqAIBuogTVBd8KaHjVmokds5jehFAbdfXClwYfgaT477MNVNXYmzN1w63sTl0DIxqiYRMCFHEHuGUg6cQ3tYqb50Y2spG9XTANTlF4UxEeDfX8ue7xz7kG8aNlf6TL084iEUVgmrAJGWikZJQjGZWPmtKC3OTeJY5Bev5qHVuMRe+XEM5aQc3ph+lXlOF0Qp0Eg8YRWprrev2faH6prMqu2JGomoac6sfM4QJhtEViF7Gw0XPthPTbF19IefuAwi9psMM/9CnQ+MTWN2i6IxoUdicsFuC+Wdlb3K5V/+uldNSr+ePEhcya+YTLK9IOcVwWKQHykCgYEA8XvuEribf+t0ZPtfxr+DC9nZHXbVoFx0/ARpSG+P/fp3Hn3rO9iYQ6OtZ9mEXTzf+dhYTaRWq6PbCOz6i0It+J8QSBdxU9OcQ4871mDe41IvSc1CCGMW4PeIYtNQEK0zrqhN7SMtKyUd7yAsYRCrIzMc7NjE2qJvFw5kh7xC3Q0CgYEA75Qjn5daNYSAOa/ILdOs5J/8oIaO27RNK/fSKm/btsMsyum8+YP/mWmm1MXBzG9WEKzZv5yEKOWCEVJYVsFQsGt9yLYW2WIKU5UxiuU0F1RImF/dphIbYOh7oGC3WfYKk2f+K7ftjc196ZkEkDuE2Xh1h75/67Mzztx1DbXj6OsCgYBcDRfFfyWXb5Og4smxo1M680H2H1RzmorlfnD7sbs733wE3Y8L8xanwf7Z9WqleA0Q2k1e22RGbWGTV3JyHzoS6d90+6qxf5qzjigLIkYUdUGdambfd5ZDD1ioA1Ej6kInM/TwjlYreiyc+LCyF36FHnjKOB9iEEU0jsH3k+YRCQKBgHMVLPuHX6zfhhyvxK/Gw4FbHKYbnNoKxRs+wvThoKAtJwIdv0n4TzppVttUV2CVhrkh3sM9MvrWLGGXtZmO6Oyl5dkZJuarQpydyRuYOCqQsQKI4lbY0c/+PQxwCQMsvi3KwXxMsM7yC+6/M0L5ZDp2s7ZOGvKktVlD6vJ4Eg+bAoGARnGGprSBW8dAb/s53r0paPh4k/bySrXdGEprLwk6g3S8+aylcmjUdjcIq4dEb4A/nv12dx1Sc4y99c62R0zi+TT6FYBIFDMz3HNVzO0Jr6SgC6CNVotL0D725CioR5U1NyTHHRLZth69HLuEZCZQlPJCbePXMRRHmOl1svzcVuo=";
        const pubkey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";

        try test_sign_with_key_der(prikey, pubkey);
    }
}

fn test_sign_with_key_der(prikey: []const u8, pubkey: []const u8) !void {
    const alloc = testing.allocator;

    const prikey_bytes = try base64Decode(alloc, prikey);
    const pubkey_bytes = try base64Decode(alloc, pubkey);

    defer alloc.free(prikey_bytes);
    defer alloc.free(pubkey_bytes);

    const pri_key = try SecretKey.fromDerAuto(prikey_bytes);
    const pub_key = try PublicKey.fromDerAuto(pubkey_bytes);

    try std.testing.expectEqual(256, pri_key.public_key.size());
    try std.testing.expectEqual(256, pub_key.size());

    const msg = "rsa PSS signature";
    var out: [max_modulus_len]u8 = undefined;

    var sig = Pss(TestHash).Signer.init(pri_key, null);
    sig.update(msg);
    const signed = try sig.finalize(&out);

    const signed_bytes = signed.toBytes();
    try testing.expectEqual(true, signed_bytes.len > 0);

    try signed.verify(msg, pub_key, null);
}
