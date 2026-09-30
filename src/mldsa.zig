const std = @import("std");
const testing = std.testing;
const Random = std.Random;
const Allocator = std.mem.Allocator;

pub const mldsa = std.crypto.sign.mldsa;
pub const MLDSA44 = mldsa.MLDSA44;
pub const MLDSA65 = mldsa.MLDSA65;
pub const MLDSA87 = mldsa.MLDSA87;

const rsa = @import("zig-rsa");
pub const der = rsa.der;
pub const oids = rsa.oids;
pub const utils = @import("utils.zig");

pub const SigningMLDSA44 = SignMLDSA(mldsa.MLDSA44, "ML-DSA-44");
pub const SigningMLDSA65 = SignMLDSA(mldsa.MLDSA65, "ML-DSA-65");
pub const SigningMLDSA87 = SignMLDSA(mldsa.MLDSA87, "ML-DSA-87");

pub fn SignMLDSA(comptime MLDSA: type, comptime name: []const u8) type {
    return struct {
        alloc: Allocator,

        const Self = @This();

        pub const encoded_length = MLDSA.Signature.encoded_length;

        pub fn init(alloc: Allocator) Self {
            return .{
                .alloc = alloc,
            };
        }

        pub fn alg(self: Self) []const u8 {
            _ = self;
            return name;
        }

        pub fn signLength(self: Self) isize {
            _ = self;
            return encoded_length;
        }

        pub fn sign(self: Self, _: Random, msg: []const u8, key: MLDSA.SecretKey) ![]u8 {
            var secret_key = try MLDSA.KeyPair.fromSecretKey(key);

            const sig = try secret_key.sign(msg[0..], null);
            const out = sig.toBytes();

            return self.alloc.dupe(u8, out[0..]);
        }

        pub fn verify(self: Self, msg: []const u8, signature: []u8, key: MLDSA.PublicKey) !bool {
            const sign_length = self.signLength();
            if (signature.len != sign_length) {
                return false;
            }

            var signed: [encoded_length]u8 = undefined;
            @memcpy(signed[0..], signature);

            const sig = try MLDSA.Signature.fromBytes(signed);
            try sig.verify(msg, key);

            return true;
        }
    };
}

const oid_mldsa44_publickey = "2.16.840.1.101.3.4.3.17";
const oid_mldsa65_publickey = "2.16.840.1.101.3.4.3.18";
const oid_mldsa87_publickey = "2.16.840.1.101.3.4.3.19";

pub const ParseMLDSA44Der = ParseKeyDer(mldsa.MLDSA44, CheckOid(oid_mldsa44_publickey));
pub const ParseMLDSA65Der = ParseKeyDer(mldsa.MLDSA65, CheckOid(oid_mldsa65_publickey));
pub const ParseMLDSA87Der = ParseKeyDer(mldsa.MLDSA87, CheckOid(oid_mldsa87_publickey));

/// check publickey OID
pub fn CheckOid(comptime publickey_oid: []const u8) type {
    return struct {
        const Self = @This();

        /// check oid
        pub fn check(oid: []const u8) !void {
            try checkMLDSAPublickeyOid(oid, publickey_oid);
        }
    };
}

// parse key der
pub fn ParseKeyDer(comptime MLDSA: type, comptime CheckOidFn: type) type {
    return struct {
        const Self = @This();

        pub fn parsePublicKeyDer(bytes: []const u8) !MLDSA.PublicKey {
            var parser = der.Parser{ .bytes = bytes };
            _ = try parser.expectSequence();

            const oid_seq = try parser.expectSequence();
            const oid = try parser.expectOid();

            try CheckOidFn.check(oid);

            parser.seek(oid_seq.slice.end);
            const pubkey = try parser.expectBitstring();

            if (pubkey.bytes.len != MLDSA.PublicKey.encoded_length) {
                return error.JWTMLDSAPublicKeyBytesLengthError;
            }

            var pubkey_bytes: [MLDSA.PublicKey.encoded_length]u8 = undefined;
            @memcpy(pubkey_bytes[0..], pubkey.bytes);

            return MLDSA.PublicKey.fromBytes(pubkey_bytes);
        }

        pub fn parseSecretKeyDer(bytes: []const u8) !MLDSA.SecretKey {
            var parser = der.Parser{ .bytes = bytes };
            _ = try parser.expectSequence();

            const version = try parser.expectInt(u8);
            if (version != 0) {
                return error.JWTMLDSAPKCS8VersionError;
            }

            const oid_seq = try parser.expectSequence();
            const oid = try parser.expectOid();

            try CheckOidFn.check(oid);

            parser.seek(oid_seq.slice.end);

            const prikey_octet = try parser.expect(.universal, false, .octetstring);
            const parse_prikey_bytes = parser.view(prikey_octet);

            if (parse_prikey_bytes[0] != 0x80) {
                return error.JWTInvalidMLDSASecretKey;
            }

            if (parse_prikey_bytes.len != 2 + MLDSA.KeyPair.seed_length) {
                return error.JWTMLDSASecretKeyBytesLengthError;
            }

            if (parse_prikey_bytes[1] != MLDSA.KeyPair.seed_length) {
                return error.JWTInvalidMLDSASecretKeyASN1Encoding;
            }

            var seed: [MLDSA.KeyPair.seed_length]u8 = undefined;
            @memcpy(seed[0..], parse_prikey_bytes[2..]);

            const kp = try MLDSA.KeyPair.generateDeterministic(seed);

            return kp.secret_key;
        }
    };
}

fn checkMLDSAPublickeyOid(oid: []const u8, namedcurve_oid: []const u8) !void {
    var buf: [256]u8 = undefined;
    var stream: std.Io.Writer = .fixed(&buf);
    try oids.decode(oid, &stream);

    const oid_string = stream.buffered();
    if (!std.mem.eql(u8, oid_string, namedcurve_oid)) {
        return error.JWTEcdsaOIDNotSupport;
    }

    return;
}

test "SigningMLDSA44" {
    const io = testing.io;
    const alloc = testing.allocator;

    const h = SigningMLDSA44.init(alloc);

    const alg = h.alg();
    const signLength = h.signLength();
    try testing.expectEqual(2420, signLength);
    try testing.expectEqualStrings("ML-DSA-44", alg);

    const kp = mldsa.MLDSA44.KeyPair.generate(io);

    const msg = "test-data";

    const random = (Random.IoSource{
        .io = testing.io,
    }).interface();

    const signed = try h.sign(random, msg, kp.secret_key);

    defer alloc.free(signed);

    try testing.expectEqual(2420, signed.len);

    const veri = try h.verify(msg, signed, kp.public_key);

    try testing.expectEqual(true, veri);
}

test "SigningMLDSA65" {
    const io = testing.io;
    const alloc = testing.allocator;

    const h = SigningMLDSA65.init(alloc);

    const alg = h.alg();
    const signLength = h.signLength();
    try testing.expectEqual(3309, signLength);
    try testing.expectEqualStrings("ML-DSA-65", alg);

    const kp = mldsa.MLDSA65.KeyPair.generate(io);

    const msg = "test-data";

    const random = (Random.IoSource{
        .io = testing.io,
    }).interface();

    const signed = try h.sign(random, msg, kp.secret_key);

    defer alloc.free(signed);

    try testing.expectEqual(3309, signed.len);

    const veri = try h.verify(msg, signed, kp.public_key);

    try testing.expectEqual(true, veri);
}

test "SigningMLDSA87" {
    const io = testing.io;
    const alloc = testing.allocator;

    const h = SigningMLDSA87.init(alloc);

    const alg = h.alg();
    const signLength = h.signLength();
    try testing.expectEqual(4627, signLength);
    try testing.expectEqualStrings("ML-DSA-87", alg);

    const kp = mldsa.MLDSA87.KeyPair.generate(io);

    const msg = "test-data";

    const random = (Random.IoSource{
        .io = testing.io,
    }).interface();

    const signed = try h.sign(random, msg, kp.secret_key);

    defer alloc.free(signed);

    try testing.expectEqual(4627, signed.len);

    const veri = try h.verify(msg, signed, kp.public_key);

    try testing.expectEqual(true, veri);
}

test "SigningMLDSA65 with der key" {
    const alloc = testing.allocator;

    const prikey = "MDQCAQAwCwYJYIZIAWUDBAMSBCKAIBbRB15gndF8gEtIQokaAYvOTNfW9a5U3mthqjNJjkVN";
    const pubkey = "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";

    const prikey_bytes = try utils.base64Decode(alloc, prikey);
    const pubkey_bytes = try utils.base64Decode(alloc, pubkey);

    defer alloc.free(prikey_bytes);
    defer alloc.free(pubkey_bytes);

    const secret_key = try ParseMLDSA65Der.parseSecretKeyDer(prikey_bytes);
    const public_key = try ParseMLDSA65Der.parsePublicKeyDer(pubkey_bytes);

    const h = SigningMLDSA65.init(alloc);

    const alg = h.alg();
    const signLength = h.signLength();
    try testing.expectEqual(3309, signLength);
    try testing.expectEqualStrings("ML-DSA-65", alg);

    const msg = "test-data";

    const random = (Random.IoSource{
        .io = testing.io,
    }).interface();

    const signed = try h.sign(random, msg, secret_key);

    defer alloc.free(signed);

    try testing.expectEqual(3309, signed.len);

    const veri = try h.verify(msg, signed, public_key);

    try testing.expectEqual(true, veri);
}
