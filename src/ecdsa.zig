const std = @import("std");
const fmt = std.fmt;
const testing = std.testing;
const Allocator = std.mem.Allocator;

pub const ecdsa = std.crypto.sign.ecdsa;

pub const der = @import("rsa/der.zig");
pub const oids = @import("rsa/oid.zig");
pub const utils = @import("utils.zig");

pub const SigningES256 = SignECDSA(ecdsa.EcdsaP256Sha256, "ES256");
pub const SigningES384 = SignECDSA(ecdsa.EcdsaP384Sha384, "ES384");
// pub const SigningES512 = SignECDSA(ecdsa.EcdsaP521Sha512, "ES512");

pub const SigningES256K = SignECDSA(ecdsa.EcdsaSecp256k1Sha256, "ES256K");

pub fn SignECDSA(comptime EC: type, comptime name: []const u8) type {
    return struct {
        alloc: Allocator,

        const Self = @This();

        pub const encoded_length = EC.Signature.encoded_length;

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

        pub fn sign(self: Self, msg: []const u8, key: EC.SecretKey) ![]u8 {
            var secret_key = try EC.KeyPair.fromSecretKey(key);

            const sig = try secret_key.sign(msg[0..], null);
            const out = sig.toBytes();

            return self.alloc.dupe(u8, out[0..]);
        }

        pub fn verify(self: Self, msg: []const u8, signature: []u8, key: EC.PublicKey) bool {
            const sign_length = self.signLength();
            if (signature.len != sign_length) {
                return false;
            }

            var signed: [encoded_length]u8 = undefined;
            @memcpy(signed[0..], signature);

            const sig = EC.Signature.fromBytes(signed);
            sig.verify(msg, key) catch {
                return false;
            };

            return true;
        }
    };
}

const oid_ecdsa_publickey = "1.2.840.10045.2.1";
const oid_ecdsa_p256_namedcurve = "1.2.840.10045.3.1.7";
const oid_ecdsa_p384_namedcurve = "1.3.132.0.34";
const oid_ecdsa_p521_namedcurve = "1.3.132.0.35";
const oid_ecdsa_s256_namedcurve = "1.3.132.0.10";

pub const ParseP256Sha256Der = ParseKeyDer(ecdsa.EcdsaP256Sha256, CheckOid(oid_ecdsa_p256_namedcurve));
pub const ParseP384Sha384Der = ParseKeyDer(ecdsa.EcdsaP384Sha384, CheckOid(oid_ecdsa_p384_namedcurve));
// pub const ParseP521Sha512Der = ParseKeyDer(ecdsa.EcdsaP521Sha512, CheckOid(oid_ecdsa_p521_namedcurve));

pub const ParseSecp256k1Sha256Der = ParseKeyDer(ecdsa.EcdsaSecp256k1Sha256, CheckOid(oid_ecdsa_s256_namedcurve));

/// check namedcurve OID
pub fn CheckOid(comptime namedcurve_oid: []const u8) type {
    return struct {
        const Self = @This();

        /// check oid
        pub fn check(oid: []const u8) !void {
            try checkECDSAPublickeyNamedCurveOid(oid, namedcurve_oid);
        }
    };
}

// parse key der
pub fn ParseKeyDer(comptime EC: type, comptime CheckOidFn: type) type {
    return struct {
        const Self = @This();

        pub fn parsePublicKeyDer(bytes: []const u8) !EC.PublicKey {
            var parser = der.Parser{ .bytes = bytes };
            const seq = try parser.expectSequence();

            const oid_seq = try parser.expectSequence();
            const oid = try parser.expectOid();

            try checkECDSAPublickeyOid(oid);

            const namedcurve_oid = try parser.expectOid();

            try CheckOidFn.check(namedcurve_oid);

            parser.seek(oid_seq.slice.end);
            const pubkey = try parser.expectBitstring();

            try parser.expectEnd(seq.slice.end);
            try parser.expectEnd(bytes.len);

            return EC.PublicKey.fromSec1(pubkey.bytes);
        }

        pub fn parseSecretKeyDer(bytes: []const u8) !EC.SecretKey {
            return Self.parseECSecretKeyDer(bytes, null);
        }

        pub fn parseSecretKeyPKCS8Der(bytes: []const u8) !EC.SecretKey {
            var parser = der.Parser{ .bytes = bytes };
            _ = try parser.expectSequence();

            const version = try parser.expectInt(u8);
            if (version != 0) {
                return error.JWTEcdsaPKCS8VersionError;
            }

            const oid_seq = try parser.expectSequence();
            const oid = try parser.expectOid();

            try checkECDSAPublickeyOid(oid);

            const namedcurve_oid = try parser.expectOid();

            parser.seek(oid_seq.slice.end);
            const prikey_octet = try parser.expect(.universal, false, .octetstring);

            return Self.parseECSecretKeyDer(parser.view(prikey_octet), namedcurve_oid);
        }

        pub fn parseSecretKeyDerAuto(bytes: []const u8) !EC.SecretKey {
            const sk = Self.parseSecretKeyPKCS8Der(bytes) catch {
                return Self.parseSecretKeyDer(bytes);
            };

            return sk;
        }

        fn parseECSecretKeyDer(bytes: []const u8, oid: ?[]const u8) !EC.SecretKey {
            var parser = der.Parser{ .bytes = bytes };
            _ = try parser.expectSequence();

            const version = try parser.expectInt(u8);
            if (version != 1) {
                return error.JWTEcdsaECVersionError;
            }

            const prikey_octet = try parser.expect(.universal, false, .octetstring);
            const parse_prikey_bytes = parser.view(prikey_octet);

            var namedcurve_oid: []const u8 = "";
            if (oid) |val| {
                namedcurve_oid = val;
            } else {
                const oid_seq = try parser.expect(.context_specific, true, null);
                if (@intFromEnum(oid_seq.identifier.tag) != 0) {
                    return error.JWTEcdsaOidTagError;
                }
                namedcurve_oid = parser.expectOid() catch "";
            }

            try CheckOidFn.check(namedcurve_oid);

            var prikey: [EC.SecretKey.encoded_length]u8 = undefined;
            @memcpy(prikey[0..], parse_prikey_bytes);

            return EC.SecretKey.fromBytes(prikey);
        }
    };
}

fn checkECDSAPublickeyOid(oid: []const u8) !void {
    var buf: [256]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try oids.decode(oid, stream.writer());

    const oid_string = stream.getWritten();
    if (!std.mem.eql(u8, oid_string, oid_ecdsa_publickey)) {
        return error.JWTEcdsaOidError;
    }

    return;
}

fn checkECDSAPublickeyNamedCurveOid(oid: []const u8, namedcurve_oid: []const u8) !void {
    var buf: [256]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try oids.decode(oid, stream.writer());

    const oid_string = stream.getWritten();
    if (!std.mem.eql(u8, oid_string, namedcurve_oid)) {
        return error.JWTEcdsaNamedCurveNotSupport;
    }

    return;
}

test "SigningES256 with der key" {
    const alloc = testing.allocator;

    const prikey = "MHcCAQEEIEhYoZNv+yhRKnM2+SCgUzi9qH9dWM4MrqMQAKGOpqdpoAoGCCqGSM49AwEHoUQDQgAE9mdkEmwCjAkiIpa+MyWK7LqwZZWMv2Ft6eNXAKIFAaY11SaJBqLYIVCzewGQv/7yKkChKBDx6dvgfxR0Qm2EKw==";
    const pubkey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9mdkEmwCjAkiIpa+MyWK7LqwZZWMv2Ft6eNXAKIFAaY11SaJBqLYIVCzewGQv/7yKkChKBDx6dvgfxR0Qm2EKw==";

    const prikey_bytes = try utils.base64Decode(alloc, prikey);
    const pubkey_bytes = try utils.base64Decode(alloc, pubkey);

    defer alloc.free(prikey_bytes);
    defer alloc.free(pubkey_bytes);

    const secret_key = try ParseP256Sha256Der.parseSecretKeyDer(prikey_bytes);
    const public_key = try ParseP256Sha256Der.parsePublicKeyDer(pubkey_bytes);

    const msg = "test-data";

    const h = SigningES256.init(alloc);
    const signed = try h.sign(msg, secret_key);

    defer alloc.free(signed);

    try testing.expectEqual(64, signed.len);

    const veri = h.verify(msg, signed, public_key);

    try testing.expectEqual(true, veri);
}

test "SigningES256 with der pkcs8 key" {
    const alloc = testing.allocator;

    const prikey = "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgYwnjpvkTGLLhlf+eJ0XdvbW975d4Y0ntypkpzuvfBL2gCgYIKoZIzj0DAQehRANCAAQwgtPll6KemOFTbbsjt2IohhDKpXVQ5O14hDjHmWd7hWKBn5pFQGqF3OVz6ulEShHYDOgEm8Sd4jRglFtYyRhI";
    const pubkey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMILT5ZeinpjhU227I7diKIYQyqV1UOTteIQ4x5lne4VigZ+aRUBqhdzlc+rpREoR2AzoBJvEneI0YJRbWMkYSA==";

    const prikey_bytes = try utils.base64Decode(alloc, prikey);
    const pubkey_bytes = try utils.base64Decode(alloc, pubkey);

    defer alloc.free(prikey_bytes);
    defer alloc.free(pubkey_bytes);

    const secret_key = try ParseP256Sha256Der.parseSecretKeyPKCS8Der(prikey_bytes);
    const public_key = try ParseP256Sha256Der.parsePublicKeyDer(pubkey_bytes);

    const msg = "test-data";

    const h = SigningES256.init(alloc);
    const signed = try h.sign(msg, secret_key);

    defer alloc.free(signed);

    try testing.expectEqual(64, signed.len);

    const veri = h.verify(msg, signed, public_key);

    try testing.expectEqual(true, veri);
}

test "SigningES256 with der pkcs8 key no namedcurve" {
    const alloc = testing.allocator;

    const prikey = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg02WpZ4lQaQM/PVRB7d4owkuvsuXxrj5vDji8I9zhwNehRANCAAT8yE4hP7yvCEOtDd49SGio7MHlgWd4E6SyCD/HJ0avZVuRkXVobTz6DROHtbuv8EEVuJ/QMQRDxtLVDXAXSYOm";
    const pubkey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/MhOIT+8rwhDrQ3ePUhoqOzB5YFneBOksgg/xydGr2VbkZF1aG08+g0Th7W7r/BBFbif0DEEQ8bS1Q1wF0mDpg==";

    const prikey_bytes = try utils.base64Decode(alloc, prikey);
    const pubkey_bytes = try utils.base64Decode(alloc, pubkey);

    defer alloc.free(prikey_bytes);
    defer alloc.free(pubkey_bytes);

    const secret_key = try ParseP256Sha256Der.parseSecretKeyPKCS8Der(prikey_bytes);
    const public_key = try ParseP256Sha256Der.parsePublicKeyDer(pubkey_bytes);

    const msg = "test-data";

    const h = SigningES256.init(alloc);
    const signed = try h.sign(msg, secret_key);

    defer alloc.free(signed);

    try testing.expectEqual(64, signed.len);

    const veri = h.verify(msg, signed, public_key);

    try testing.expectEqual(true, veri);
}

test "SigningES256 with der key use parseSecretKeyDerAuto" {
    const alloc = testing.allocator;

    {
        // pkcs1 der
        const prikey = "MHcCAQEEIEhYoZNv+yhRKnM2+SCgUzi9qH9dWM4MrqMQAKGOpqdpoAoGCCqGSM49AwEHoUQDQgAE9mdkEmwCjAkiIpa+MyWK7LqwZZWMv2Ft6eNXAKIFAaY11SaJBqLYIVCzewGQv/7yKkChKBDx6dvgfxR0Qm2EKw==";
        const pubkey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9mdkEmwCjAkiIpa+MyWK7LqwZZWMv2Ft6eNXAKIFAaY11SaJBqLYIVCzewGQv/7yKkChKBDx6dvgfxR0Qm2EKw==";

        const prikey_bytes = try utils.base64Decode(alloc, prikey);
        const pubkey_bytes = try utils.base64Decode(alloc, pubkey);

        defer alloc.free(prikey_bytes);
        defer alloc.free(pubkey_bytes);

        const secret_key = try ParseP256Sha256Der.parseSecretKeyDerAuto(prikey_bytes);
        const public_key = try ParseP256Sha256Der.parsePublicKeyDer(pubkey_bytes);

        const msg = "test-data";

        const h = SigningES256.init(alloc);
        const signed = try h.sign(msg, secret_key);

        defer alloc.free(signed);

        try testing.expectEqual(64, signed.len);

        const veri = h.verify(msg, signed, public_key);

        try testing.expectEqual(true, veri);
    }

    {
        // pkcs8 der
        const prikey = "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgYwnjpvkTGLLhlf+eJ0XdvbW975d4Y0ntypkpzuvfBL2gCgYIKoZIzj0DAQehRANCAAQwgtPll6KemOFTbbsjt2IohhDKpXVQ5O14hDjHmWd7hWKBn5pFQGqF3OVz6ulEShHYDOgEm8Sd4jRglFtYyRhI";
        const pubkey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMILT5ZeinpjhU227I7diKIYQyqV1UOTteIQ4x5lne4VigZ+aRUBqhdzlc+rpREoR2AzoBJvEneI0YJRbWMkYSA==";

        const prikey_bytes = try utils.base64Decode(alloc, prikey);
        const pubkey_bytes = try utils.base64Decode(alloc, pubkey);

        defer alloc.free(prikey_bytes);
        defer alloc.free(pubkey_bytes);

        const secret_key = try ParseP256Sha256Der.parseSecretKeyDerAuto(prikey_bytes);
        const public_key = try ParseP256Sha256Der.parsePublicKeyDer(pubkey_bytes);

        const msg = "test-data";

        const h = SigningES256.init(alloc);
        const signed = try h.sign(msg, secret_key);

        defer alloc.free(signed);

        try testing.expectEqual(64, signed.len);

        const veri = h.verify(msg, signed, public_key);

        try testing.expectEqual(true, veri);
    }
}

test "SigningES384 with der key" {
    const alloc = testing.allocator;

    const prikey = "MIGkAgEBBDDqWgdCzllebram3uEH+cbKAjsu5xHwL/kZa97cfTJVdZ4j+IMj99PHZkdfxli2vo2gBwYFK4EEACKhZANiAAS5Zzmt6BAsk5mfpCqYBXK3PVy8Vgvkof3+8XLoRpq04PjnwLtdtY/M5pnMxsyWbIRbZHtB8Qkeb71EF+jg7WAtb9B013H1rvlbtVXu0uCmUE3J8hQ3EqY6ugmwqUUhi0M=";
    const pubkey = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEuWc5regQLJOZn6QqmAVytz1cvFYL5KH9/vFy6EaatOD458C7XbWPzOaZzMbMlmyEW2R7QfEJHm+9RBfo4O1gLW/QdNdx9a75W7VV7tLgplBNyfIUNxKmOroJsKlFIYtD";

    const prikey_bytes = try utils.base64Decode(alloc, prikey);
    const pubkey_bytes = try utils.base64Decode(alloc, pubkey);

    defer alloc.free(prikey_bytes);
    defer alloc.free(pubkey_bytes);

    const secret_key = try ParseP384Sha384Der.parseSecretKeyDer(prikey_bytes);
    const public_key = try ParseP384Sha384Der.parsePublicKeyDer(pubkey_bytes);

    const h = SigningES384.init(alloc);

    const alg = h.alg();
    const signLength = h.signLength();
    try testing.expectEqual(96, signLength);
    try testing.expectEqualStrings("ES384", alg);

    const msg = "test-data";

    const signed = try h.sign(msg, secret_key);

    defer alloc.free(signed);

    try testing.expectEqual(96, signed.len);

    const veri = h.verify(msg, signed, public_key);

    try testing.expectEqual(true, veri);
}

test "SigningES384 with der pkcs8 key" {
    const alloc = testing.allocator;

    const prikey = "MIG/AgEAMBAGByqGSM49AgEGBSuBBAAiBIGnMIGkAgEBBDBzeDiOINSYF7z6egMEwI8qhBIhJYnVE3ShVdjkuYXg68PlRdWHuX+CEYIvxxpKlSWgBwYFK4EEACKhZANiAATQsy+6e9r88AuK1JBLC9URXg6ErKA3s2WoHM4LorWFmZl6klPlB+9k/hhjQWqt4GpRqBZV8Zhp2KXcthY2TdNDbrtMwv/zKZ+pSsugZo13wwLIX8i1h3SHLt4BoCTapUE=";
    const pubkey = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE0LMvunva/PALitSQSwvVEV4OhKygN7NlqBzOC6K1hZmZepJT5QfvZP4YY0FqreBqUagWVfGYadil3LYWNk3TQ267TML/8ymfqUrLoGaNd8MCyF/ItYd0hy7eAaAk2qVB";

    const prikey_bytes = try utils.base64Decode(alloc, prikey);
    const pubkey_bytes = try utils.base64Decode(alloc, pubkey);

    defer alloc.free(prikey_bytes);
    defer alloc.free(pubkey_bytes);

    const secret_key = try ParseP384Sha384Der.parseSecretKeyPKCS8Der(prikey_bytes);
    const public_key = try ParseP384Sha384Der.parsePublicKeyDer(pubkey_bytes);

    const h = SigningES384.init(alloc);

    const alg = h.alg();
    const signLength = h.signLength();
    try testing.expectEqual(96, signLength);
    try testing.expectEqualStrings("ES384", alg);

    const msg = "test-data";

    const signed = try h.sign(msg, secret_key);

    defer alloc.free(signed);

    try testing.expectEqual(96, signed.len);

    const veri = h.verify(msg, signed, public_key);

    try testing.expectEqual(true, veri);
}

test "SigningES256K with der pkcs8 key" {
    const alloc = testing.allocator;

    const prikey = "MIGNAgEAMBAGByqGSM49AgEGBSuBBAAKBHYwdAIBAQQgWG7JTJJajqfBSxfzsmz44+xeJPLQtQwFl7lEEaI9I5mgBwYFK4EEAAqhRANCAAR4OeEraufi3V1WWqc6g1ossT/Y0lucIxFSxLL/P/Rq7OmaOEQtk3uFiAp7CnG9rF9U0gdvy1d+rTQOvHZw5450";
    const pubkey = "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEeDnhK2rn4t1dVlqnOoNaLLE/2NJbnCMRUsSy/z/0auzpmjhELZN7hYgKewpxvaxfVNIHb8tXfq00Drx2cOeOdA==";

    const prikey_bytes = try utils.base64Decode(alloc, prikey);
    const pubkey_bytes = try utils.base64Decode(alloc, pubkey);

    defer alloc.free(prikey_bytes);
    defer alloc.free(pubkey_bytes);

    const secret_key = try ParseSecp256k1Sha256Der.parseSecretKeyPKCS8Der(prikey_bytes);
    const public_key = try ParseSecp256k1Sha256Der.parsePublicKeyDer(pubkey_bytes);

    const msg = "test-data";

    const h = SigningES256K.init(alloc);
    const signed = try h.sign(msg, secret_key);

    defer alloc.free(signed);

    try testing.expectEqual(64, signed.len);

    const veri = h.verify(msg, signed, public_key);

    try testing.expectEqual(true, veri);
}

test "SigningES256" {
    const alloc = testing.allocator;

    const h = SigningES256.init(alloc);

    const alg = h.alg();
    const signLength = h.signLength();
    try testing.expectEqual(64, signLength);
    try testing.expectEqualStrings("ES256", alg);

    const kp = ecdsa.EcdsaP256Sha256.KeyPair.generate();

    const msg = "test-data";

    const signed = try h.sign(msg, kp.secret_key);

    defer alloc.free(signed);

    try testing.expectEqual(64, signed.len);

    const veri = h.verify(msg, signed, kp.public_key);

    try testing.expectEqual(true, veri);
}

test "SigningES384" {
    const alloc = testing.allocator;

    const h = SigningES384.init(alloc);

    const alg = h.alg();
    const signLength = h.signLength();
    try testing.expectEqual(96, signLength);
    try testing.expectEqualStrings("ES384", alg);

    const kp = ecdsa.EcdsaP384Sha384.KeyPair.generate();

    const msg = "test-data";

    const signed = try h.sign(msg, kp.secret_key);

    defer alloc.free(signed);

    try testing.expectEqual(96, signed.len);

    const veri = h.verify(msg, signed, kp.public_key);

    try testing.expectEqual(true, veri);
}

test "SigningES256K" {
    const alloc = testing.allocator;

    const h = SigningES256K.init(alloc);

    const alg = h.alg();
    const signLength = h.signLength();
    try testing.expectEqual(64, signLength);
    try testing.expectEqualStrings("ES256K", alg);

    const kp = ecdsa.EcdsaSecp256k1Sha256.KeyPair.generate();

    const msg = "test-data";

    const signed = try h.sign(msg, kp.secret_key);

    defer alloc.free(signed);

    try testing.expectEqual(64, signed.len);

    const veri = h.verify(msg, signed, kp.public_key);

    try testing.expectEqual(true, veri);
}
