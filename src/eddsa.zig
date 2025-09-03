const std = @import("std");
const fmt = std.fmt;
const testing = std.testing;
const Allocator = std.mem.Allocator;

pub const der = @import("rsa/der.zig");
pub const oids = @import("rsa/oid.zig");
pub const utils = @import("utils.zig");

pub const Ed25519 = std.crypto.sign.Ed25519;

pub const SigningEdDSA = SignEdDSA("EdDSA");
pub const SigningED25519 = SignEdDSA("ED25519");

pub fn SignEdDSA(comptime name: []const u8) type {
    return struct {
        alloc: Allocator,

        const Self = @This();

        pub const encoded_length = Ed25519.Signature.encoded_length;

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

        pub fn sign(self: Self, msg: []const u8, key: Ed25519.SecretKey) ![]u8 {
            var secret_key = try Ed25519.KeyPair.fromSecretKey(key);

            const sig = try secret_key.sign(msg[0..], null);
            var out = sig.toBytes();

            return self.alloc.dupe(u8, out[0..]);
        }

        pub fn verify(self: Self, msg: []const u8, signature: []u8, key: Ed25519.PublicKey) bool {
            const sign_length = self.signLength();
            if (signature.len != sign_length) {
                return false;
            }

            var signed: [encoded_length]u8 = undefined;
            @memcpy(signed[0..], signature);

            const sig = Ed25519.Signature.fromBytes(signed);
            sig.verify(msg, key) catch {
                return false;
            };

            return true;
        }
    };
}

const oid_eddsa_publickey = "1.3.101.112";

pub fn parseSecretKeyDer(bytes: []const u8) !Ed25519.SecretKey {
    var parser = der.Parser{ .bytes = bytes };
    _ = try parser.expectSequence();

    const version = try parser.expectInt(u8);
    if (version != 0) {
        return error.JWTEdDSAPKCS8VersionError;
    }

    const oid_seq = try parser.expectSequence();
    const oid = try parser.expectOid();

    try checkEdDSAPublickeyOid(oid);

    parser.seek(oid_seq.slice.end);
    const prikey_octet = try parser.expect(.universal, false, .octetstring);

    var prikey_parser = der.Parser{ .bytes = parser.view(prikey_octet) };
    const prikey = try prikey_parser.expect(.universal, false, .octetstring);

    const parse_prikey_bytes = prikey_parser.view(prikey);
    if (parse_prikey_bytes.len != Ed25519.KeyPair.seed_length) {
        return error.JWTEdDSASecretKeyBytesLengthError;
    }

    var seed: [Ed25519.KeyPair.seed_length]u8 = undefined;
    @memcpy(seed[0..], parse_prikey_bytes);

    const kp = try Ed25519.KeyPair.generateDeterministic(seed);

    return kp.secret_key;
}

pub fn parsePublicKeyDer(bytes: []const u8) !Ed25519.PublicKey {
    var parser = der.Parser{ .bytes = bytes };
    _ = try parser.expectSequence();

    const oid_seq = try parser.expectSequence();
    const oid = try parser.expectOid();

    try checkEdDSAPublickeyOid(oid);

    parser.seek(oid_seq.slice.end);
    const pubkey = try parser.expectBitstring();

    if (pubkey.bytes.len != Ed25519.PublicKey.encoded_length) {
        return error.JWTEdDSAPublicKeyBytesLengthError;
    }

    var pubkey_bytes: [Ed25519.PublicKey.encoded_length]u8 = undefined;
    @memcpy(pubkey_bytes[0..], pubkey.bytes);

    return Ed25519.PublicKey.fromBytes(pubkey_bytes);
}

fn checkEdDSAPublickeyOid(oid: []const u8) !void {
    var buf: [256]u8 = undefined;
    var stream: std.Io.Writer = .fixed(&buf);
    try oids.decode(oid, &stream);

    const oid_string = stream.buffered();
    if (!std.mem.eql(u8, oid_string, oid_eddsa_publickey)) {
        return error.JWTEdDSAOidError;
    }

    return;
}

test "SigningEdDSA with der key" {
    const alloc = testing.allocator;

    const prikey = "MC4CAQAwBQYDK2VwBCIEIE7YvvGJzvKQ3uZOQ6qAPkRsK7nkpmjPOaqsZKqrFQMw";
    const pubkey = "MCowBQYDK2VwAyEAgbbl7UO5W8ZMmOm+Kw9X2y9PyblBTDcZIRaR/kDFoA0=";

    const prikey_bytes = try utils.base64Decode(alloc, prikey);
    const pubkey_bytes = try utils.base64Decode(alloc, pubkey);

    defer alloc.free(prikey_bytes);
    defer alloc.free(pubkey_bytes);

    const secret_key = try parseSecretKeyDer(prikey_bytes);
    const public_key = try parsePublicKeyDer(pubkey_bytes);

    const msg = "test-data";

    const h = SigningEdDSA.init(alloc);
    const signed = try h.sign(msg, secret_key);
    defer alloc.free(signed);

    try testing.expectEqual(64, signed.len);

    const veri = h.verify(msg, signed, public_key);

    try testing.expectEqual(true, veri);
}

test "SigningEdDSA" {
    const alloc = testing.allocator;

    const h = SigningEdDSA.init(alloc);

    const alg = h.alg();
    const signLength = h.signLength();
    try testing.expectEqual(64, signLength);
    try testing.expectEqualStrings("EdDSA", alg);

    const kp = Ed25519.KeyPair.generate();

    const msg = "test-data";

    const signed = try h.sign(msg, kp.secret_key);
    defer alloc.free(signed);

    try testing.expectEqual(64, signed.len);

    const veri = h.verify(msg, signed, kp.public_key);

    try testing.expectEqual(true, veri);
}

test "SigningED25519" {
    const alloc = testing.allocator;

    const h = SigningED25519.init(alloc);

    const alg = h.alg();
    const signLength = h.signLength();
    try testing.expectEqual(64, signLength);
    try testing.expectEqualStrings("ED25519", alg);

    const kp = Ed25519.KeyPair.generate();

    const msg = "test-data";

    const signed = try h.sign(msg, kp.secret_key);
    defer alloc.free(signed);

    try testing.expectEqual(64, signed.len);

    const veri = h.verify(msg, signed, kp.public_key);

    try testing.expectEqual(true, veri);
}
