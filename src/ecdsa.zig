const std = @import("std");
const fmt = std.fmt;
const testing = std.testing;

pub const ecdsa = std.crypto.sign.ecdsa;

pub const SigningES256 = SignECDSA(ecdsa.EcdsaP256Sha256, "ES256");
pub const SigningES384 = SignECDSA(ecdsa.EcdsaP384Sha384, "ES384");
// pub const SigningES512 = SignECDSA(ecdsa.EcdsaP512Sha512, "ES512");

pub fn SignECDSA(comptime EC: type, comptime name: []const u8) type {
    return struct {
        const Self = @This();

        pub const encoded_length = EC.Signature.encoded_length;

        pub fn init() Self {
            return .{};
        }

        pub fn alg(self: Self) []const u8 {
            _ = self;
            return name;
        }

        pub fn signLength(self: Self) isize {
            _ = self;
            return encoded_length;
        }

        pub fn sign(self: Self, msg: []const u8, key: EC.SecretKey) ![encoded_length]u8 {
            _ = self;

            var secret_key = try EC.KeyPair.fromSecretKey(key);

            const sig = try secret_key.sign(msg[0..], null);
            const out: [encoded_length]u8 = sig.toBytes();
            
            return out;
        }

        pub fn verify(self: Self, msg: []const u8, signature: [encoded_length]u8, key: EC.PublicKey) bool {
            _ = self;

            const sig = EC.Signature.fromBytes(signature);
            
            sig.verify(msg, key) catch {
                return false;
            };

            return true;
        }
    };
}

test "SigningES256" {
    const h = SigningES256.init();

    const alg = h.alg();
    const signLength = h.signLength();
    try testing.expectEqual(64, signLength);
    try testing.expectEqualStrings("ES256", alg);

    const kp = ecdsa.EcdsaP256Sha256.KeyPair.generate();

    const msg = "test-data";

    const signed = try h.sign(msg, kp.secret_key);
    const singed_res = fmt.bytesToHex(signed, .lower);

    try testing.expectEqual(128, singed_res.len);

    var signature: [64]u8 = undefined;
    _ = try fmt.hexToBytes(&signature, &singed_res);
    const veri = h.verify(msg, signature, kp.public_key);

    try testing.expectEqual(true, veri);

}

test "SigningES384" {
    const h = SigningES384.init();

    const alg = h.alg();
    const signLength = h.signLength();
    try testing.expectEqual(96, signLength);
    try testing.expectEqualStrings("ES384", alg);

    const kp = ecdsa.EcdsaP384Sha384.KeyPair.generate();

    const msg = "test-data";

    const signed = try h.sign(msg, kp.secret_key);
    const singed_res = fmt.bytesToHex(signed, .lower);

    try testing.expectEqual(192, singed_res.len);

    var signature: [96]u8 = undefined;
    _ = try fmt.hexToBytes(&signature, &singed_res);
    const veri = h.verify(msg, signature, kp.public_key);

    try testing.expectEqual(true, veri);

}