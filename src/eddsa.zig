const std = @import("std");
const fmt = std.fmt;
const testing = std.testing;

pub const Ed25519 = std.crypto.sign.Ed25519;

pub const EdDSA = SigningEdDSA("EdDSA");

pub fn SigningEdDSA(comptime name: []const u8) type {
    return struct {
        const Self = @This();

        pub const encoded_length = Ed25519.Signature.encoded_length;

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

        pub fn sign(self: Self, msg: []const u8, key: Ed25519.SecretKey) ![encoded_length]u8 {
            _ = self;
            var secret_key = try Ed25519.KeyPair.fromSecretKey(key);

            const sig = try secret_key.sign(msg[0..], null);
            const out: [encoded_length]u8 = sig.toBytes();
            
            return out;
        }

        pub fn verify(self: Self, msg: []const u8, signature: [encoded_length]u8, key: Ed25519.PublicKey) bool {
            _ = self;
            const sig = Ed25519.Signature.fromBytes(signature);
            
            sig.verify(msg, key) catch {
                return false;
            };

            return true;
        }
    };
}

test "EdDSA" {
    const h = EdDSA.init();

    const alg = h.alg();
    const signLength = h.signLength();
    try testing.expectEqual(64, signLength);
    try testing.expectEqualStrings("EdDSA", alg);

    const kp = Ed25519.KeyPair.generate();

    const msg = "test-data";

    const signed = try h.sign(msg, kp.secret_key);
    const singed_res = fmt.bytesToHex(signed, .lower);

    try testing.expectEqual(128, singed_res.len);

    var signature: [64]u8 = undefined;
    _ = try fmt.hexToBytes(&signature, &singed_res);
    const veri = h.verify(msg, signature, kp.public_key);

    try testing.expectEqual(true, veri);

}
