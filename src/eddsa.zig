const std = @import("std");
const fmt = std.fmt;
const testing = std.testing;
const Allocator = std.mem.Allocator;

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

test "SigningEdDSA" {
    const alloc = std.heap.page_allocator;

    const h = SigningEdDSA.init(alloc);

    const alg = h.alg();
    const signLength = h.signLength();
    try testing.expectEqual(64, signLength);
    try testing.expectEqualStrings("EdDSA", alg);

    const kp = Ed25519.KeyPair.generate();

    const msg = "test-data";

    const signed = try h.sign(msg, kp.secret_key);

    try testing.expectEqual(64, signed.len);

    const veri = h.verify(msg, signed, kp.public_key);

    try testing.expectEqual(true, veri);

}

test "SigningED25519" {
    const alloc = std.heap.page_allocator;

    const h = SigningED25519.init(alloc);

    const alg = h.alg();
    const signLength = h.signLength();
    try testing.expectEqual(64, signLength);
    try testing.expectEqualStrings("ED25519", alg);

    const kp = Ed25519.KeyPair.generate();

    const msg = "test-data";

    const signed = try h.sign(msg, kp.secret_key);

    try testing.expectEqual(64, signed.len);

    const veri = h.verify(msg, signed, kp.public_key);

    try testing.expectEqual(true, veri);

}
