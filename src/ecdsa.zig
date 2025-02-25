const std = @import("std");
const fmt = std.fmt;
const testing = std.testing;
const Allocator = std.mem.Allocator;

pub const ecdsa = std.crypto.sign.ecdsa;

pub const SigningES256 = SignECDSA(ecdsa.EcdsaP256Sha256, "ES256");
pub const SigningES384 = SignECDSA(ecdsa.EcdsaP384Sha384, "ES384");
// pub const SigningES512 = SignECDSA(ecdsa.EcdsaP512Sha512, "ES512");

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
            const out: [encoded_length]u8 = sig.toBytes();

            const out_string = try self.alloc.alloc(u8, @as(usize, @intCast(self.signLength())));
            @memcpy(out_string[0..], out[0..]);

            return out_string;
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

test "SigningES256" {
    const alloc = std.heap.page_allocator;

    const h = SigningES256.init(alloc);

    const alg = h.alg();
    const signLength = h.signLength();
    try testing.expectEqual(64, signLength);
    try testing.expectEqualStrings("ES256", alg);

    const kp = ecdsa.EcdsaP256Sha256.KeyPair.generate();

    const msg = "test-data";

    const signed = try h.sign(msg, kp.secret_key);

    try testing.expectEqual(64, signed.len);

    const veri = h.verify(msg, signed, kp.public_key);

    try testing.expectEqual(true, veri);

}

test "SigningES384" {
    const alloc = std.heap.page_allocator;

    const h = SigningES384.init(alloc);

    const alg = h.alg();
    const signLength = h.signLength();
    try testing.expectEqual(96, signLength);
    try testing.expectEqualStrings("ES384", alg);

    const kp = ecdsa.EcdsaP384Sha384.KeyPair.generate();

    const msg = "test-data";

    const signed = try h.sign(msg, kp.secret_key);

    try testing.expectEqual(96, signed.len);

    const veri = h.verify(msg, signed, kp.public_key);

    try testing.expectEqual(true, veri);

}

test "SigningES256K" {
    const alloc = std.heap.page_allocator;

    const h = SigningES256K.init(alloc);

    const alg = h.alg();
    const signLength = h.signLength();
    try testing.expectEqual(64, signLength);
    try testing.expectEqualStrings("ES256K", alg);

    const kp = ecdsa.EcdsaSecp256k1Sha256.KeyPair.generate();

    const msg = "test-data";

    const signed = try h.sign(msg, kp.secret_key);

    try testing.expectEqual(64, signed.len);

    const veri = h.verify(msg, signed, kp.public_key);

    try testing.expectEqual(true, veri);

}
