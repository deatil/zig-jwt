const std = @import("std");
const fmt = std.fmt;
const testing = std.testing;
const hmac = std.crypto.auth.hmac;
const Allocator = std.mem.Allocator;

pub const SigningHMD5 = SignHmac(hmac.HmacMd5, "HMD5");
pub const SigningHSHA1 = SignHmac(hmac.HmacSha1, "HSHA1");
pub const SigningHS224 = SignHmac(hmac.sha2.HmacSha224, "HS224");
pub const SigningHS256 = SignHmac(hmac.sha2.HmacSha256, "HS256");
pub const SigningHS384 = SignHmac(hmac.sha2.HmacSha384, "HS384");
pub const SigningHS512 = SignHmac(hmac.sha2.HmacSha512, "HS512");

pub fn SignHmac(comptime Hash: type, comptime name: []const u8) type {
    return struct {
        alloc: Allocator,

        const Self = @This();

        pub const mac_length = Hash.mac_length;

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
            return mac_length;
        }

        pub fn sign(self: Self, msg: []const u8, key: []const u8) ![]u8 {
            var out: [mac_length]u8 = undefined;

            var h = Hash.init(key);
            h.update(msg[0..]);
            h.final(out[0..]);

            return self.alloc.dupe(u8, out[0..]);
        }

        pub fn verify(self: Self, msg: []const u8, signature: []u8, key: []const u8) bool {
            const sign_length = self.signLength();
            if (signature.len != sign_length) {
                return false;
            }

            var out: [mac_length]u8 = undefined;

            var h = Hash.init(key);
            h.update(msg[0..]);
            h.final(out[0..]);

            if (std.mem.eql(u8, out[0..], signature[0..])) {
                return true;
            }

            return false;
        }
    };
}

test "SigningHMD5" {
    const alloc = testing.allocator;
    const h = SigningHMD5.init(alloc);

    const alg = h.alg();
    const signLength = h.signLength();
    try testing.expectEqual(16, signLength);
    try testing.expectEqualStrings("HMD5", alg);

    const msg = "test-data";
    const key = "test-key";
    const sign = "e2e8b98014f740a7c2e19152c24534b2";

    const signed = try h.sign(msg, key);
    defer alloc.free(signed);

    var signature2: [16]u8 = undefined;
    @memcpy(signature2[0..], signed);
    const singed_res = fmt.bytesToHex(signature2, .lower);

    try testing.expectEqualStrings(sign, singed_res[0..]);

    const veri = h.verify(msg, signed, key);

    try testing.expectEqual(true, veri);
}

test "SigningHSHA1" {
    const alloc = testing.allocator;
    const h = SigningHSHA1.init(alloc);

    const alg = h.alg();
    const signLength = h.signLength();
    try testing.expectEqual(20, signLength);
    try testing.expectEqualStrings("HSHA1", alg);

    const msg = "test-data";
    const key = "test-key";
    const sign = "4106aea97422ce36d01edb8deb52a7841f0234e5";

    const signed = try h.sign(msg, key);
    defer alloc.free(signed);

    var signature2: [20]u8 = undefined;
    @memcpy(signature2[0..], signed);
    const singed_res = fmt.bytesToHex(signature2, .lower);

    try testing.expectEqualStrings(sign, singed_res[0..]);

    const veri = h.verify(msg, signed, key);

    try testing.expectEqual(true, veri);
}

test "SigningHS224" {
    const alloc = testing.allocator;
    const h = SigningHS224.init(alloc);

    const alg = h.alg();
    const signLength = h.signLength();
    try testing.expectEqual(28, signLength);
    try testing.expectEqualStrings("HS224", alg);

    const msg = "test-data";
    const key = "test-key";
    const sign = "ed6ef737f62e606c28d27a7c586b23becae7196fd4c7b141b46c9902";

    const signed = try h.sign(msg, key);
    defer alloc.free(signed);

    var signature2: [28]u8 = undefined;
    @memcpy(signature2[0..], signed);
    const singed_res = fmt.bytesToHex(signature2, .lower);

    try testing.expectEqualStrings(sign, singed_res[0..]);

    const veri = h.verify(msg, signed, key);

    try testing.expectEqual(true, veri);
}

test "SigningHS256" {
    const alloc = testing.allocator;
    const h = SigningHS256.init(alloc);

    const alg = h.alg();
    const signLength = h.signLength();
    try testing.expectEqual(32, signLength);
    try testing.expectEqualStrings("HS256", alg);

    const msg = "test-data";
    const key = "test-key";
    const sign = "21a286fd6fd9f52676007c66d0f883db46d06158c266d33fb537c23bc618e567";

    const signed = try h.sign(msg, key);
    defer alloc.free(signed);

    var signature2: [32]u8 = undefined;
    @memcpy(signature2[0..], signed);
    const singed_res = fmt.bytesToHex(signature2, .lower);

    try testing.expectEqualStrings(sign, singed_res[0..]);

    const veri = h.verify(msg, signed, key);

    try testing.expectEqual(true, veri);
}

test "SigningHS384" {
    const alloc = testing.allocator;
    const h = SigningHS384.init(alloc);

    const alg = h.alg();
    const signLength = h.signLength();
    try testing.expectEqual(48, signLength);
    try testing.expectEqualStrings("HS384", alg);

    const msg = "test-data";
    const key = "test-key";
    const sign = "7ef9106e87232142b352343c291d323498d8a8426029181ddf61a65d0f1bc2c497c86a1091f66d97c2179a18d6e67bdf";

    const signed = try h.sign(msg, key);
    defer alloc.free(signed);

    var signature2: [48]u8 = undefined;
    @memcpy(signature2[0..], signed);
    const singed_res = fmt.bytesToHex(signature2, .lower);

    try testing.expectEqualStrings(sign, singed_res[0..]);

    const veri = h.verify(msg, signed, key);

    try testing.expectEqual(true, veri);
}

test "SigningHS512" {
    const alloc = testing.allocator;
    const h = SigningHS512.init(alloc);

    const alg = h.alg();
    const signLength = h.signLength();
    try testing.expectEqual(64, signLength);
    try testing.expectEqualStrings("HS512", alg);

    const msg = "test-data";
    const key = "test-key";
    const sign = "080e166f475f1c5d61f26b94d45a0cd822729a525e3a3865b87cdf58a36f039ea1948735aab3ad5027d553ad06487fb57d3a9034d2861300297d6cebf838f5bf";

    const signed = try h.sign(msg, key);
    defer alloc.free(signed);

    var signature2: [64]u8 = undefined;
    @memcpy(signature2[0..], signed);
    const singed_res = fmt.bytesToHex(signature2, .lower);

    try testing.expectEqualStrings(sign, singed_res[0..]);

    const veri = h.verify(msg, signed, key);

    try testing.expectEqual(true, veri);
}
