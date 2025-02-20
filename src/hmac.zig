const std = @import("std");
const fmt = std.fmt;
const testing = std.testing;
const hmac = std.crypto.auth.hmac;

pub const SigningHS256 = SignHmac(hmac.sha2.HmacSha256, "HS256");
pub const SigningHS384 = SignHmac(hmac.sha2.HmacSha384, "HS384");
pub const SigningHS512 = SignHmac(hmac.sha2.HmacSha512, "HS512");

pub fn SignHmac(comptime Hash: type, comptime name: []const u8) type {
    return struct {
        const Self = @This();

        pub const mac_length = Hash.mac_length;

        pub fn init() Self {
            return .{};
        }

        pub fn alg(self: Self) []const u8 {
            _ = self;
            return name;
        }

        pub fn signLength(self: Self) isize {
            _ = self;
            return mac_length;
        }

        pub fn sign(self: Self, msg: []const u8, key: []const u8) ![mac_length]u8 {
            _ = self;

            var h = Hash.init(key);
            h.update(msg[0..]);

            var out: [mac_length]u8 = undefined;
            h.final(out[0..]);

            return out;
        }

        pub fn verify(self: Self, msg: []const u8, signature: [mac_length]u8, key: []const u8) bool {
            _ = self;
            
            var h = Hash.init(key);
            h.update(msg[0..]);

            var out: [mac_length]u8 = undefined;
            h.final(out[0..]);

            if (std.mem.eql(u8, out[0..], signature[0..])) {
                return true;
            }

            return false;
        }
    };
}

test "SigningHS256" {
    const h = SigningHS256.init();

    const alg = h.alg();
    const signLength = h.signLength();
    try testing.expectEqual(32, signLength);
    try testing.expectEqualStrings("HS256", alg);

    const msg = "test-data";
    const key = "test-key";
    const sign = "21a286fd6fd9f52676007c66d0f883db46d06158c266d33fb537c23bc618e567";

    const signed = try h.sign(msg, key);
    const singed_res = fmt.bytesToHex(signed, .lower);

    try testing.expectEqualStrings(sign, singed_res[0..]);

    var signature: [32]u8 = undefined;
    _ = try fmt.hexToBytes(&signature, sign);
    const veri = h.verify(msg, signature, key);

    try testing.expectEqual(true, veri);

}

test "SigningHS384" {
    const h = SigningHS384.init();

    const alg = h.alg();
    const signLength = h.signLength();
    try testing.expectEqual(48, signLength);
    try testing.expectEqualStrings("HS384", alg);

    const msg = "test-data";
    const key = "test-key";
    const sign = "7ef9106e87232142b352343c291d323498d8a8426029181ddf61a65d0f1bc2c497c86a1091f66d97c2179a18d6e67bdf";

    const signed = try h.sign(msg, key);
    const singed_res = fmt.bytesToHex(signed, .lower);

    try testing.expectEqualStrings(sign, singed_res[0..]);

    var signature: [48]u8 = undefined;
    _ = try fmt.hexToBytes(&signature, sign);
    const veri = h.verify(msg, signature, key);

    try testing.expectEqual(true, veri);

}

test "SigningHS512" {
    const h = SigningHS512.init();

    const alg = h.alg();
    const signLength = h.signLength();
    try testing.expectEqual(64, signLength);
    try testing.expectEqualStrings("HS512", alg);

    const msg = "test-data";
    const key = "test-key";
    const sign = "080e166f475f1c5d61f26b94d45a0cd822729a525e3a3865b87cdf58a36f039ea1948735aab3ad5027d553ad06487fb57d3a9034d2861300297d6cebf838f5bf";

    const signed = try h.sign(msg, key);
    const singed_res = fmt.bytesToHex(signed, .lower);

    try testing.expectEqualStrings(sign, singed_res[0..]);

    var signature: [64]u8 = undefined;
    _ = try fmt.hexToBytes(&signature, sign);
    const veri = h.verify(msg, signature, key);

    try testing.expectEqual(true, veri);

}