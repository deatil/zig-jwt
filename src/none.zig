const std = @import("std");
const fmt = std.fmt;
const testing = std.testing;

pub const SigningNone = SignNone("none");

pub fn SignNone(comptime name: []const u8) type {
    return struct {
        const Self = @This();

        pub const encoded_length = 0;

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

        pub fn sign(self: Self, msg: []const u8, key: []const u8) ![encoded_length]u8 {
            _ = self;
            _ = msg;
            _ = key;

            const out: [encoded_length]u8 = undefined;
            return out;
        }

        pub fn verify(self: Self, msg: []const u8, signature: [encoded_length]u8, key: []const u8) bool {
            _ = self;
            _ = msg;
            _ = signature;
            _ = key;

            return true;
        }
    };
}

test "SigningNone" {
    const h = SigningNone.init();

    const alg = h.alg();
    const signLength = h.signLength();
    try testing.expectEqual(0, signLength);
    try testing.expectEqualStrings("none", alg);

    const msg = "test-data";

    const signed = try h.sign(msg, "");
    const singed_res = fmt.bytesToHex(signed, .lower);

    try testing.expectEqual(0, singed_res.len);

    var signature: [0]u8 = undefined;
    _ = try fmt.hexToBytes(&signature, &singed_res);
    const veri = h.verify(msg, signature, "");

    try testing.expectEqual(true, veri);

}
