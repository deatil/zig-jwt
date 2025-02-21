const std = @import("std");
const fmt = std.fmt;
const testing = std.testing;
const Allocator = std.mem.Allocator;

pub const SigningNone = SignNone("none");

pub fn SignNone(comptime name: []const u8) type {
    return struct {
        alloc: Allocator, 

        const Self = @This();

        pub const encoded_length = 0;

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

        pub fn sign(self: Self, msg: []const u8, key: []const u8) ![]u8 {
            _ = self;
            _ = msg;
            _ = key;

            const out: []u8 = undefined;
            return out;
        }

        pub fn verify(self: Self, msg: []const u8, signature: []u8, key: []const u8) bool {
            _ = self;
            _ = msg;
            _ = key;

            if (signature.len > 0) {
                return false;
            }

            return true;
        }
    };
}

test "SigningNone" {
    const alloc = std.heap.page_allocator;
    const h = SigningNone.init(alloc);

    const alg = h.alg();
    const signLength = h.signLength();
    try testing.expectEqual(0, signLength);
    try testing.expectEqualStrings("none", alg);

    const msg = "test-data";

    const signed = try h.sign(msg, "");
    try testing.expectEqual(0, signed.len);

    const veri = h.verify(msg, signed, "");
    try testing.expectEqual(true, veri);

    var buf2: [5]u8 = "hello".*;
    const signed2: []u8 = &buf2;
    const veri2 = h.verify(msg, signed2[0..], "");
    try testing.expectEqual(false, veri2);

}
