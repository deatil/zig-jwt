const std = @import("std");
const fmt = std.fmt;
const testing = std.testing;
const blake2 = std.crypto.hash.blake2;
const Allocator = std.mem.Allocator;

pub const SigningBlake2b = SignBlake2b(blake2.Blake2b256, "BLAKE2B");

pub fn SignBlake2b(comptime Hash: type, comptime name: []const u8) type {
    return struct {
        alloc: Allocator, 

        const Self = @This();

        pub const digest_length = Hash.digest_length;

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
            return digest_length;
        }

        pub fn sign(self: Self, msg: []const u8, key: []const u8) ![]u8 {
            if (key.len * 8 < 256) {
                return error.JWTKeyTooShort;
            }

            var out: [digest_length]u8 = undefined;

            var h = Hash.init(.{
                .key = key,
            });
            h.update(msg[0..]);
            h.final(out[0..]);

            return self.alloc.dupe(u8, out[0..]);
        }

        pub fn verify(self: Self, msg: []const u8, signature: []u8, key: []const u8) bool {
            if (key.len * 8 < 256) {
                return false;
            }

            const sign_length = self.signLength();
            if (signature.len != sign_length) {
                return false;
            }
                        
            var out: [digest_length]u8 = undefined;

            var h = Hash.init(.{
                .key = key,
            });
            h.update(msg[0..]);
            h.final(out[0..]);

            if (std.mem.eql(u8, out[0..], signature[0..])) {
                return true;
            }

            return false;
        }
    };
}

test "SigningBlake2b" {
    const alloc = std.heap.page_allocator;
    const h = SigningBlake2b.init(alloc);

    const alg = h.alg();
    const signLength = h.signLength();
    try testing.expectEqual(32, signLength);
    try testing.expectEqualStrings("BLAKE2B", alg);

    const msg = "test-data";
    const key = "12345678901234567890as1234567890";
    const sign = "d40bb120a0915ab65e0051fca93854775bd1380a1fb012ebd5c5df361159937e";

    const signed = try h.sign(msg, key);

    var signature2: [32]u8 = undefined;
    @memcpy(signature2[0..], signed);
    const singed_res = fmt.bytesToHex(signature2, .lower);

    try testing.expectEqualStrings(sign, singed_res[0..]);

    const veri = h.verify(msg, signed, key);

    try testing.expectEqual(true, veri);

}

test "SigningBlake2b key short" {
    const alloc = std.heap.page_allocator;
    const h = SigningBlake2b.init(alloc);

    const alg = h.alg();
    const signLength = h.signLength();
    try testing.expectEqual(32, signLength);
    try testing.expectEqualStrings("BLAKE2B", alg);

    const msg = "test-data";
    const key = "test-key";

    var need_true: bool = false;
    _ = h.sign(msg, key) catch |err| {
        need_true = true;
        try testing.expectEqual(error.JWTKeyTooShort, err);
    };
    try testing.expectEqual(true, need_true);

}
