const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;

pub const json = std.json;
pub const base64 = std.base64;

pub fn base64UrlEncode(alloc: Allocator, input: []const u8) ![]const u8 {
    const encoder = base64.url_safe_no_pad.Encoder;
    const encode_len = encoder.calcSize(input.len);

    const buffer = try alloc.alloc(u8, encode_len);
    const res = encoder.encode(buffer, input);

    return res;
}

pub fn base64UrlDecode(alloc: Allocator, input: []const u8) ![]const u8 {
    const decoder = base64.url_safe_no_pad.Decoder;
    const decode_len = try decoder.calcSizeForSlice(input);

    const buffer = try alloc.alloc(u8, decode_len);
    _ = decoder.decode(buffer, input) catch {
        return "";
    };

    return buffer[0..];
}

pub fn jsonEncode(alloc: Allocator, value: anytype) ![]const u8 {
    var out = std.ArrayList(u8).init(alloc);
    defer out.deinit();

    try json.stringify(value, .{ .emit_null_optional_fields = false }, out.writer());

    return try out.toOwnedSlice();
}

pub fn jsonDecode(alloc: Allocator, value: []const u8) !json.Value {
    const parsed = try json.parseFromSlice(json.Value, alloc, value, .{});
    return parsed.value;
}

test "base64UrlEncode" {
    const alloc = std.heap.page_allocator;

    const msg = "test-data";
    const check = "dGVzdC1kYXRh";

    const res = try base64UrlEncode(alloc, msg);
    try testing.expectEqualStrings(check, res);

    const res2 = try base64UrlDecode(alloc, check);
    try testing.expectEqualStrings(msg, res2);

}

test "jsonEncode" {
    const alloc = std.heap.page_allocator;

    const msg = .{
        .typ = "test-data",
    };
    const check = "{\"typ\":\"test-data\"}";

    const res = try jsonEncode(alloc, msg);
    try testing.expectEqualStrings(check, res);

    const res2 = try jsonDecode(alloc, check);
    try testing.expectEqualStrings(msg.typ, res2.object.get("typ").?.string);
}
