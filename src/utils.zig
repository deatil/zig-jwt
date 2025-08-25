const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;

pub const fmt = std.fmt;
pub const json = std.json;
pub const base64 = std.base64;

pub const JsonParsedValue = json.Parsed(json.Value);

pub fn base64Decode(alloc: Allocator, input: []const u8) ![]const u8 {
    const decoder = base64.standard.Decoder;
    const decode_len = try decoder.calcSizeForSlice(input);

    const buffer = try alloc.alloc(u8, decode_len);
    _ = decoder.decode(buffer, input) catch {
        defer alloc.free(buffer);

        return "";
    };

    return buffer[0..];
}

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
        defer alloc.free(buffer);

        return "";
    };

    return buffer[0..];
}

pub fn jsonEncode(alloc: Allocator, value: anytype) ![]const u8 {
    const out = try json.Stringify.valueAlloc(alloc, value, .{ .emit_null_optional_fields = false });

    return out;
}

pub fn jsonDecode(alloc: Allocator, value: []const u8) !json.Parsed(json.Value) {
    return json.parseFromSlice(json.Value, alloc, value, .{});
}

pub fn jsonDecodeT(comptime T: type, alloc: Allocator, value: []const u8) !json.Parsed(T) {
    return json.parseFromSlice(T, alloc, value, .{});
}

pub fn eq(rest: []const u8, needle: []const u8) bool {
    return std.mem.eql(u8, rest, needle);
}

pub fn constTimeEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) {
        return false;
    }

    return constantTimeCompare(a, b) == 1;
}

pub inline fn constantTimeCompare(a: []const u8, b: []const u8) usize {
    if (a.len != b.len) {
        return 0;
    }

    var v: u8 = 0;
    var i: usize = 0;

    while (i < a.len) : (i += 1) {
        v |= a[i] ^ b[i];
    }

    return constantTimeByteEq(v, 0);
}

pub inline fn constantTimeByteEq(x: u8, y: u8) u8 {
    const xor = x ^ y;
    return @intFromBool(xor == 0);
}

test "constTimeEqual" {
    try testing.expectEqual(0, constantTimeByteEq(2, 3));
    try testing.expectEqual(1, constantTimeByteEq(3, 3));

    try testing.expectEqual(0, constantTimeCompare("asdf", "0asdf"));
    try testing.expectEqual(1, constantTimeCompare("asdf", "asdf"));

    try testing.expectEqual(false, constTimeEqual("asdf", "0asdf"));
    try testing.expectEqual(false, constTimeEqual("asdf", "bsdf"));
    try testing.expectEqual(true, constTimeEqual("bsdf", "bsdf"));
}

test "base64UrlEncode" {
    const alloc = testing.allocator;

    const msg = "test-data";
    const check = "dGVzdC1kYXRh";

    const res = try base64UrlEncode(alloc, msg);
    defer alloc.free(res);
    try testing.expectEqualStrings(check, res);

    const res2 = try base64UrlDecode(alloc, check);
    defer alloc.free(res2);
    try testing.expectEqualStrings(msg, res2);

    const res3 = try base64Decode(alloc, check);
    defer alloc.free(res3);
    try testing.expectEqualStrings(msg, res3);
}

test "jsonEncode" {
    const alloc = testing.allocator;

    const msg = .{
        .typ = "test-data",
    };
    const check = "{\"typ\":\"test-data\"}";

    const res = try jsonEncode(alloc, msg);
    defer alloc.free(res);
    try testing.expectEqualStrings(check, res);

    const res2 = try jsonDecode(alloc, check);
    defer res2.deinit();
    try testing.expectEqualStrings(msg.typ, res2.value.object.get("typ").?.string);

    const msg3 = struct {
        typ: []const u8,
    };

    const res3 = try jsonDecodeT(msg3, alloc, check);
    defer res3.deinit();
    try testing.expectEqualStrings(msg.typ, res3.value.typ);
}
