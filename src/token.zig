const std = @import("std");
const json = std.json;
const time = std.time;
const testing = std.testing;
const Allocator = std.mem.Allocator;

const utils = @import("utils.zig");

pub const Token = struct {
    raw: []const u8 = "",
    msg: []const u8 = "",
    header: []const u8 = "",
    claims: []const u8 = "",
    signature: []const u8 = "",
    alloc: Allocator,

    const Self = @This();

    pub const Header = struct {
        typ: []const u8,
        alg: []const u8,
        kid: ?[]const u8 = null,

        pub fn deinit(self: *@This(), alloc: Allocator) void {
            alloc.free(self.typ);
            alloc.free(self.alg);

            if (self.kid != null) {
                alloc.free(self.kid.?);
            }
        }
    };

    pub fn init(alloc: Allocator) Self {
        return .{
            .alloc = alloc,
        };
    }

    pub fn deinit(self: *Self) void {
        self.alloc.free(self.raw);
        self.alloc.free(self.msg);
        self.alloc.free(self.header);
        self.alloc.free(self.claims);
        self.alloc.free(self.signature);
    }

    pub fn withHeader(self: *Self, header: []const u8) !void {
        self.header = try self.alloc.dupe(u8, header);
    }

    pub fn setHeader(self: *Self, header: anytype) !void {
        self.header = try utils.jsonEncode(self.alloc, header);
    }

    pub fn withClaims(self: *Self, claims: []const u8) !void {
        self.claims = try self.alloc.dupe(u8, claims);
    }

    pub fn setClaims(self: *Self, claims: anytype) !void {
        self.claims = try utils.jsonEncode(self.alloc, claims);
    }

    pub fn withSignature(self: *Self, signature: []const u8) !void {
        self.signature = try self.alloc.dupe(u8, signature);
    }

    pub fn signingString(self: *Self) ![]const u8 {
        return self.signing(false);
    }

    pub fn signedString(self: *Self) ![]const u8 {
        return self.signing(true);
    }

    fn signing(self: *Self, need_sign: bool) ![]const u8 {
        var buf = try std.ArrayList(u8).initCapacity(self.alloc, 0);
        defer buf.deinit(self.alloc);

        const header = try utils.base64UrlEncode(self.alloc, self.header);
        try buf.appendSlice(self.alloc, header[0..]);

        const claims = try utils.base64UrlEncode(self.alloc, self.claims);
        try buf.append(self.alloc, '.');
        try buf.appendSlice(self.alloc, claims[0..]);

        defer self.alloc.free(header);
        defer self.alloc.free(claims);

        if (need_sign) {
            const signature = try utils.base64UrlEncode(self.alloc, self.signature);
            try buf.append(self.alloc, '.');
            try buf.appendSlice(self.alloc, signature[0..]);

            defer self.alloc.free(signature);
        }

        return buf.toOwnedSlice(self.alloc);
    }

    pub fn parse(self: *Self, token_string: []const u8) void {
        self.raw = self.alloc.dupe(u8, token_string) catch "";
        self.header = "";
        self.claims = "";
        self.signature = "";

        if (token_string.len == 0) {
            return;
        }

        var it = std.mem.splitScalar(u8, token_string, '.');
        if (it.next()) |pair| {
            self.header = utils.base64UrlDecode(self.alloc, pair) catch "";
        }
        if (it.next()) |pair| {
            self.claims = utils.base64UrlDecode(self.alloc, pair) catch "";
        }
        if (it.next()) |pair| {
            self.signature = utils.base64UrlDecode(self.alloc, pair) catch "";
        }

        self.msg = self.getRawNoSignature() catch "";
    }

    pub fn getRaw(self: *Self) ![]const u8 {
        return self.alloc.dupe(u8, self.raw);
    }

    pub fn getMsg(self: *Self) ![]const u8 {
        return self.alloc.dupe(u8, self.msg);
    }

    pub fn getPartCount(self: *Self) usize {
        const count = std.mem.count(u8, self.raw, ".");
        return count + 1;
    }

    fn getRawNoSignature(self: *Self) ![]const u8 {
        const count = std.mem.count(u8, self.raw, ".");
        if (count <= 1) {
            return self.alloc.dupe(u8, self.raw);
        }

        var header: []const u8 = "";
        var claims: []const u8 = "";

        var it = std.mem.splitScalar(u8, self.raw, '.');
        if (it.next()) |pair| {
            header = pair;
        }
        if (it.next()) |pair| {
            claims = pair;
        }

        return std.mem.join(self.alloc, ".", &[_][]const u8{ header, claims });
    }

    pub fn getHeader(self: *Self) !Self.Header {
        const parsed_header = try utils.jsonDecode(self.alloc, self.header);
        defer parsed_header.deinit();

        const hv = parsed_header.value;

        var typ: []const u8 = "";
        if (hv.object.get("typ")) |val| {
            if (val == .string) {
                typ = try self.alloc.dupe(u8, val.string);
            }
        }

        var alg: []const u8 = "";
        if (hv.object.get("alg")) |val| {
            if (val == .string) {
                alg = try self.alloc.dupe(u8, val.string);
            }
        }

        var kid: []const u8 = "";
        if (hv.object.get("kid")) |val| {
            if (val == .string) {
                kid = try self.alloc.dupe(u8, val.string);
            }
        }

        return .{
            .typ = typ,
            .alg = alg,
            .kid = kid,
        };
    }

    pub fn getHeaders(self: *Self) !json.Parsed(json.Value) {
        return utils.jsonDecode(self.alloc, self.header);
    }

    pub fn getHeadersT(self: *Self, comptime T: type) !json.Parsed(T) {
        return utils.jsonDecodeT(T, self.alloc, self.header);
    }

    pub fn getClaims(self: *Self) !json.Parsed(json.Value) {
        return utils.jsonDecode(self.alloc, self.claims);
    }

    pub fn getClaimsT(self: *Self, comptime T: type) !json.Parsed(T) {
        return utils.jsonDecodeT(T, self.alloc, self.claims);
    }

    pub fn getSignature(self: *Self) ![]const u8 {
        return self.alloc.dupe(u8, self.signature);
    }
};

test "Token" {
    const alloc = testing.allocator;

    const header: Token.Header = .{
        .typ = "JWT",
        .alg = "ES256",
    };
    const claims = .{
        .aud = "example.com",
        .iat = "foo",
    };
    const signature = "test-signature";

    const check1 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJleGFtcGxlLmNvbSIsImlhdCI6ImZvbyJ9";
    const check2 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJleGFtcGxlLmNvbSIsImlhdCI6ImZvbyJ9.dGVzdC1zaWduYXR1cmU";

    var token = Token.init(alloc);
    try token.setHeader(header);
    try token.setClaims(claims);
    try token.withSignature(signature);

    defer token.deinit();

    const res1 = try token.signingString();
    defer alloc.free(res1);
    try testing.expectEqualStrings(check1, res1);

    const res2 = try token.signedString();
    defer alloc.free(res2);
    try testing.expectEqualStrings(check2, res2);

    // ====================

    // pub const ObjectMap = StringArrayHashMap(Value);
    // pub const Array = ArrayList(Value);
    // pub const json.Value = union(enum) {
    //     null,
    //     bool: bool,
    //     integer: i64,
    //     float: f64,
    //     number_string: []const u8,
    //     string: []const u8,
    //     array: Array,
    //     object: ObjectMap,
    // }

    var token2 = Token.init(alloc);
    token2.parse(check1);

    defer token2.deinit();

    var header2 = try token2.getHeader();
    defer header2.deinit(alloc);
    try testing.expectEqualStrings("JWT", header2.typ);
    try testing.expectEqualStrings("ES256", header2.alg);

    const claims2 = try token2.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.iat, claims2.value.object.get("iat").?.string);

    const signature2 = try token2.getSignature();
    defer alloc.free(signature2);
    try testing.expectEqual(0, signature2.len);

    const partCount = token2.getPartCount();
    try testing.expectEqual(2, partCount);

    // ====================

    var token3 = Token.init(alloc);
    token3.parse(check2);

    defer token3.deinit();

    var header3 = try token3.getHeader();
    defer header3.deinit(alloc);
    try testing.expectEqualStrings("JWT", header3.typ);
    try testing.expectEqualStrings("ES256", header3.alg);

    const claims3 = try token3.getClaims();
    defer claims3.deinit();
    try testing.expectEqualStrings(claims.aud, claims3.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.iat, claims3.value.object.get("iat").?.string);

    const signature3 = try token3.getSignature();
    defer alloc.free(signature3);
    try testing.expectEqualStrings(signature, signature3);

    const token51 = try token3.getRaw();
    defer alloc.free(token51);
    try testing.expectEqualStrings(check2, token51);

    const token5 = try token3.getMsg();
    defer alloc.free(token5);
    try testing.expectEqualStrings(check1, token5);

    const partCount2 = token3.getPartCount();
    try testing.expectEqual(3, partCount2);

    // ====================

    const check3 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9";

    var token6 = Token.init(alloc);
    token6.parse(check3);

    defer token6.deinit();

    const sig61 = try token6.getRaw();
    defer alloc.free(sig61);
    try testing.expectEqualStrings(check3, sig61);

    const sig6 = try token6.getMsg();
    defer alloc.free(sig6);
    try testing.expectEqualStrings(check3, sig6);

    const partCount6 = token6.getPartCount();
    try testing.expectEqual(1, partCount6);
}

test "Token 2" {
    const alloc = testing.allocator;

    const header: Token.Header = .{
        .typ = "JWE",
        .alg = "ES256",
    };
    const claims = .{
        .aud = "example.com",
        .iat = "foo",
    };
    const signature = "test-signature";

    const check1 = "eyJ0eXAiOiJKV0UiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJleGFtcGxlLmNvbSIsImlhdCI6ImZvbyJ9.dGVzdC1zaWduYXR1cmU";

    var token = Token.init(alloc);
    try token.setHeader(header);
    try token.setClaims(claims);
    try token.withSignature(signature);

    defer token.deinit();

    const res1 = try token.signedString();
    defer alloc.free(res1);
    try testing.expectEqualStrings(check1, res1);

    // ======

    var token2 = Token.init(alloc);
    try token2.withHeader("ase123");
    try token2.withClaims("tyh78");
    try token2.withSignature("qwe");

    defer token2.deinit();

    try testing.expectEqualStrings("ase123", token2.header);
    try testing.expectEqualStrings("tyh78", token2.claims);
    try testing.expectEqualStrings("qwe", token2.signature);
}

test "Token 3" {
    const alloc = testing.allocator;

    const header: Token.Header = .{
        .typ = "JWE",
        .alg = "ES256",
        .kid = "kids",
    };
    const claims = .{
        .aud = "example.com",
        .iat = "foo",
    };
    const signature = "test-signature";

    const check1 = "eyJ0eXAiOiJKV0UiLCJhbGciOiJFUzI1NiIsImtpZCI6ImtpZHMifQ.eyJhdWQiOiJleGFtcGxlLmNvbSIsImlhdCI6ImZvbyJ9.dGVzdC1zaWduYXR1cmU";

    var token = Token.init(alloc);
    try token.setHeader(header);
    try token.setClaims(claims);
    try token.withSignature(signature);

    defer token.deinit();

    const res1 = try token.signedString();
    defer alloc.free(res1);
    try testing.expectEqualStrings(check1, res1);

    // ================

    var token2 = Token.init(alloc);
    token2.parse(check1);

    defer token2.deinit();

    var header2 = try token2.getHeader();
    defer header2.deinit(alloc);
    try testing.expectEqualStrings(header.kid.?, header2.kid.?);

    // ================

    const claimsT = struct {
        aud: []const u8,
        iat: []const u8,
    };
    const claims3 = try token2.getClaimsT(claimsT);
    defer claims3.deinit();
    try testing.expectEqualStrings(claims.aud, claims3.value.aud);
    try testing.expectEqualStrings(claims.iat, claims3.value.iat);

    const headerT = struct {
        typ: []const u8,
        alg: []const u8,
        kid: []const u8,
    };
    const header3 = try token2.getHeadersT(headerT);
    defer header3.deinit();
    try testing.expectEqualStrings(header.typ, header3.value.typ);
    try testing.expectEqualStrings(header.alg, header3.value.alg);
    try testing.expectEqualStrings(header.kid.?, header3.value.kid);

    const header33 = try token2.getHeaders();
    defer header33.deinit();
    try testing.expectEqualStrings(header.typ, header33.value.object.get("typ").?.string);
    try testing.expectEqualStrings(header.alg, header33.value.object.get("alg").?.string);
    try testing.expectEqualStrings(header.kid.?, header33.value.object.get("kid").?.string);
}
