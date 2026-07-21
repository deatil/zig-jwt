const std = @import("std");
const json = std.json;
const time = std.time;
const testing = std.testing;
const Allocator = std.mem.Allocator;

const StringArray = std.array_list.Managed([]const u8);

const utils = @import("utils.zig");

pub const Token = struct {
    raw: []const u8 = "",
    msg: []const u8 = "",
    header: []const u8 = "",
    claims: []const u8 = "",
    signature: []const u8 = "",
    alloc: Allocator,

    const Self = @This();

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
        self.alloc.free(self.header);
        self.header = try self.alloc.dupe(u8, header);
    }

    pub fn setHeader(self: *Self, header: anytype) !void {
        self.alloc.free(self.header);
        self.header = try utils.jsonEncode(self.alloc, header);
    }

    pub fn withClaims(self: *Self, claims: []const u8) !void {
        self.alloc.free(self.claims);
        self.claims = try self.alloc.dupe(u8, claims);
    }

    pub fn setClaims(self: *Self, claims: anytype) !void {
        self.alloc.free(self.claims);
        self.claims = try utils.jsonEncode(self.alloc, claims);
    }

    pub fn withSignature(self: *Self, signature: []const u8) !void {
        self.alloc.free(self.signature);
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
        self.deinit();

        self.raw = self.alloc.dupe(u8, token_string) catch "";

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

    pub fn getHeader(self: *Self) !HeadersData {
        return HeadersData.init(self);
    }

    pub fn getHeaders(self: *Self) !json.Parsed(json.Value) {
        return utils.jsonDecode(self.alloc, self.header);
    }

    pub fn getHeadersT(self: *Self, comptime T: type) !json.Parsed(T) {
        return utils.jsonDecodeT(T, self.alloc, self.header);
    }

    pub fn getHeaderRaw(self: *Self) ![]const u8 {
        return self.alloc.dupe(u8, self.header);
    }

    pub fn getClaim(self: *Self) !ClaimsData {
        return ClaimsData.init(self.alloc, self);
    }

    pub fn getClaims(self: *Self) !json.Parsed(json.Value) {
        return utils.jsonDecode(self.alloc, self.claims);
    }

    pub fn getClaimsT(self: *Self, comptime T: type) !json.Parsed(T) {
        return utils.jsonDecodeT(T, self.alloc, self.claims);
    }

    pub fn getClaimsRaw(self: *Self) ![]const u8 {
        return self.alloc.dupe(u8, self.claims);
    }

    pub fn getSignature(self: *Self) ![]const u8 {
        return self.alloc.dupe(u8, self.signature);
    }
};

pub const HeadersData = struct {
    headers: json.Parsed(json.Value),

    const Self = @This();

    pub fn init(token: *Token) !Self {
        const headers = try token.getHeaders();

        return .{
            .headers = headers,
        };
    }

    pub fn deinit(self: *Self) void {
        self.headers.deinit();
    }

    pub fn getType(self: *Self) ?[]const u8 {
        return self.getString("typ");
    }

    pub fn getAlgorithm(self: *Self) ?[]const u8 {
        return self.getString("alg");
    }

    pub fn getKeyID(self: *Self) ?[]const u8 {
        return self.getString("kid");
    }

    pub fn getContentType(self: *Self) ?[]const u8 {
        return self.getString("cty");
    }

    pub fn getString(self: *Self, name: []const u8) ?[]const u8 {
        const headers = self.headers;

        if (headers.value.object.get(name)) |val| {
            if (val == .string) {
                return val.string;
            }
        }

        return null;
    }
};

pub const ClaimsData = struct {
    claims: json.Parsed(json.Value),
    alloc: Allocator,

    const Self = @This();

    pub fn init(alloc: Allocator, token: *Token) !Self {
        const claims = try token.getClaims();

        return .{
            .claims = claims,
            .alloc = alloc,
        };
    }

    pub fn deinit(self: *Self) void {
        self.claims.deinit();
    }

    pub fn getExpirationTime(self: *Self) ?i64 {
        return self.getInteger("exp");
    }

    pub fn getNotBefore(self: *Self) ?i64 {
        return self.getInteger("nbf");
    }

    pub fn getIssuedAt(self: *Self) ?i64 {
        return self.getInteger("iat");
    }

    pub fn getAudience(self: *Self) ?[]const []const u8 {
        return self.getStrings("aud");
    }

    pub fn getIssuer(self: *Self) ?[]const u8 {
        return self.getString("iss");
    }

    pub fn getSubject(self: *Self) ?[]const u8 {
        return self.getString("sub");
    }

    pub fn getID(self: *Self) ?[]const u8 {
        return self.getString("jti");
    }

    pub fn getBool(self: *Self, name: []const u8) ?bool {
        const claims = self.claims;

        if (claims.value.object.get(name)) |val| {
            if (val == .bool) {
                return val.bool;
            }
        }

        return null;
    }

    pub fn getInteger(self: *Self, name: []const u8) ?i64 {
        const claims = self.claims;

        if (claims.value.object.get(name)) |val| {
            if (val == .integer) {
                return val.integer;
            }
        }

        return null;
    }

    pub fn getFloat(self: *Self, name: []const u8) ?f64 {
        const claims = self.claims;

        if (claims.value.object.get(name)) |val| {
            if (val == .float) {
                return val.float;
            }
        }

        return null;
    }

    pub fn getNumberString(self: *Self, name: []const u8) ?[]const u8 {
        const claims = self.claims;

        if (claims.value.object.get(name)) |val| {
            if (val == .number_string) {
                return val.number_string;
            }
        }

        return null;
    }

    pub fn getString(self: *Self, name: []const u8) ?[]const u8 {
        const claims = self.claims;

        if (claims.value.object.get(name)) |val| {
            if (val == .string) {
                return val.string;
            }
        }

        return null;
    }

    pub fn getArray(self: *Self, name: []const u8) ?json.Array {
        const claims = self.claims;

        if (claims.value.object.get(name)) |val| {
            if (val == .array) {
                return val.array;
            }
        }

        return null;
    }

    pub fn getObject(self: *Self, name: []const u8) ?json.ObjectMap {
        const claims = self.claims;

        if (claims.value.object.get(name)) |val| {
            if (val == .object) {
                return val.object;
            }
        }

        return null;
    }

    pub fn getStrings(self: *Self, name: []const u8) ?[]const []const u8 {
        const aud = self.getMustStrings(name) catch &.{};
        if (aud.len > 0) {
            return aud;
        }

        return null;
    }

    pub fn getMustStrings(self: *Self, name: []const u8) ![]const []const u8 {
        const claims = self.claims;

        var arr = StringArray.init(self.alloc);
        defer arr.deinit();

        if (claims.value.object.get(name)) |val| {
            if (val == .string) {
                try arr.append(val.string);
            } else if (val == .array) {
                for (val.array.items) |vv| {
                    if (vv == .string) {
                        try arr.append(vv.string);
                    }
                }
            }
        }

        return arr.toOwnedSlice();
    }
};

test "Token" {
    const alloc = testing.allocator;

    const header = .{
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
    defer header2.deinit();
    try testing.expectEqualStrings("JWT", header2.getType().?);
    try testing.expectEqualStrings("ES256", header2.getAlgorithm().?);

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
    defer header3.deinit();
    try testing.expectEqualStrings("JWT", header3.getType().?);
    try testing.expectEqualStrings("ES256", header3.getAlgorithm().?);

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

    const header = .{
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

    const header = .{
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
    defer header2.deinit();
    try testing.expectEqualStrings(header.kid, header2.getKeyID().?);

    // ================

    const headerRaw = try token2.getHeaderRaw();
    defer alloc.free(headerRaw);
    const headerRawCheck =
        \\{"typ":"JWE","alg":"ES256","kid":"kids"}
    ;
    try testing.expectEqualStrings(headerRawCheck, headerRaw);

    const claimsRaw = try token2.getClaimsRaw();
    defer alloc.free(claimsRaw);
    const claimsRawCheck =
        \\{"aud":"example.com","iat":"foo"}
    ;
    try testing.expectEqualStrings(claimsRawCheck, claimsRaw);

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
    try testing.expectEqualStrings(header.kid, header3.value.kid);

    const header33 = try token2.getHeaders();
    defer header33.deinit();
    try testing.expectEqualStrings(header.typ, header33.value.object.get("typ").?.string);
    try testing.expectEqualStrings(header.alg, header33.value.object.get("alg").?.string);
    try testing.expectEqualStrings(header.kid, header33.value.object.get("kid").?.string);
}

test "Token with check" {
    const alloc = testing.allocator;

    const header = .{
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

    try token.withHeader("{a:b}");
    try token.withClaims("{c:d}");
    try token.withSignature("aabbbcc");

    try testing.expectEqualStrings("{a:b}", token.header);
    try testing.expectEqualStrings("{c:d}", token.claims);
    try testing.expectEqualStrings("aabbbcc", token.signature);

    try token.withHeader("");
    try token.withClaims("");
    try token.withSignature("");

    try testing.expectEqualStrings("", token.header);
    try testing.expectEqualStrings("", token.claims);
    try testing.expectEqualStrings("", token.signature);

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
    try testing.expectEqualStrings(header.kid, header3.value.kid);
}

test "Token ClaimsData" {
    const alloc = testing.allocator;

    const check1 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0Iiwic3ViIjoiU3ViamVjdCIsImF1ZCI6WyJhdWQxIiwiYXVkMiJdLCJleHAiOjE1MTYyMzkwMjIsIm5iZiI6MTUxNjIwOTAyMiwiaWF0IjoxNTE2MjA5MDEyLCJqdGkiOiJJRCIsImJvIjp0cnVlLCJmbCI6MTIuMzQ1Nn0.Ik_fqgeKtMp41Utw8QisQ00nk8FbsHEHQGKlhB2C7lc";

    var token = Token.init(alloc);
    token.parse(check1);

    defer token.deinit();

    var data = try ClaimsData.init(alloc, &token);
    defer data.deinit();

    try testing.expectFmt("1516239022", "{d}", .{data.getExpirationTime().?});
    try testing.expectFmt("1516209022", "{d}", .{data.getNotBefore().?});
    try testing.expectFmt("1516209012", "{d}", .{data.getIssuedAt().?});

    const auds = data.getAudience().?;
    defer alloc.free(auds);

    try testing.expectEqual(2, auds.len);
    try testing.expectFmt("aud1", "{s}", .{auds[0]});
    try testing.expectFmt("aud2", "{s}", .{auds[1]});

    try testing.expectFmt("test", "{s}", .{data.getIssuer().?});
    try testing.expectFmt("Subject", "{s}", .{data.getSubject().?});
    try testing.expectFmt("ID", "{s}", .{data.getID().?});

    try testing.expectEqual(true, data.getBool("bo").?);
    try testing.expectFmt("12.3456", "{}", .{data.getFloat("fl").?});
}

test "Token ClaimsData fail" {
    const alloc = testing.allocator;

    const check1 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0Iiwic3ViIjoiU3ViamVjdCIsImF1ZCI6ImF1ZDEiLCJleHAiOjE1MTYyMzkwMjIsIm5iZiI6MTUxNjIwOTAyMiwiaWF0IjoxNTE2MjA5MDEyLCJqdGkiOiJJRCIsIm5zIjoxMTExMTExMTkyMjMzNzIwMzY4NTQ3NzYwMDAsIm9iIjp7Im9iZCI6Im9iZC1kYXRhIn0sImFyciI6WyJhcnItZGF0YSJdfQ.Q4TGaqj3xwpwMNpBU4bFHFFcbSyfMkVNn1QtFGIAaZE";

    var token = Token.init(alloc);
    token.parse(check1);

    defer token.deinit();

    var data = try ClaimsData.init(alloc, &token);
    defer data.deinit();

    const auds = data.getAudience().?;
    defer alloc.free(auds);

    try testing.expectEqual(1, auds.len);
    try testing.expectFmt("aud1", "{s}", .{auds[0]});

    const subs = data.getMustStrings("sub0") catch &.{};
    defer alloc.free(subs);

    try testing.expectEqual(0, subs.len);

    try testing.expectEqual(.{null}, .{data.getObject("iss")});
    try testing.expectEqual(.{null}, .{data.getArray("iss")});
    try testing.expectEqual(.{null}, .{data.getString("ita")});
    try testing.expectEqual(.{null}, .{data.getStrings("sub0")});
    try testing.expectEqual(.{null}, .{data.getNumberString("ita")});
    try testing.expectEqual(.{null}, .{data.getFloat("ita")});
    try testing.expectEqual(.{null}, .{data.getInteger("ita")});
    try testing.expectEqual(.{null}, .{data.getBool("ita")});

    try testing.expectEqual(.{null}, .{data.getObject("sub")});
    try testing.expectEqual(.{null}, .{data.getArray("sub")});
    try testing.expectEqual(.{null}, .{data.getString("iat")});
    try testing.expectEqual(.{null}, .{data.getStrings("iat")});
    try testing.expectEqual(.{null}, .{data.getNumberString("sub")});
    try testing.expectEqual(.{null}, .{data.getFloat("sub")});
    try testing.expectEqual(.{null}, .{data.getInteger("sub")});
    try testing.expectEqual(.{null}, .{data.getBool("sub")});

    const ob = data.getObject("ob").?;
    try testing.expectFmt("obd-data", "{s}", .{ob.get("obd").?.string});

    const arr = data.getArray("arr").?;
    try testing.expectFmt("arr-data", "{s}", .{arr.items[0].string});

    try testing.expectFmt("111111119223372036854776000", "{s}", .{data.getNumberString("ns").?});
    try testing.expectFmt("aud1", "{s}", .{data.getString("aud").?});
}

test "Token HeadersData" {
    const alloc = testing.allocator;

    const header = .{
        .typ = "JWE",
        .alg = "ES256",
        .kid = "kids",
        .cty = "ctysss",
        .str = "str22",
        .nstr = 123456,
    };
    const claims = .{
        .aud = "example.com",
        .iat = "foo",
    };
    const signature = "test-signature";

    var token = Token.init(alloc);
    try token.setHeader(header);
    try token.setClaims(claims);
    try token.withSignature(signature);

    defer token.deinit();

    const res = try token.signedString();
    defer alloc.free(res);

    var token2 = Token.init(alloc);
    token2.parse(res);

    defer token2.deinit();

    var header2 = try token2.getHeader();
    defer header2.deinit();

    try testing.expectEqualStrings(header.typ, header2.getType().?);
    try testing.expectEqualStrings(header.alg, header2.getAlgorithm().?);
    try testing.expectEqualStrings(header.kid, header2.getKeyID().?);
    try testing.expectEqualStrings(header.cty, header2.getContentType().?);
    try testing.expectEqualStrings(header.str, header2.getString("str").?);

    try testing.expectEqual(.{null}, .{header2.getString("strfs")});
    try testing.expectEqual(.{null}, .{header2.getString("nstr")});
}
