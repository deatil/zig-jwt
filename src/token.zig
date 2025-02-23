const std = @import("std");
const json = std.json;
const time = std.time;
const testing = std.testing;
const Allocator = std.mem.Allocator;

const utils = @import("utils.zig");

pub const Token = struct {
    raw: []const u8 = "",
    header: []const u8 = "",
    claims: []const u8 = "",
    signature: []const u8 = "",
    alloc: Allocator, 

    const Self = @This();

    pub const Header = struct {
        typ: []const u8,
        alg: []const u8,
        kid: ?[]const u8 = null,
    };

    pub fn init(alloc: Allocator) Self {
        return .{
            .alloc = alloc,
        };
    }

    pub fn deinit(self: *Self) void {
        self.alloc.free(self.header);
        self.alloc.free(self.claims);
    }

    pub fn withHeader(self: *Self, header: []const u8) void {
        self.header = header;
    }

    pub fn setHeader(self: *Self, header: Header) !void {
        self.header = try utils.jsonEncode(self.alloc, header);
    }

    pub fn withClaims(self: *Self, claims: []const u8) void {
        self.claims = claims;
    }

    pub fn setClaims(self: *Self, claims: anytype) !void {
        self.claims = try utils.jsonEncode(self.alloc, claims);
    }

    pub fn withSignature(self: *Self, signature: []const u8) void {
        self.signature = signature;
    }

    pub fn signedString(self: *Self) ![]const u8 {
        return try self.signing(true);
    }

    pub fn signingString(self: *Self) ![]const u8 {
        return try self.signing(false);
    }

    fn signing(self: *Self, need_sign: bool) ![]const u8 {
        var buf = std.ArrayList(u8).init(self.alloc);
        defer buf.deinit();

        const header = try utils.base64UrlEncode(self.alloc, self.header);
        try buf.appendSlice(header[0..]);

        const claims = try utils.base64UrlEncode(self.alloc, self.claims);
        try buf.append('.');
        try buf.appendSlice(claims[0..]);

        if (need_sign) {
            const signature = try utils.base64UrlEncode(self.alloc, self.signature);
            try buf.append('.');
            try buf.appendSlice(signature[0..]);
        }

        return try buf.toOwnedSlice();
    }

    pub fn parse(self: *Self, token_string: []const u8) !void {
        if (token_string.len == 0) {
            return;
        }

        self.raw = token_string;
        self.header = "";
        self.claims = "";
        self.signature = "";

        var it = std.mem.splitScalar(u8, token_string, '.');
        if (it.next()) |pair| {
            self.header = try utils.base64UrlDecode(self.alloc, pair);
        }
        if (it.next()) |pair| {
            self.claims = try utils.base64UrlDecode(self.alloc, pair);
        }
        if (it.next()) |pair| {
            self.signature = try utils.base64UrlDecode(self.alloc, pair);
        }
    }

    pub fn getRaw(self: *Self) []const u8 {
        return self.raw;
    }

    pub fn getRawNoSignature(self: *Self) []const u8 {
        const index = std.mem.lastIndexOf(u8, self.raw, ".") orelse self.raw.len;
        return self.raw[0..index];
    }

    pub fn getHeader(self: *Self) !Header {
        const header = try utils.jsonDecode(self.alloc, self.header);

        var typ: []const u8 = "";
        if (header.object.get("typ")) |jwt_type| {
            if (jwt_type == .string) {
                typ = jwt_type.string;
            }
        }

        var alg: []const u8 = "";
        if (header.object.get("alg")) |jwt_alg| {
            if (jwt_alg == .string) {
                alg = jwt_alg.string;
            }
        }

        var kid: []const u8 = "";
        if (header.object.get("kid")) |jwt_kid| {
            if (jwt_kid == .string) {
                kid = jwt_kid.string;
            }
        }

        return .{
            .typ = typ,
            .alg = alg,
            .kid = kid,
        };
    }

    pub fn getHeaderT(self: *Self, comptime T: type) !T {
        const header = try utils.jsonDecodeT(T, self.alloc, self.header);
        return header;
    }

    pub fn getClaims(self: *Self) !json.Value {
        const claims = try utils.jsonDecode(self.alloc, self.claims);
        return claims;
    }

    pub fn getClaimsT(self: *Self, comptime T: type) !T {
        const claims = try utils.jsonDecodeT(T, self.alloc, self.claims);
        return claims;
    }

    pub fn getSignature(self: *Self) []const u8 {
        return self.signature;
    }

    pub fn isPermittedFor(self: *Self, audience: []const u8) !bool {
       const claims = try self.getClaims();

        if (claims.object.get("aud")) |val| {
            if (val == .string) {
                if (utils.eq(audience, val.string)) {
                    return true;
                }
            }

            return false;
        }

        return false;
    }

    pub fn isIdentifiedBy(self: *Self, id: []const u8) !bool {
       const claims = try self.getClaims();

        if (claims.object.get("jti")) |val| {
            if (val == .string) {
                if (utils.eq(id, val.string)) {
                    return true;
                }
            }

            return false;
        }

        return false;
    }

    pub fn isRelatedTo(self: *Self, subject: []const u8) !bool {
       const claims = try self.getClaims();

        if (claims.object.get("sub")) |val| {
            if (val == .string) {
                if (utils.eq(subject, val.string)) {
                    return true;
                }
            }

            return false;
        }

        return false;
    }

    pub fn hasBeenIssuedBy(self: *Self, issuer: []const u8) !bool {
       const claims = try self.getClaims();

        if (claims.object.get("iss")) |val| {
            if (val == .string) {
                if (utils.eq(issuer, val.string)) {
                    return true;
                }
            }

            return false;
        }

        return false;
    }

    pub fn hasBeenIssuedBefore(self: *Self, now: i64) !bool {
       const claims = try self.getClaims();

        if (claims.object.get("iat")) |val| {
            if (val == .integer) {
                if (now > val.integer) {
                    return true;
                }
            }

            return false;
        }

        return true;
    }

    pub fn isMinimumTimeBefore(self: *Self, now: i64) !bool {
       const claims = try self.getClaims();

        if (claims.object.get("nbf")) |val| {
            if (val == .integer) {
                if (now > val.integer) {
                    return true;
                }
            }

            return false;
        }

        return true;
    }

    pub fn isExpired(self: *Self, now: i64) !bool {
       const claims = try self.getClaims();

        if (claims.object.get("exp")) |val| {
            if (val == .integer) {
                if (now <= val.integer) {
                    return false;
                }
            }

            return true;
        }

        return false;
    }

};

test "Token" {
    const alloc = std.heap.page_allocator;

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
    token.withSignature(signature);

    defer token.deinit();

    const res1 = try token.signingString();
    try testing.expectEqualStrings(check1, res1);

    const res2 = try token.signedString();
    try testing.expectEqualStrings(check2, res2);

    // ====================

    var token2 = Token.init(alloc);
    try token2.parse(check1);

    const header2 = try token2.getHeader();
    try testing.expectEqualStrings("JWT", header2.typ);
    try testing.expectEqualStrings("ES256", header2.alg);

    const claims2 = try token2.getClaims();
    try testing.expectEqualStrings(claims.aud, claims2.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.iat, claims2.object.get("iat").?.string);

    const signature2 = token2.getSignature();
    try testing.expectEqual(0, signature2.len);

    // ====================

    var token3 = Token.init(alloc);
    try token3.parse(check2);

    const header3 = try token3.getHeader();
    try testing.expectEqualStrings("JWT", header3.typ);
    try testing.expectEqualStrings("ES256", header3.alg);

    const claims3 = try token3.getClaims();
    try testing.expectEqualStrings(claims.aud, claims3.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.iat, claims3.object.get("iat").?.string);

    const signature3 = token3.getSignature();
    try testing.expectEqualStrings(signature, signature3);

    const token51 = token3.getRaw();
    try testing.expectEqualStrings(check2, token51);

    const token5 = token3.getRawNoSignature();
    try testing.expectEqualStrings(check1, token5);

    // ====================

    const check3 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9";

    var token6 = Token.init(alloc);
    try token6.parse(check3);

    const sig61 = token6.getRaw();
    try testing.expectEqualStrings(check3, sig61);

    const sig6 = token6.getRawNoSignature();
    try testing.expectEqualStrings(check3, sig6);

}

test "Token 2" {
    const alloc = std.heap.page_allocator;

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
    token.withSignature(signature);

    defer token.deinit();

    const res1 = try token.signedString();
    try testing.expectEqualStrings(check1, res1);

    // ======

    var token2 = Token.init(alloc);
    token2.withHeader("ase123");
    token2.withClaims("tyh78");
    token2.withSignature("qwe");

    try testing.expectEqualStrings("ase123", token2.header);
    try testing.expectEqualStrings("tyh78", token2.claims);
    try testing.expectEqualStrings("qwe", token2.signature);
}

test "Token 3" {
    const alloc = std.heap.page_allocator;

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
    token.withSignature(signature);

    defer token.deinit();

    const res1 = try token.signedString();
    try testing.expectEqualStrings(check1, res1);

    // ================

    var token2 = Token.init(alloc);
    try token2.parse(check1);

    const header2 = try token2.getHeader();
    try testing.expectEqualStrings(header.kid.?, header2.kid.?);

    // ================

    const claimsT = struct {
        aud: []const u8,
        iat: []const u8,
    };
    const claims3 = try token2.getClaimsT(claimsT);
    try testing.expectEqualStrings(claims.aud, claims3.aud);
    try testing.expectEqualStrings(claims.iat, claims3.iat);

    const headerT = struct {
        typ: []const u8,
        alg: []const u8,
        kid: []const u8,
    };
    const header3 = try token2.getHeaderT(headerT);
    try testing.expectEqualStrings(header.typ, header3.typ);
    try testing.expectEqualStrings(header.alg, header3.alg);
    try testing.expectEqualStrings(header.kid.?, header3.kid);

}

test "Token isExpired" {
    const alloc = std.heap.page_allocator;

    const check1 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJleHAiOjE3Mzk4MTAzOTB9.dGVzdC1zaWduYXR1cmU";
    const now = time.timestamp();

    var token = Token.init(alloc);
    try token.parse(check1);
    const isExpired = try token.isExpired(now);

    try testing.expectEqual(true, isExpired);
    try testing.expectEqualStrings(check1, token.raw);

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

    const claims = try token.getClaims();
    try testing.expectEqual(true, claims.object.get("exp").?.integer > 0);
    
}

test "Token isMinimumTimeBefore" {
    const alloc = std.heap.page_allocator;

    const check1 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJleGFtcGxlLmNvbSIsImlhdCI6ImZvbyIsIm5iZiI6MTczOTgxNjU0MH0.dGVzdC1zaWduYXR1cmU";
    const now = time.timestamp();

    var token = Token.init(alloc);
    try token.parse(check1);
    const isMinimumTimeBefore = try token.isMinimumTimeBefore(now);

    try testing.expectEqual(true, isMinimumTimeBefore);

    const claims = try token.getClaims();
    try testing.expectEqual(true, claims.object.get("nbf").?.integer > 0);
    
}

test "Token hasBeenIssuedBefore" {
    const alloc = std.heap.page_allocator;

    const check1 = "eyJ0eXAiOiJKV0UiLCJhbGciOiJFUzI1NiIsImtpZCI6ImtpZHMifQ.eyJpc3MiOiJpc3MiLCJpYXQiOjE1Njc4NDIzODgsImV4cCI6MTc2Nzg0MjM4OCwiYXVkIjoiZXhhbXBsZS5jb20iLCJzdWIiOiJzdWIiLCJqdGkiOiJqdGkgcnJyIiwibmJmIjoxNTY3ODQyMzg4fQ.dGVzdC1zaWduYXR1cmU";
    const now = time.timestamp();

    var token = Token.init(alloc);
    try token.parse(check1);

    try testing.expectEqual(true, try token.hasBeenIssuedBy("iss"));
    try testing.expectEqual(true, try token.isRelatedTo("sub"));
    try testing.expectEqual(true, try token.isIdentifiedBy("jti rrr"));
    try testing.expectEqual(true, try token.isPermittedFor("example.com"));
    try testing.expectEqual(true, try token.hasBeenIssuedBefore(now));

    const claims = try token.getClaims();
    try testing.expectEqual(true, claims.object.get("nbf").?.integer > 0);
    
}