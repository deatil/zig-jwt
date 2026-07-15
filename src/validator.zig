const std = @import("std");
const json = std.json;
const testing = std.testing;
const Allocator = std.mem.Allocator;

const utils = @import("utils.zig");
const Token = @import("token.zig").Token;

const StringArray = std.array_list.Managed([]const u8);

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
        const aud = self.getStrings("aud") catch &.{};
        if (aud.len > 0) {
            return aud;
        }

        return null;
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

    pub fn getStrings(self: *Self, name: []const u8) ![]const []const u8 {
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

pub const Validator = struct {
    claims: ClaimsData,
    leeway: i64 = 0,
    alloc: Allocator,

    const Self = @This();

    pub fn init(alloc: Allocator, token: *Token) !Self {
        const claims = try ClaimsData.init(alloc, token);

        return .{
            .claims = claims,
            .leeway = 0,
            .alloc = alloc,
        };
    }

    pub fn deinit(self: *Self) void {
        self.claims.deinit();
    }

    pub fn withLeeway(self: *Self, leeway: i64) void {
        self.leeway = leeway;
    }

    pub fn isPermittedFor(self: *Self, audiences: []const []const u8) bool {
        const auds = self.claims.getAudience();
        defer self.alloc.free(auds.?);

        if (auds) |val| {
            for (val) |aud| {
                for (audiences) |audience| {
                    if (utils.eq(audience, aud)) {
                        return true;
                    }
                }
            }

            return false;
        }

        return false;
    }

    pub fn isIdentifiedBy(self: *Self, id: []const u8) bool {
        const jti = self.claims.getID();

        if (jti) |val| {
            if (utils.eq(id, val)) {
                return true;
            }

            return false;
        }

        return false;
    }

    pub fn isRelatedTo(self: *Self, subjects: []const []const u8) bool {
        const sub = self.claims.getSubject();

        if (sub) |val| {
            for (subjects) |subject| {
                if (utils.eq(subject, val)) {
                    return true;
                }
            }

            return false;
        }

        return false;
    }

    pub fn hasBeenIssuedBy(self: *Self, issuers: []const []const u8) bool {
        const iss = self.claims.getIssuer();

        if (iss) |val| {
            for (issuers) |issuer| {
                if (utils.eq(issuer, val)) {
                    return true;
                }
            }

            return false;
        }

        return false;
    }

    pub fn hasBeenIssuedBefore(self: *Self, now: i64) bool {
        const iat = self.claims.getIssuedAt();

        if (iat) |val| {
            if (now + self.leeway >= val) {
                return true;
            }

            return false;
        }

        return true;
    }

    pub fn isMinimumTimeBefore(self: *Self, now: i64) bool {
        const nbf = self.claims.getNotBefore();

        if (nbf) |val| {
            if (now + self.leeway >= val) {
                return true;
            }

            return false;
        }

        return true;
    }

    pub fn isExpired(self: *Self, now: i64) bool {
        const exp = self.claims.getExpirationTime();

        if (exp) |val| {
            if (now - self.leeway < val) {
                return false;
            }

            return true;
        }

        return false;
    }
};

test "Validator isExpired" {
    const io = testing.io;
    const alloc = testing.allocator;

    const check1 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJleHAiOjE3Mzk4MTAzOTB9.dGVzdC1zaWduYXR1cmU";
    const ts = std.Io.Clock.real.now(io).nanoseconds;
    const now = @as(i64, @intCast(ts));

    var token = Token.init(alloc);
    token.parse(check1);
    defer token.deinit();

    var validator = try Validator.init(alloc, &token);
    defer validator.deinit();

    const isExpired = validator.isExpired(now);

    try testing.expectEqual(true, isExpired);
    try testing.expectEqualStrings(check1, token.raw);

    const claims = try token.getClaims();
    defer claims.deinit();
    try testing.expectEqual(true, claims.value.object.get("exp").?.integer > 0);
}

test "Validator isMinimumTimeBefore" {
    const io = testing.io;
    const alloc = testing.allocator;

    const check1 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJleGFtcGxlLmNvbSIsImlhdCI6ImZvbyIsIm5iZiI6MTczOTgxNjU0MH0.dGVzdC1zaWduYXR1cmU";
    const ts = std.Io.Clock.real.now(io).nanoseconds;
    const now = @as(i64, @intCast(ts));

    var token = Token.init(alloc);
    token.parse(check1);

    defer token.deinit();

    var validator = try Validator.init(alloc, &token);
    defer validator.deinit();

    const isMinimumTimeBefore = validator.isMinimumTimeBefore(now);
    try testing.expectEqual(true, isMinimumTimeBefore);

    const claims = try token.getClaims();
    defer claims.deinit();
    try testing.expectEqual(true, claims.value.object.get("nbf").?.integer > 0);
}

test "Validator" {
    const alloc = testing.allocator;

    const check1 = "eyJ0eXAiOiJKV0UiLCJhbGciOiJFUzI1NiIsImtpZCI6ImtpZHMifQ.eyJpc3MiOiJpc3MiLCJpYXQiOjE1Njc4NDIzODgsImV4cCI6MTc2Nzg0MjM4OCwiYXVkIjoiZXhhbXBsZS5jb20iLCJzdWIiOiJzdWIiLCJqdGkiOiJqdGkgcnJyIiwibmJmIjoxNTY3ODQyMzg4fQ.dGVzdC1zaWduYXR1cmU";
    const now = @as(i64, 1567842388);

    var token = Token.init(alloc);
    token.parse(check1);

    defer token.deinit();

    var validator = try Validator.init(alloc, &token);
    defer validator.deinit();

    try testing.expectEqual(true, validator.hasBeenIssuedBy(&.{"iss"}));
    try testing.expectEqual(true, validator.isRelatedTo(&.{ "sub1", "sub" }));
    try testing.expectEqual(true, validator.isIdentifiedBy("jti rrr"));
    try testing.expectEqual(true, validator.isPermittedFor(&.{"example.com"}));
    try testing.expectEqual(true, validator.hasBeenIssuedBefore(now));
    try testing.expectEqual(false, validator.isExpired(now));

    const claims = try token.getClaims();
    defer claims.deinit();
    try testing.expectEqual(true, claims.value.object.get("nbf").?.integer > 0);

    try testing.expectEqual(1567842388, claims.value.object.get("iat").?.integer);
    try testing.expectEqual(1767842388, claims.value.object.get("exp").?.integer);
    try testing.expectEqual(1567842388, claims.value.object.get("nbf").?.integer);

    try testing.expectEqual(true, validator.hasBeenIssuedBefore(1567842389));
    try testing.expectEqual(true, validator.isMinimumTimeBefore(1567842389));
    try testing.expectEqual(true, validator.isExpired(1767842389));

    // ======

    var token2 = Token.init(alloc);
    token2.parse(check1);

    defer token2.deinit();

    var validator2 = try Validator.init(alloc, &token2);
    defer validator2.deinit();

    validator2.withLeeway(3);

    try testing.expectEqual(true, validator2.hasBeenIssuedBefore(1567842391));
    try testing.expectEqual(false, validator2.hasBeenIssuedBefore(1567842384));
    try testing.expectEqual(true, validator2.isMinimumTimeBefore(1567842391));
    try testing.expectEqual(false, validator2.isMinimumTimeBefore(1567842384));
    try testing.expectEqual(true, validator2.isExpired(1767842392));
    try testing.expectEqual(false, validator2.isExpired(1767842389));
}

test "ClaimsData" {
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

test "ClaimsData fail" {
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

    const subs = data.getStrings("sub0") catch &.{};
    defer alloc.free(subs);

    try testing.expectEqual(0, subs.len);

    try testing.expectEqual(.{null}, .{data.getObject("iss")});
    try testing.expectEqual(.{null}, .{data.getArray("iss")});
    try testing.expectEqual(.{null}, .{data.getString("ita")});
    try testing.expectEqual(.{null}, .{data.getNumberString("ita")});
    try testing.expectEqual(.{null}, .{data.getFloat("ita")});
    try testing.expectEqual(.{null}, .{data.getInteger("ita")});
    try testing.expectEqual(.{null}, .{data.getBool("ita")});

    const ob = data.getObject("ob").?;
    try testing.expectFmt("obd-data", "{s}", .{ob.get("obd").?.string});

    const arr = data.getArray("arr").?;
    try testing.expectFmt("arr-data", "{s}", .{arr.items[0].string});

    try testing.expectFmt("111111119223372036854776000", "{s}", .{data.getNumberString("ns").?});
    try testing.expectFmt("aud1", "{s}", .{data.getString("aud").?});
}
