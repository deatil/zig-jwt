const std = @import("std");
const json = std.json;
const time = std.time;
const testing = std.testing;

const utils = @import("utils.zig");
const Token = @import("token.zig").Token;

pub const Validator = struct {
    token: Token,
    claims: json.Value,

    const Self = @This();

    pub fn init(token: Token) !Self {
        var valid_token = token;
        const claims = try valid_token.getClaims();

        return .{
            .token = token,
            .claims = claims,
        };
    }

    pub fn deinit(self: *Self) void {
        self.token.deinit();
    }

    pub fn isPermittedFor(self: *Self, audience: []const u8) bool {
        const claims = self.claims;

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

    pub fn isIdentifiedBy(self: *Self, id: []const u8) bool {
        const claims = self.claims;

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

    pub fn isRelatedTo(self: *Self, subject: []const u8) bool {
        const claims = self.claims;

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

    pub fn hasBeenIssuedBy(self: *Self, issuer: []const u8) bool {
        const claims = self.claims;

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

    pub fn hasBeenIssuedBefore(self: *Self, now: i64) bool {
        const claims = self.claims;

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

    pub fn isMinimumTimeBefore(self: *Self, now: i64) bool {
        const claims = self.claims;

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

    pub fn isExpired(self: *Self, now: i64) bool {
        const claims = self.claims;

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

test "Validator isExpired" {
    const alloc = std.heap.page_allocator;

    const check1 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJleHAiOjE3Mzk4MTAzOTB9.dGVzdC1zaWduYXR1cmU";
    const now = time.timestamp();

    var token = Token.init(alloc);
    try token.parse(check1);

    var validator = try Validator.init(token);
    defer validator.deinit();

    const isExpired = validator.isExpired(now);

    try testing.expectEqual(true, isExpired);
    try testing.expectEqualStrings(check1, token.raw);

    const claims = try token.getClaims();
    try testing.expectEqual(true, claims.object.get("exp").?.integer > 0);
    
}

test "Validator isMinimumTimeBefore" {
    const alloc = std.heap.page_allocator;

    const check1 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJleGFtcGxlLmNvbSIsImlhdCI6ImZvbyIsIm5iZiI6MTczOTgxNjU0MH0.dGVzdC1zaWduYXR1cmU";
    const now = time.timestamp();

    var token = Token.init(alloc);
    try token.parse(check1);

    var validator = try Validator.init(token);
    defer validator.deinit();

    const isMinimumTimeBefore = validator.isMinimumTimeBefore(now);
    try testing.expectEqual(true, isMinimumTimeBefore);

    const claims = try token.getClaims();
    try testing.expectEqual(true, claims.object.get("nbf").?.integer > 0);
    
}

test "Validator" {
    const alloc = std.heap.page_allocator;

    const check1 = "eyJ0eXAiOiJKV0UiLCJhbGciOiJFUzI1NiIsImtpZCI6ImtpZHMifQ.eyJpc3MiOiJpc3MiLCJpYXQiOjE1Njc4NDIzODgsImV4cCI6MTc2Nzg0MjM4OCwiYXVkIjoiZXhhbXBsZS5jb20iLCJzdWIiOiJzdWIiLCJqdGkiOiJqdGkgcnJyIiwibmJmIjoxNTY3ODQyMzg4fQ.dGVzdC1zaWduYXR1cmU";
    const now = time.timestamp();

    var token = Token.init(alloc);
    try token.parse(check1);

    var validator = try Validator.init(token);
    defer validator.deinit();

    try testing.expectEqual(true, validator.hasBeenIssuedBy("iss"));
    try testing.expectEqual(true, validator.isRelatedTo("sub"));
    try testing.expectEqual(true, validator.isIdentifiedBy("jti rrr"));
    try testing.expectEqual(true, validator.isPermittedFor("example.com"));
    try testing.expectEqual(true, validator.hasBeenIssuedBefore(now));

    const claims = try token.getClaims();
    try testing.expectEqual(true, claims.object.get("nbf").?.integer > 0);
    
}
