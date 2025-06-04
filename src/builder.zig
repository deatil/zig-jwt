const std = @import("std");
const fmt = std.fmt;
const json = std.json;
const testing = std.testing;
const Allocator = std.mem.Allocator;

const Values = std.ArrayList(u8);

const eddsa = @import("eddsa.zig");
const Token = @import("token.zig").Token;

pub fn Builder(comptime Signer: type, comptime SecretKeyType: type) type {
    return struct {
        signer: Signer,
        headers: Values,
        claims: Values,
        alloc: Allocator,

        const Self = @This();

        pub fn init(alloc: Allocator) Self {
            return .{
                .signer = Signer.init(alloc),
                .headers = Values.init(alloc),
                .claims = Values.init(alloc),
                .alloc = alloc,
            };
        }

        pub fn deinit(self: *Self) void {
            self.headers.deinit();
            self.claims.deinit();
        }

        pub fn headersData(self: *Self) Data {
            return Data.init(&self.headers);
        }

        pub fn claimsData(self: *Self) Data {
            return Data.init(&self.claims);
        }

        pub fn getHeaders(self: *Self) ![]const u8 {
            var clone = try self.headers.clone();
            const headers = try clone.toOwnedSlice();
            return headers;
        }

        pub fn getClaims(self: *Self) ![]const u8 {
            var clone = try self.claims.clone();
            const claims = try clone.toOwnedSlice();
            return claims;
        }

        pub fn getToken(self: *Self, secret_key: SecretKeyType) !Token {
            var header = try self.getHeaders();
            if (header.len == 0) {
                var h = self.headersData();
                defer h.deinit();

                try h.begin();
                try h.setData("typ", "JWT");
                try h.setData("alg", self.signer.alg());
                try h.end();

                header = try self.getHeaders();
            }

            defer self.alloc.free(header);

            const claims = try self.getClaims();
            defer self.alloc.free(claims);

            var t = Token.init(self.alloc);
            try t.withHeader(header);
            try t.withClaims(claims);

            const signing_string = try t.signingString();
            defer self.alloc.free(signing_string);

            const signature = try self.signer.sign(signing_string, secret_key);
            defer self.alloc.free(signature);

            try t.withSignature(signature);

            return t;
        }
    };
}

pub const Data = struct {
    stream: json.WriteStream(Values.Writer, .{ .checked_to_fixed_depth = 256 }),

    const Self = @This();

    pub fn init(value: *Values) Self {
        return .{
            .stream = json.writeStream(value.*.writer(), .{ .emit_null_optional_fields = false }),
        };
    }

    pub fn deinit(self: *Self) void {
        self.stream.deinit();
    }

    pub fn begin(self: *Self) !void {
        try self.stream.beginObject();
    }

    pub fn end(self: *Self) !void {
        try self.stream.endObject();
    }

    pub fn permittedFor(self: *Self, audience: []const u8) !void {
        try self.setData("aud", audience);
    }

    pub fn expiresAt(self: *Self, expiration: i64) !void {
        try self.setData("exp", expiration);
    }

    pub fn identifiedBy(self: *Self, id: []const u8) !void {
        try self.setData("jti", id);
    }

    pub fn issuedAt(self: *Self, issued_at: i64) !void {
        try self.setData("iat", issued_at);
    }

    pub fn issuedBy(self: *Self, issuer: []const u8) !void {
        try self.setData("iss", issuer);
    }

    pub fn canOnlyBeUsedAfter(self: *Self, not_before: i64) !void {
        try self.setData("nbf", not_before);
    }

    pub fn relatedTo(self: *Self, subject: []const u8) !void {
        try self.setData("sub", subject);
    }

    pub fn setData(self: *Self, name: []const u8, value: anytype) !void {
        try self.stream.objectField(name);
        try self.stream.write(value);
    }
};

test "Data" {
    const alloc = testing.allocator;

    var value = Values.init(alloc);

    var b = Data.init(&value);
    defer b.deinit();

    try b.begin();
    try b.permittedFor("permitted_for");
    try b.expiresAt(1567842388);
    try b.identifiedBy("identified_by");
    try b.issuedAt(1567842389);
    try b.issuedBy("issued_by");
    try b.canOnlyBeUsedAfter(1567842387);
    try b.relatedTo("related_to");
    try b.setData("foo", "bar");
    try b.end();

    const check =
        \\{"aud":"permitted_for","exp":1567842388,"jti":"identified_by","iat":1567842389,"iss":"issued_by","nbf":1567842387,"sub":"related_to","foo":"bar"}
    ;

    const claims = try value.toOwnedSlice();

    defer alloc.free(claims);

    try testing.expectEqualStrings(check, claims);
}

test "Data 2" {
    const alloc = testing.allocator;

    var value = Values.init(alloc);

    var b = Data.init(&value);
    defer b.deinit();

    try b.begin();
    try b.setData("typ", "JWT");
    try b.setData("alg", "ES256");
    try b.end();

    const check =
        \\{"typ":"JWT","alg":"ES256"}
    ;

    const claims = try value.toOwnedSlice();

    defer alloc.free(claims);

    try testing.expectEqualStrings(check, claims);
}

test "Builder" {
    const alloc = testing.allocator;

    var build = Builder(eddsa.SigningEdDSA, eddsa.Ed25519.SecretKey).init(alloc);
    defer build.deinit();

    var b = build.claimsData();
    defer b.deinit();

    try b.begin();
    try b.permittedFor("permitted_for");
    try b.expiresAt(1567842388);
    try b.identifiedBy("identified_by");
    try b.issuedAt(1567842389);
    try b.issuedBy("issued_by");
    try b.canOnlyBeUsedAfter(1567842387);
    try b.relatedTo("related_to");
    try b.setData("foo", "bar");
    try b.end();

    const check =
        \\{"aud":"permitted_for","exp":1567842388,"jti":"identified_by","iat":1567842389,"iss":"issued_by","nbf":1567842387,"sub":"related_to","foo":"bar"}
    ;

    const claims = try build.getClaims();

    defer alloc.free(claims);

    try testing.expectEqualStrings(check, claims);

    // =======

    var h = build.headersData();
    defer h.deinit();

    try h.begin();
    try h.setData("typ", "JWT");
    try h.setData("alg", "HS256");
    try h.end();

    const check2 =
        \\{"typ":"JWT","alg":"HS256"}
    ;

    const claims2 = try build.getHeaders();
    defer alloc.free(claims2);
    try testing.expectEqualStrings(check2, claims2);

    // =======

    const kp = eddsa.Ed25519.KeyPair.generate();

    var t = try build.getToken(kp.secret_key);
    const token_string = try t.signedString();

    defer t.deinit();
    defer alloc.free(token_string);

    try testing.expectEqual(true, token_string.len > 0);

    const check3 =
        \\{"typ":"JWT","alg":"HS256"}
    ;
    try testing.expectEqualStrings(check3, t.header);
}

test "Builder 2" {
    const alloc = testing.allocator;

    var build = Builder(eddsa.SigningEdDSA, eddsa.Ed25519.SecretKey).init(alloc);
    defer build.deinit();

    var b = build.claimsData();
    defer b.deinit();

    try b.begin();
    try b.permittedFor("permitted_for");
    try b.expiresAt(1567842388);
    try b.identifiedBy("identified_by");
    try b.issuedAt(1567842389);
    try b.issuedBy("issued_by");
    try b.canOnlyBeUsedAfter(1567842387);
    try b.relatedTo("related_to");
    try b.setData("foo", "bar");
    try b.end();

    var h = build.headersData();
    defer h.deinit();

    try h.begin();
    try h.setData("typ", "JWT");
    try h.setData("alg", "ES256");
    try h.end();

    const kp = eddsa.Ed25519.KeyPair.generate();

    var t = try build.getToken(kp.secret_key);
    const token_string = try t.signedString();

    defer t.deinit();
    defer alloc.free(token_string);

    try testing.expectEqual(true, token_string.len > 0);
}

test "Builder 3" {
    const alloc = testing.allocator;

    var build = Builder(eddsa.SigningEdDSA, eddsa.Ed25519.SecretKey).init(alloc);
    defer build.deinit();

    var b = build.claimsData();
    defer b.deinit();

    try b.begin();
    try b.permittedFor("permitted_for");
    try b.expiresAt(1567842388);
    try b.identifiedBy("identified_by");
    try b.issuedAt(1567842389);
    try b.issuedBy("issued_by");
    try b.canOnlyBeUsedAfter(1567842387);
    try b.relatedTo("related_to");
    try b.setData("foo", "bar");
    try b.end();

    const check =
        \\{"aud":"permitted_for","exp":1567842388,"jti":"identified_by","iat":1567842389,"iss":"issued_by","nbf":1567842387,"sub":"related_to","foo":"bar"}
    ;

    const claims = try build.getClaims();

    defer alloc.free(claims);

    try testing.expectEqualStrings(check, claims);

    // =======

    const kp = eddsa.Ed25519.KeyPair.generate();

    var t = try build.getToken(kp.secret_key);
    const token_string = try t.signedString();

    defer t.deinit();
    defer alloc.free(token_string);

    try testing.expectEqual(true, token_string.len > 0);

    const check3 =
        \\{"typ":"JWT","alg":"EdDSA"}
    ;
    try testing.expectEqualStrings(check3, t.header);
}
