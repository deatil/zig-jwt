const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;

pub const ecdsa = @import("ecdsa.zig");
pub const eddsa = @import("eddsa.zig");
pub const hmac = @import("hmac.zig");
pub const none = @import("none.zig");
pub const token = @import("token.zig");
pub const utils = @import("utils.zig");

pub const SigningMethodES256 = JWT(ecdsa.ES256, ecdsa.ecdsa.EcdsaP256Sha256.SecretKey, ecdsa.ecdsa.EcdsaP256Sha256.PublicKey);
pub const SigningMethodES384 = JWT(ecdsa.ES384, ecdsa.ecdsa.EcdsaP384Sha384.SecretKey, ecdsa.ecdsa.EcdsaP384Sha384.PublicKey);
// pub const SigningMethodES512 = JWT(ecdsa.ES512, ecdsa.ecdsa.SecretKey, ecdsa.ecdsa.PublicKey);

pub const SigningMethodEdDSA = JWT(eddsa.EdDSA, eddsa.Ed25519.SecretKey, eddsa.Ed25519.PublicKey);

pub const SigningMethodHS256 = JWT(hmac.HS256, []const u8, []const u8);
pub const SigningMethodHS384 = JWT(hmac.HS384, []const u8, []const u8);
pub const SigningMethodHS512 = JWT(hmac.HS512, []const u8, []const u8);

pub const SigningMethodNone = JWT(none.None, []const u8, []const u8);

pub const Error = error {
    JWTVerifyFail,
    JWTSignatureInvalid,
    JWTNoExistsSigningMethod,
};

pub fn JWT(comptime Signer: type, comptime SecretKeyType: type, comptime PublicKeyType: type) type {
    return struct {
        signer: Signer,
        alloc: Allocator, 

        const Self = @This();

        pub fn init(alloc: Allocator) Self {
            return .{
                .signer = Signer.init(),
                .alloc = alloc,
            };
        }

        pub fn make(self: Self, claims: anytype, key: SecretKeyType) ![]const u8 {
            var t = token.Token.init(self.alloc);
            try t.setHeader(.{
                .typ = "JWT",
                .alg = self.signer.alg(),
            });
            try t.setClaims(claims);

            const signed = try t.signingString();
            defer t.deinit();

            var signed_string = try self.signer.sign(signed, key);
            try t.setSignature(&signed_string);

            const sig = try t.signedString();
            return sig;
        }

        pub fn parse(self: Self, token_string: []const u8, key: PublicKeyType) !token.Token {
            var t = token.Token.init(self.alloc);
            try t.parse(token_string);

            const msg = try t.signingString();

            const token_sign = t.getSignature();

            const sign_length = self.signer.signLength();
            if (token_sign.len != sign_length) {
                return Error.JWTSignatureInvalid;
            }

            var sign: [self.signer.signLength()]u8 = undefined;
            @memcpy(sign[0..], token_sign);
    
            if (!self.signer.verify(msg, sign, key)) {
                return Error.JWTVerifyFail;
            }

            return t;
        }
    };
}

// jwt claims struct
pub const JWTClaims = struct {
    // Issuer
    iss: ?[]const u8 = null,
    // Issued At
    iat: ?i64 = null,
    // Expiration Time
    exp: ?i64 = null,
    // Audience
    aud: ?[]const u8 = null,
    // Subject
    sub: ?[]const u8 = null,
    // JWT ID
    jti: ?[]const u8 = null,
    // Not Before
    nbf: ?i64 = null,
};

pub fn getSigningMethod(name: []const u8) !type {
    if (eq(name, "ES256")) {
        return SigningMethodES256;
    }
    if (eq(name, "ES384")) {
        return SigningMethodES384;
    }

    if (eq(name, "EdDSA")) {
        return SigningMethodEdDSA;
    }

    if (eq(name, "HS256")) {
        return SigningMethodHS256;
    }
    if (eq(name, "HS384")) {
        return SigningMethodHS384;
    }
    if (eq(name, "HS512")) {
        return SigningMethodHS512;
    }

    if (eq(name, "none")) {
        return SigningMethodNone;
    }

    return Error.JWTNoExistsSigningMethod;
}

pub fn eq(rest: []const u8, needle: []const u8) bool {
    return std.mem.eql(u8, rest, needle);
}

test "getSigningMethod" {
    try testing.expectEqual(SigningMethodES256, try getSigningMethod("ES256"));
    try testing.expectEqual(SigningMethodES384, try getSigningMethod("ES384"));

    try testing.expectEqual(SigningMethodEdDSA, try getSigningMethod("EdDSA"));

    try testing.expectEqual(SigningMethodHS256, try getSigningMethod("HS256"));
    try testing.expectEqual(SigningMethodHS384, try getSigningMethod("HS384"));
    try testing.expectEqual(SigningMethodHS512, try getSigningMethod("HS512"));

    try testing.expectEqual(SigningMethodNone, try getSigningMethod("none"));

    var need_true: bool = false;
    getSigningMethod("HS258") catch |err| {
        need_true = true;
        try testing.expectEqual(Error.JWTNoExistsSigningMethod, err);
    };
    try testing.expectEqual(true, need_true);

}

test "SigningMethodEdDSA" {
    const alloc = std.heap.page_allocator;

    const kp = eddsa.Ed25519.KeyPair.generate();

    const claims = .{
        .aud = "example.com",
        .iat = "foo",
    };

    const s = SigningMethodEdDSA.init(alloc);
    const token_string = try s.make(claims, kp.secret_key);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = SigningMethodEdDSA.init(alloc);
    var parsed = try p.parse(token_string, kp.public_key);

    const claims2 = try parsed.getClaims();
    try testing.expectEqualStrings(claims.aud, claims2.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.iat, claims2.object.get("iat").?.string);

}

test "SigningMethodES256" {
    const alloc = std.heap.page_allocator;

    const kp = ecdsa.ecdsa.EcdsaP256Sha256.KeyPair.generate();

    const claims = .{
        .aud = "example.com",
        .iat = "foo",
    };

    const s = SigningMethodES256.init(alloc);
    const token_string = try s.make(claims, kp.secret_key);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = SigningMethodES256.init(alloc);
    var parsed = try p.parse(token_string, kp.public_key);

    const claims2 = try parsed.getClaims();
    try testing.expectEqualStrings(claims.aud, claims2.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.iat, claims2.object.get("iat").?.string);

}

test "SigningMethodES384" {
    const alloc = std.heap.page_allocator;

    const kp = ecdsa.ecdsa.EcdsaP384Sha384.KeyPair.generate();

    const claims = .{
        .aud = "example.com",
        .iat = "foo",
    };

    const s = SigningMethodES384.init(alloc);
    const token_string = try s.make(claims, kp.secret_key);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = SigningMethodES384.init(alloc);
    var parsed = try p.parse(token_string, kp.public_key);

    const claims2 = try parsed.getClaims();
    try testing.expectEqualStrings(claims.aud, claims2.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.iat, claims2.object.get("iat").?.string);

}

test "SigningMethodHS256" {
    const alloc = std.heap.page_allocator;

    const claims = .{
        .aud = "example.com",
        .iat = "foo",
    };
    const key = "test-key";

    const s = SigningMethodHS256.init(alloc);
    const token_string = try s.make(claims, key);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = SigningMethodHS256.init(alloc);
    var parsed = try p.parse(token_string, key);

    const claims2 = try parsed.getClaims();
    try testing.expectEqualStrings(claims.aud, claims2.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.iat, claims2.object.get("iat").?.string);

}

test "SigningMethodHS384" {
    const alloc = std.heap.page_allocator;

    const claims = .{
        .aud = "example.com",
        .iat = "foo",
    };
    const key = "test-key";

    const s = SigningMethodHS384.init(alloc);
    const token_string = try s.make(claims, key);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = SigningMethodHS384.init(alloc);
    var parsed = try p.parse(token_string, key);

    const claims2 = try parsed.getClaims();
    try testing.expectEqualStrings(claims.aud, claims2.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.iat, claims2.object.get("iat").?.string);

}

test "SigningMethodHS512" {
    const alloc = std.heap.page_allocator;

    const claims = .{
        .aud = "example.com",
        .iat = "foo",
    };
    const key = "test-key";

    const s = SigningMethodHS512.init(alloc);
    const token_string = try s.make(claims, key);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = SigningMethodHS512.init(alloc);
    var parsed = try p.parse(token_string, key);

    const claims2 = try parsed.getClaims();
    try testing.expectEqualStrings(claims.aud, claims2.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.iat, claims2.object.get("iat").?.string);

}

test "SigningMethodNone" {
    const alloc = std.heap.page_allocator;

    const claims = .{
        .aud = "example.com",
        .iat = "foo",
    };
    const key = "";

    const s = SigningMethodNone.init(alloc);
    const token_string = try s.make(claims, key);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = SigningMethodNone.init(alloc);
    var parsed = try p.parse(token_string, key);

    const claims2 = try parsed.getClaims();
    try testing.expectEqualStrings(claims.aud, claims2.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.iat, claims2.object.get("iat").?.string);

}

test "use JWTClaims to json" {
    const alloc = std.heap.page_allocator;

    const msg = JWTClaims{
        .iss = "test-data",
    };
    const check = "{\"iss\":\"test-data\"}";

    const res = try utils.jsonEncode(alloc, msg);
    try testing.expectEqualStrings(check, res);
}
