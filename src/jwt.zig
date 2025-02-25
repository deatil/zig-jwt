const std = @import("std");
const fmt = std.fmt;
const time = std.time;
const testing = std.testing;
const Allocator = std.mem.Allocator;

pub const crypto_rsa = @import("rsa/rsa.zig");

pub const rsa = @import("rsa.zig");
pub const rsa_pss = @import("rsa_pss.zig");
pub const ecdsa = @import("ecdsa.zig");
pub const eddsa = @import("eddsa.zig");
pub const hmac = @import("hmac.zig");
pub const none = @import("none.zig");
pub const utils = @import("utils.zig");

pub const Token = @import("token.zig").Token;
pub const Validator = @import("validator.zig").Validator;

pub const SigningMethodRS256 = JWT(rsa.SigningRS256, crypto_rsa.SecretKey, crypto_rsa.PublicKey);
pub const SigningMethodRS384 = JWT(rsa.SigningRS384, crypto_rsa.SecretKey, crypto_rsa.PublicKey);
pub const SigningMethodRS512 = JWT(rsa.SigningRS512, crypto_rsa.SecretKey, crypto_rsa.PublicKey);

pub const SigningMethodPS256 = JWT(rsa_pss.SigningPS256, crypto_rsa.SecretKey, crypto_rsa.PublicKey);
pub const SigningMethodPS384 = JWT(rsa_pss.SigningPS384, crypto_rsa.SecretKey, crypto_rsa.PublicKey);
pub const SigningMethodPS512 = JWT(rsa_pss.SigningPS512, crypto_rsa.SecretKey, crypto_rsa.PublicKey);

pub const SigningMethodES256 = JWT(ecdsa.SigningES256, ecdsa.ecdsa.EcdsaP256Sha256.SecretKey, ecdsa.ecdsa.EcdsaP256Sha256.PublicKey);
pub const SigningMethodES384 = JWT(ecdsa.SigningES384, ecdsa.ecdsa.EcdsaP384Sha384.SecretKey, ecdsa.ecdsa.EcdsaP384Sha384.PublicKey);
// pub const SigningMethodES512 = JWT(ecdsa.SigningES512, ecdsa.ecdsa.SecretKey, ecdsa.ecdsa.PublicKey);

pub const SigningMethodEdDSA = JWT(eddsa.SigningEdDSA, eddsa.Ed25519.SecretKey, eddsa.Ed25519.PublicKey);
pub const SigningMethodED25519 = JWT(eddsa.SigningED25519, eddsa.Ed25519.SecretKey, eddsa.Ed25519.PublicKey);

pub const SigningMethodHS256 = JWT(hmac.SigningHS256, []const u8, []const u8);
pub const SigningMethodHS384 = JWT(hmac.SigningHS384, []const u8, []const u8);
pub const SigningMethodHS512 = JWT(hmac.SigningHS512, []const u8, []const u8);

pub const SigningMethodNone = JWT(none.SigningNone, []const u8, []const u8);

pub const Error = error {
    JWTVerifyFail,
    JWTSigningMethodNotExists,
    JWTTypeInvalid,
    JWTAlgoInvalid
};

pub fn JWT(comptime Signer: type, comptime SecretKeyType: type, comptime PublicKeyType: type) type {
    return struct {
        signer: Signer,
        alloc: Allocator, 

        const Self = @This();

        pub fn init(alloc: Allocator) Self {
            return .{
                .signer = Signer.init(alloc),
                .alloc = alloc,
            };
        }

        pub fn alg(self: Self) []const u8 {
            return self.signer.alg();
        }

        pub fn signLength(self: Self) isize {
            return self.signer.signLength();
        }

        // use SigningMethod to make token
        pub fn sign(self: Self, claims: anytype, secret_key: SecretKeyType) ![]const u8 {
            const header = .{
                .typ = "JWT",
                .alg = self.signer.alg(),
            };

            return try self.signWithHeader(header, claims, secret_key);
        }

        // use SigningMethod with header to make token
        pub fn signWithHeader(self: Self, header: anytype, claims: anytype, secret_key: SecretKeyType) ![]const u8 {
            var t = Token.init(self.alloc);
            try t.setHeader(header);
            try t.setClaims(claims);

            const signing_string = try t.signingString();
            defer t.deinit();

            const signature = try self.signer.sign(signing_string, secret_key);
            t.withSignature(signature);

            defer self.alloc.free(signature);

            const signed_token = try t.signedString();
            return signed_token;
        }

        // parse token and verify token signature
        pub fn parse(self: Self, token_string: []const u8, public_key: PublicKeyType) !Token {
            var t = Token.init(self.alloc);
            try t.parse(token_string);

            const header = try t.getHeader();
            if (!utils.eq(header.typ, "JWT")) {
                return Error.JWTTypeInvalid;
            }
            if (!utils.eq(header.alg, self.signer.alg())) {
                return Error.JWTAlgoInvalid;
            }

            const signature = t.getSignature();
    
            const token_sign = try self.alloc.alloc(u8, signature.len);
            @memcpy(token_sign[0..], signature[0..]);

            defer self.alloc.free(token_sign);

            const signing_string = try t.signingString();
            if (!self.signer.verify(signing_string, token_sign, public_key)) {
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
    if (utils.eq(name, "RS256")) {
        return SigningMethodRS256;
    }
    if (utils.eq(name, "RS384")) {
        return SigningMethodRS384;
    }
    if (utils.eq(name, "RS512")) {
        return SigningMethodRS512;
    }

    if (utils.eq(name, "PS256")) {
        return SigningMethodPS256;
    }
    if (utils.eq(name, "PS384")) {
        return SigningMethodPS384;
    }
    if (utils.eq(name, "PS512")) {
        return SigningMethodPS512;
    }

    if (utils.eq(name, "ES256")) {
        return SigningMethodES256;
    }
    if (utils.eq(name, "ES384")) {
        return SigningMethodES384;
    }

    if (utils.eq(name, "EdDSA")) {
        return SigningMethodEdDSA;
    }

    if (utils.eq(name, "HS256")) {
        return SigningMethodHS256;
    }
    if (utils.eq(name, "HS384")) {
        return SigningMethodHS384;
    }
    if (utils.eq(name, "HS512")) {
        return SigningMethodHS512;
    }

    if (utils.eq(name, "none")) {
        return SigningMethodNone;
    }

    return Error.JWTSigningMethodNotExists;
}

pub fn getTokenHeader(alloc: Allocator, token_string: []const u8) !Token.Header {
    var t = Token.init(alloc);
    try t.parse(token_string);

    const header = try t.getHeader();
    return header;
}

test "getSigningMethod" {
    try testing.expectEqual(SigningMethodRS256, try getSigningMethod("RS256"));
    try testing.expectEqual(SigningMethodRS384, try getSigningMethod("RS384"));
    try testing.expectEqual(SigningMethodRS512, try getSigningMethod("RS512"));

    try testing.expectEqual(SigningMethodPS256, try getSigningMethod("PS256"));
    try testing.expectEqual(SigningMethodPS384, try getSigningMethod("PS384"));
    try testing.expectEqual(SigningMethodPS512, try getSigningMethod("PS512"));

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
        try testing.expectEqual(Error.JWTSigningMethodNotExists, err);
    };
    try testing.expectEqual(true, need_true);

}

test "parse JWTTypeInvalid" {
    const alloc = std.heap.page_allocator;

    const kp = eddsa.Ed25519.KeyPair.generate();

    const token_string = "eyJ0eXAiOiJKV0UiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJleGFtcGxlLmNvbSIsImlhdCI6ImZvbyJ9.dGVzdC1zaWduYXR1cmU";

    const p = SigningMethodEdDSA.init(alloc);

    var need_true: bool = false;
    _ = p.parse(token_string, kp.public_key) catch |err| {
        need_true = true;
        try testing.expectEqual(Error.JWTTypeInvalid, err);
    };
    try testing.expectEqual(true, need_true);

}

test "parse JWTSignatureInvalid" {
    const alloc = std.heap.page_allocator;

    const kp = ecdsa.ecdsa.EcdsaP256Sha256.KeyPair.generate();

    const token_string = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJleGFtcGxlLmNvbSIsImlhdCI6ImZvbyJ9.dGVzdC1zaWduYXR1cmU";

    const p = SigningMethodES256.init(alloc);

    var need_true: bool = false;
    _ = p.parse(token_string, kp.public_key) catch |err| {
        need_true = true;
        try testing.expectEqual(Error.JWTVerifyFail, err);
    };
    try testing.expectEqual(true, need_true);

}

test "Token Validator" {
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

test "SigningMethodEdDSA signWithHeader" {
    const alloc = std.heap.page_allocator;

    const kp = eddsa.Ed25519.KeyPair.generate();

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    const s = SigningMethodEdDSA.init(alloc);

    const header = .{
        .typ = "JWT",
        .alg = s.alg(),
        .tuy = "data123",
    };

    const token_string = try s.signWithHeader(header, claims, kp.secret_key);
    try testing.expectEqual(true, token_string.len > 0);
    try testing.expectEqualStrings("EdDSA", header.alg);

    // ==========

    const p = SigningMethodEdDSA.init(alloc);
    var parsed = try p.parse(token_string, kp.public_key);

    const header2 = try parsed.getHeaderValue();
    try testing.expectEqualStrings(header.typ, header2.object.get("typ").?.string);
    try testing.expectEqualStrings(header.alg, header2.object.get("alg").?.string);
    try testing.expectEqualStrings(header.tuy, header2.object.get("tuy").?.string);

    const claims2 = try parsed.getClaims();
    try testing.expectEqualStrings(claims.aud, claims2.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.object.get("sub").?.string);

    // ==========

    try testing.expectEqual(64, s.signLength());
    try testing.expectEqualStrings("EdDSA", s.alg());

}

test "SigningMethodEdDSA" {
    const alloc = std.heap.page_allocator;

    const kp = eddsa.Ed25519.KeyPair.generate();

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    const s = SigningMethodEdDSA.init(alloc);
    const token_string = try s.sign(claims, kp.secret_key);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = SigningMethodEdDSA.init(alloc);
    var parsed = try p.parse(token_string, kp.public_key);

    const claims2 = try parsed.getClaims();
    try testing.expectEqualStrings(claims.aud, claims2.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.object.get("sub").?.string);

}

test "SigningMethodES256" {
    const alloc = std.heap.page_allocator;

    const kp = ecdsa.ecdsa.EcdsaP256Sha256.KeyPair.generate();

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    const s = SigningMethodES256.init(alloc);
    const token_string = try s.sign(claims, kp.secret_key);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = SigningMethodES256.init(alloc);
    var parsed = try p.parse(token_string, kp.public_key);

    const claims2 = try parsed.getClaims();
    try testing.expectEqualStrings(claims.aud, claims2.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.object.get("sub").?.string);

}

test "SigningMethodES384" {
    const alloc = std.heap.page_allocator;

    const kp = ecdsa.ecdsa.EcdsaP384Sha384.KeyPair.generate();

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    const s = SigningMethodES384.init(alloc);
    const token_string = try s.sign(claims, kp.secret_key);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = SigningMethodES384.init(alloc);
    var parsed = try p.parse(token_string, kp.public_key);

    const claims2 = try parsed.getClaims();
    try testing.expectEqualStrings(claims.aud, claims2.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.object.get("sub").?.string);

}

test "SigningMethodHS256" {
    const alloc = std.heap.page_allocator;

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };
    const key = "test-key";

    const s = SigningMethodHS256.init(alloc);
    const token_string = try s.sign(claims, key);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = SigningMethodHS256.init(alloc);
    var parsed = try p.parse(token_string, key);

    const claims2 = try parsed.getClaims();
    try testing.expectEqualStrings(claims.aud, claims2.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.object.get("sub").?.string);

}

test "SigningMethodHS384" {
    const alloc = std.heap.page_allocator;

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };
    const key = "test-key";

    const s = SigningMethodHS384.init(alloc);
    const token_string = try s.sign(claims, key);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = SigningMethodHS384.init(alloc);
    var parsed = try p.parse(token_string, key);

    const claims2 = try parsed.getClaims();
    try testing.expectEqualStrings(claims.aud, claims2.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.object.get("sub").?.string);

}

test "SigningMethodHS512" {
    const alloc = std.heap.page_allocator;

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };
    const key = "test-key";

    const s = SigningMethodHS512.init(alloc);
    const token_string = try s.sign(claims, key);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = SigningMethodHS512.init(alloc);
    var parsed = try p.parse(token_string, key);

    const claims2 = try parsed.getClaims();
    try testing.expectEqualStrings(claims.aud, claims2.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.object.get("sub").?.string);

}

test "SigningMethodNone" {
    const alloc = std.heap.page_allocator;

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };
    const key = "";

    const s = SigningMethodNone.init(alloc);
    const token_string = try s.sign(claims, key);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = SigningMethodNone.init(alloc);
    var parsed = try p.parse(token_string, key);

    const claims2 = try parsed.getClaims();
    try testing.expectEqualStrings(claims.aud, claims2.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.object.get("sub").?.string);

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

test "SigningMethodES256 Check" {
    const alloc = std.heap.page_allocator;

    const pub_key = "04603e7857fbe9fb9e0ff435daad8ab1e0c3dc9be1ca44843335ab184a84501d0ffa4ba3ecf2da4c713f8abc8202f16fdef64d16ec29bbd8cd4ff6353b48b7ffbe";
    const pri_key = "603e7857fbe9fb9e0ff435daad8ab1e0c3dc9be1ca44843335ab184a84501d0f";
    const token_str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.feG39E-bn8HXAKhzDZq7yEAPWYDhZlwTn3sePJnU9VrGMmwdXAIEyoOnrjreYlVM_Z4N13eK9-TmMTWyfKJtHQ";

    const encoded_length = ecdsa.ecdsa.EcdsaP256Sha256.SecretKey.encoded_length;

    var pri_key_buf: [encoded_length]u8 = undefined;
    _ = try fmt.hexToBytes(&pri_key_buf, pri_key);

    var pub_key_buf: [pub_key.len / 2]u8 = undefined;
    const pub_key_bytes = try fmt.hexToBytes(&pub_key_buf, pub_key);

    const secret_key = try ecdsa.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(pri_key_buf);
    const public_key = try ecdsa.ecdsa.EcdsaP256Sha256.PublicKey.fromSec1(pub_key_bytes);

    const claims = .{
        .foo = "bar",
    };

    const s = SigningMethodES256.init(alloc);
    const token_string = try s.sign(claims, secret_key);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = SigningMethodES256.init(alloc);
    var parsed = try p.parse(token_str, public_key);

    const claims2 = try parsed.getClaims();
    try testing.expectEqualStrings(claims.foo, claims2.object.get("foo").?.string);

}

test "SigningMethodES384 Check" {
    const alloc = std.heap.page_allocator;

    const pub_key = "04d86bbac9694edf78b32aac0c7a69d6453503a96941ff53295b64bae238b38de58155c2d554a4ed457c45d9508429a6d44fb5ce62c483d8eb9f3284149bea2adf2095123fd6984df94918a93f98390ae2df26581ce1883e41ea383d7041a11a00";
    const pri_key = "d86bbac9694edf78b32aac0c7a69d6453503a96941ff53295b64bae238b38de58155c2d554a4ed457c45d9508429a6d4";
    const token_str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCJ9.eyJmb28iOiJiYXIifQ.ngAfKMbJUh0WWubSIYe5GMsA-aHNKwFbJk_wq3lq23aPp8H2anb1rRILIzVR0gUf4a8WzDtrzmiikuPWyCS6CN4-PwdgTk-5nehC7JXqlaBZU05p3toM3nWCwm_LXcld";

    const encoded_length = ecdsa.ecdsa.EcdsaP384Sha384.SecretKey.encoded_length;

    var pri_key_buf: [encoded_length]u8 = undefined;
    _ = try fmt.hexToBytes(&pri_key_buf, pri_key);

    var pub_key_buf: [pub_key.len / 2]u8 = undefined;
    const pub_key_bytes = try fmt.hexToBytes(&pub_key_buf, pub_key);

    const secret_key = try ecdsa.ecdsa.EcdsaP384Sha384.SecretKey.fromBytes(pri_key_buf);
    const public_key = try ecdsa.ecdsa.EcdsaP384Sha384.PublicKey.fromSec1(pub_key_bytes);

    const claims = .{
        .foo = "bar",
    };

    const s = SigningMethodES384.init(alloc);
    const token_string = try s.sign(claims, secret_key);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = SigningMethodES384.init(alloc);
    var parsed = try p.parse(token_str, public_key);

    const claims2 = try parsed.getClaims();
    try testing.expectEqualStrings(claims.foo, claims2.object.get("foo").?.string);

}

test "SigningMethodES256 Check fail" {
    const alloc = std.heap.page_allocator;

    const pub_key = "04603e7857fbe9fb9e0ff435daad8ab1e0c3dc9be1ca44843335ab184a84501d0ffa4ba3ecf2da4c713f8abc8202f16fdef64d16ec29bbd8cd4ff6353b48b7ffbe";
    const token_str = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.MEQCIHoSJnmGlPaVQDqacx_2XlXEhhqtWceVopjomc2PJLtdAiAUTeGPoNYxZw0z8mgOnnIcjoxRuNDVZvybRZF3wR1l8W";

    var pub_key_buf: [pub_key.len / 2]u8 = undefined;
    const pub_key_bytes = try fmt.hexToBytes(&pub_key_buf, pub_key);

    const public_key = try ecdsa.ecdsa.EcdsaP256Sha256.PublicKey.fromSec1(pub_key_bytes);

    const p = SigningMethodES256.init(alloc);

    var need_true: bool = false;
    _ = p.parse(token_str, public_key) catch |err| {
        need_true = true;
        try testing.expectEqual(Error.JWTVerifyFail, err);
    };
    try testing.expectEqual(true, need_true);

}

test "SigningMethodEdDSA Check" {
    const alloc = std.heap.page_allocator;

    const pub_key = "587ef3ea1a58aaf3e7b368b89fdcb29b0bc1dc03e18b82f243b887393e9caed1";
    const pri_key = "414c119ae6958c5ccd7285c4894dbcd191e4942f0e14e42e8bc9631c10777b9a587ef3ea1a58aaf3e7b368b89fdcb29b0bc1dc03e18b82f243b887393e9caed1";
    const token_str = "eyJhbGciOiJFRDI1NTE5IiwidHlwIjoiSldUIn0.eyJmb28iOiJiYXIifQ.ESuVzZq1cECrt9Od_gLPVG-_6uRP_8Nq-ajx6CtmlDqRJZqdejro2ilkqaQgSL-siE_3JMTUW7UwAorLaTyFCw";

    const encoded_length = eddsa.Ed25519.SecretKey.encoded_length;
    const encoded_length2 = eddsa.Ed25519.PublicKey.encoded_length;

    var pri_key_buf: [encoded_length]u8 = undefined;
    _ = try fmt.hexToBytes(&pri_key_buf, pri_key);

    var pub_key_buf: [encoded_length2]u8 = undefined;
    _ = try fmt.hexToBytes(&pub_key_buf, pub_key);

    const secret_key = try eddsa.Ed25519.SecretKey.fromBytes(pri_key_buf);
    const public_key = try eddsa.Ed25519.PublicKey.fromBytes(pub_key_buf);

    const claims = .{
        .foo = "bar",
    };

    const s = SigningMethodED25519.init(alloc);
    const token_string = try s.sign(claims, secret_key);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = SigningMethodED25519.init(alloc);
    var parsed = try p.parse(token_str, public_key);

    const claims2 = try parsed.getClaims();
    try testing.expectEqualStrings(claims.foo, claims2.object.get("foo").?.string);

}

test "SigningMethodEdDSA Check fail" {
    const alloc = std.heap.page_allocator;

    const pub_key = "587ef3ea1a58aaf3e7b368b89fdcb29b0bc1dc03e18b82f243b887393e9caed1";
    const token_str = "eyJhbGciOiJFRDI1NTE5IiwidHlwIjoiSldUIn0.eyJmb28iOiJiYXoifQ.ESuVzZq1cECrt9Od_gLPVG-_6uRP_8Nq-ajx6CtmlDqRJZqdejro2ilkqaQgSL-siE_3JMTUW7UwAorLaTyFCw";

    const encoded_length2 = eddsa.Ed25519.PublicKey.encoded_length;

    var pub_key_buf: [encoded_length2]u8 = undefined;
    _ = try fmt.hexToBytes(&pub_key_buf, pub_key);

    const public_key = try eddsa.Ed25519.PublicKey.fromBytes(pub_key_buf);

    const p = SigningMethodED25519.init(alloc);

    var need_true: bool = false;
    _ = p.parse(token_str, public_key) catch |err| {
        need_true = true;
        try testing.expectEqual(Error.JWTVerifyFail, err);
    };
    try testing.expectEqual(true, need_true);

}

test "SigningMethodHS256 Check" {
    const alloc = std.heap.page_allocator;

    const key = "0323354b2b0fa5bc837e0665777ba68f5ab328e6f054c928a90f84b2d2502ebfd3fb5a92d20647ef968ab4c377623d223d2e2172052e4f08c0cd9af567d080a3";
    const token_str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    var key_buf: [key.len]u8 = undefined;
    const key_bytes = try fmt.hexToBytes(&key_buf, key);

    const claims = .{
        .iss = "joe",
        .exp = 1300819380,
        .@"http://example.com/is_root" = true,
    };

    const s = SigningMethodHS256.init(alloc);
    const token_string = try s.sign(claims, key_bytes);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = SigningMethodHS256.init(alloc);
    var parsed = try p.parse(token_str, key_bytes);

    const claims2 = try parsed.getClaims();
    try testing.expectEqualStrings(claims.iss, claims2.object.get("iss").?.string);

}

test "SigningMethodHS384 Check" {
    const alloc = std.heap.page_allocator;

    const key = "0323354b2b0fa5bc837e0665777ba68f5ab328e6f054c928a90f84b2d2502ebfd3fb5a92d20647ef968ab4c377623d223d2e2172052e4f08c0cd9af567d080a3";
    const token_str = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJleHAiOjEuMzAwODE5MzhlKzA5LCJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZSwiaXNzIjoiam9lIn0.KWZEuOD5lbBxZ34g7F-SlVLAQ_r5KApWNWlZIIMyQVz5Zs58a7XdNzj5_0EcNoOy";

    var key_buf: [key.len]u8 = undefined;
    const key_bytes = try fmt.hexToBytes(&key_buf, key);

    const claims = .{
        .iss = "joe",
        .exp = 1300819380,
        .@"http://example.com/is_root" = true,
    };

    const s = SigningMethodHS384.init(alloc);
    const token_string = try s.sign(claims, key_bytes);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = SigningMethodHS384.init(alloc);
    var parsed = try p.parse(token_str, key_bytes);

    const claims2 = try parsed.getClaims();
    try testing.expectEqualStrings(claims.iss, claims2.object.get("iss").?.string);

}

test "SigningMethodHS512 Check" {
    const alloc = std.heap.page_allocator;

    const key = "0323354b2b0fa5bc837e0665777ba68f5ab328e6f054c928a90f84b2d2502ebfd3fb5a92d20647ef968ab4c377623d223d2e2172052e4f08c0cd9af567d080a3";
    const token_str = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEuMzAwODE5MzhlKzA5LCJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZSwiaXNzIjoiam9lIn0.CN7YijRX6Aw1n2jyI2Id1w90ja-DEMYiWixhYCyHnrZ1VfJRaFQz1bEbjjA5Fn4CLYaUG432dEYmSbS4Saokmw";

    var key_buf: [key.len]u8 = undefined;
    const key_bytes = try fmt.hexToBytes(&key_buf, key);

    const claims = .{
        .iss = "joe",
        .exp = 1300819380,
        .@"http://example.com/is_root" = true,
    };

    const s = SigningMethodHS512.init(alloc);
    const token_string = try s.sign(claims, key_bytes);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = SigningMethodHS512.init(alloc);
    var parsed = try p.parse(token_str, key_bytes);

    const claims2 = try parsed.getClaims();
    try testing.expectEqualStrings(claims.iss, claims2.object.get("iss").?.string);

}

test "SigningMethodHS256 Check fail" {
    const alloc = std.heap.page_allocator;

    const key = "0323354b2b0fa5bc837e0665777ba68f5ab328e6f054c928a90f84b2d2502ebfd3fb5a92d20647ef968ab4c377623d223d2e2172052e4f08c0cd9af567d080a3";
    const token_str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXo";

    var key_buf: [key.len]u8 = undefined;
    const key_bytes = try fmt.hexToBytes(&key_buf, key);

    const p = SigningMethodHS256.init(alloc);

    var need_true: bool = false;
    _ = p.parse(token_str, key_bytes) catch |err| {
        need_true = true;
        try testing.expectEqual(Error.JWTVerifyFail, err);
    };
    try testing.expectEqual(true, need_true);

}

test "getTokenHeader" {
    const alloc = std.heap.page_allocator;

    const token_str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.feG39E-bn8HXAKhzDZq7yEAPWYDhZlwTn3sePJnU9VrGMmwdXAIEyoOnrjreYlVM_Z4N13eK9-TmMTWyfKJtHQ";

    const header = try getTokenHeader(alloc, token_str);
    try testing.expectEqualStrings("ES256", header.alg);

}

test "SigningMethodES256 with JWTClaims" {
    const alloc = std.heap.page_allocator;

    const kp = ecdsa.ecdsa.EcdsaP256Sha256.KeyPair.generate();

    const claims: JWTClaims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    const s = SigningMethodES256.init(alloc);
    const token_string = try s.sign(claims, kp.secret_key);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = SigningMethodES256.init(alloc);
    var parsed = try p.parse(token_string, kp.public_key);

    const claims2 = try parsed.getClaims();
    try testing.expectEqualStrings(claims.aud.?, claims2.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub.?, claims2.object.get("sub").?.string);

}

test "SigningMethodRS256" {
    const alloc = std.heap.page_allocator;

    const prikey = "MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAyMaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdEKdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gMIvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDnFcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvYmEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghjFuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+UI5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNTOvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL04aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0KcnckbmDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ryeBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq";
    const pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";

    const prikey_bytes = try utils.base64Decode(alloc, prikey);
    const pubkey_bytes = try utils.base64Decode(alloc, pubkey);

    const secret_key = try crypto_rsa.SecretKey.fromDer(prikey_bytes);
    const public_key = try crypto_rsa.PublicKey.fromDer(pubkey_bytes);

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    const s = SigningMethodRS256.init(alloc);
    const token_string = try s.sign(claims, secret_key);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = SigningMethodRS256.init(alloc);
    var parsed = try p.parse(token_string, public_key);

    const claims2 = try parsed.getClaims();
    try testing.expectEqualStrings(claims.aud, claims2.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.object.get("sub").?.string);

}

test "SigningMethodRS384" {
    const alloc = std.heap.page_allocator;

    const prikey = "MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAyMaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdEKdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gMIvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDnFcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvYmEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghjFuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+UI5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNTOvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL04aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0KcnckbmDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ryeBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq";
    const pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";

    const prikey_bytes = try utils.base64Decode(alloc, prikey);
    const pubkey_bytes = try utils.base64Decode(alloc, pubkey);

    const secret_key = try crypto_rsa.SecretKey.fromDer(prikey_bytes);
    const public_key = try crypto_rsa.PublicKey.fromDer(pubkey_bytes);

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    const s = SigningMethodRS384.init(alloc);
    const token_string = try s.sign(claims, secret_key);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = SigningMethodRS384.init(alloc);
    var parsed = try p.parse(token_string, public_key);

    const claims2 = try parsed.getClaims();
    try testing.expectEqualStrings(claims.aud, claims2.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.object.get("sub").?.string);

}

test "SigningMethodRS512" {
    const alloc = std.heap.page_allocator;

    const prikey = "MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAyMaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdEKdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gMIvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDnFcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvYmEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghjFuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+UI5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNTOvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL04aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0KcnckbmDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ryeBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq";
    const pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";

    const prikey_bytes = try utils.base64Decode(alloc, prikey);
    const pubkey_bytes = try utils.base64Decode(alloc, pubkey);

    const secret_key = try crypto_rsa.SecretKey.fromDer(prikey_bytes);
    const public_key = try crypto_rsa.PublicKey.fromDer(pubkey_bytes);

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    const s = SigningMethodRS512.init(alloc);
    const token_string = try s.sign(claims, secret_key);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = SigningMethodRS512.init(alloc);
    var parsed = try p.parse(token_string, public_key);

    const claims2 = try parsed.getClaims();
    try testing.expectEqualStrings(claims.aud, claims2.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.object.get("sub").?.string);

}

test "SigningMethodPS256" {
    const alloc = std.heap.page_allocator;

    const prikey = "MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAyMaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdEKdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gMIvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDnFcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvYmEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghjFuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+UI5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNTOvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL04aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0KcnckbmDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ryeBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq";
    const pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";

    const prikey_bytes = try utils.base64Decode(alloc, prikey);
    const pubkey_bytes = try utils.base64Decode(alloc, pubkey);

    const secret_key = try crypto_rsa.SecretKey.fromDer(prikey_bytes);
    const public_key = try crypto_rsa.PublicKey.fromDer(pubkey_bytes);

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    const s = SigningMethodPS256.init(alloc);
    const token_string = try s.sign(claims, secret_key);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = SigningMethodPS256.init(alloc);
    var parsed = try p.parse(token_string, public_key);

    const claims2 = try parsed.getClaims();
    try testing.expectEqualStrings(claims.aud, claims2.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.object.get("sub").?.string);

}

test "SigningMethodPS384" {
    const alloc = std.heap.page_allocator;

    const prikey = "MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAyMaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdEKdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gMIvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDnFcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvYmEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghjFuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+UI5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNTOvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL04aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0KcnckbmDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ryeBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq";
    const pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";

    const prikey_bytes = try utils.base64Decode(alloc, prikey);
    const pubkey_bytes = try utils.base64Decode(alloc, pubkey);

    const secret_key = try crypto_rsa.SecretKey.fromDer(prikey_bytes);
    const public_key = try crypto_rsa.PublicKey.fromDer(pubkey_bytes);

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    const s = SigningMethodPS384.init(alloc);
    const token_string = try s.sign(claims, secret_key);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = SigningMethodPS384.init(alloc);
    var parsed = try p.parse(token_string, public_key);

    const claims2 = try parsed.getClaims();
    try testing.expectEqualStrings(claims.aud, claims2.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.object.get("sub").?.string);

}

test "SigningMethodPS512" {
    const alloc = std.heap.page_allocator;

    const prikey = "MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAyMaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdEKdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gMIvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDnFcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvYmEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghjFuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+UI5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNTOvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL04aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0KcnckbmDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ryeBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq";
    const pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";

    const prikey_bytes = try utils.base64Decode(alloc, prikey);
    const pubkey_bytes = try utils.base64Decode(alloc, pubkey);

    const secret_key = try crypto_rsa.SecretKey.fromDer(prikey_bytes);
    const public_key = try crypto_rsa.PublicKey.fromDer(pubkey_bytes);

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    const s = SigningMethodPS512.init(alloc);
    const token_string = try s.sign(claims, secret_key);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = SigningMethodPS512.init(alloc);
    var parsed = try p.parse(token_string, public_key);

    const claims2 = try parsed.getClaims();
    try testing.expectEqualStrings(claims.aud, claims2.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.object.get("sub").?.string);

}

test "SigningMethodRS256 Check" {
    const alloc = std.heap.page_allocator;

    // check data from golang-jwt
    const pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";
    const token_str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg";

    const pubkey_bytes = try utils.base64Decode(alloc, pubkey);
    const public_key = try crypto_rsa.PublicKey.fromDer(pubkey_bytes);

    const p = SigningMethodRS256.init(alloc);
    var parsed = try p.parse(token_str, public_key);

    const claims2 = try parsed.getClaims();
    try testing.expectEqualStrings("bar", claims2.object.get("foo").?.string);

}

test "SigningMethodRS384 Check" {
    const alloc = std.heap.page_allocator;

    const pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";
    const token_str = "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.W-jEzRfBigtCWsinvVVuldiuilzVdU5ty0MvpLaSaqK9PlAWWlDQ1VIQ_qSKzwL5IXaZkvZFJXT3yL3n7OUVu7zCNJzdwznbC8Z-b0z2lYvcklJYi2VOFRcGbJtXUqgjk2oGsiqUMUMOLP70TTefkpsgqDxbRh9CDUfpOJgW-dU7cmgaoswe3wjUAUi6B6G2YEaiuXC0XScQYSYVKIzgKXJV8Zw-7AN_DBUI4GkTpsvQ9fVVjZM9csQiEXhYekyrKu1nu_POpQonGd8yqkIyXPECNmmqH5jH4sFiF67XhD7_JpkvLziBpI-uh86evBUadmHhb9Otqw3uV3NTaXLzJw";

    const pubkey_bytes = try utils.base64Decode(alloc, pubkey);
    const public_key = try crypto_rsa.PublicKey.fromDer(pubkey_bytes);

    const p = SigningMethodRS384.init(alloc);
    var parsed = try p.parse(token_str, public_key);

    const claims2 = try parsed.getClaims();
    try testing.expectEqualStrings("bar", claims2.object.get("foo").?.string);

}

test "SigningMethodRS512 Check" {
    const alloc = std.heap.page_allocator;

    const pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";
    const token_str = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.zBlLlmRrUxx4SJPUbV37Q1joRcI9EW13grnKduK3wtYKmDXbgDpF1cZ6B-2Jsm5RB8REmMiLpGms-EjXhgnyh2TSHE-9W2gA_jvshegLWtwRVDX40ODSkTb7OVuaWgiy9y7llvcknFBTIg-FnVPVpXMmeV_pvwQyhaz1SSwSPrDyxEmksz1hq7YONXhXPpGaNbMMeDTNP_1oj8DZaqTIL9TwV8_1wb2Odt_Fy58Ke2RVFijsOLdnyEAjt2n9Mxihu9i3PhNBkkxa2GbnXBfq3kzvZ_xxGGopLdHhJjcGWXO-NiwI9_tiu14NRv4L2xC0ItD9Yz68v2ZIZEp_DuzwRQ";

    const pubkey_bytes = try utils.base64Decode(alloc, pubkey);
    const public_key = try crypto_rsa.PublicKey.fromDer(pubkey_bytes);

    const p = SigningMethodRS512.init(alloc);
    var parsed = try p.parse(token_str, public_key);

    const claims2 = try parsed.getClaims();
    try testing.expectEqualStrings("bar", claims2.object.get("foo").?.string);

}

test "SigningMethodRS256 Check fail" {
    const alloc = std.heap.page_allocator;

    const pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";
    const token_str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.EhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg";

    const pubkey_bytes = try utils.base64Decode(alloc, pubkey);
    const public_key = try crypto_rsa.PublicKey.fromDer(pubkey_bytes);

    const p = SigningMethodRS256.init(alloc);

    var need_true: bool = false;
    _ = p.parse(token_str, public_key) catch |err| {
        need_true = true;
        try testing.expectEqual(Error.JWTVerifyFail, err);
    };
    try testing.expectEqual(true, need_true);

}

test "SigningMethodPS256 Check" {
    const alloc = std.heap.page_allocator;

    const pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";
    const token_str = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.PPG4xyDVY8ffp4CcxofNmsTDXsrVG2npdQuibLhJbv4ClyPTUtR5giNSvuxo03kB6I8VXVr0Y9X7UxhJVEoJOmULAwRWaUsDnIewQa101cVhMa6iR8X37kfFoiZ6NkS-c7henVkkQWu2HtotkEtQvN5hFlk8IevXXPmvZlhQhwzB1sGzGYnoi1zOfuL98d3BIjUjtlwii5w6gYG2AEEzp7HnHCsb3jIwUPdq86Oe6hIFjtBwduIK90ca4UqzARpcfwxHwVLMpatKask00AgGVI0ysdk0BLMjmLutquD03XbThHScC2C2_Pp4cHWgMzvbgLU2RYYZcZRKr46QeNgz9w";

    const pubkey_bytes = try utils.base64Decode(alloc, pubkey);
    const public_key = try crypto_rsa.PublicKey.fromDer(pubkey_bytes);

    const p = SigningMethodPS256.init(alloc);
    var parsed = try p.parse(token_str, public_key);

    const claims2 = try parsed.getClaims();
    try testing.expectEqualStrings("bar", claims2.object.get("foo").?.string);

}

test "SigningMethodPS384 Check" {
    const alloc = std.heap.page_allocator;

    const pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";
    const token_str = "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.w7-qqgj97gK4fJsq_DCqdYQiylJjzWONvD0qWWWhqEOFk2P1eDULPnqHRnjgTXoO4HAw4YIWCsZPet7nR3Xxq4ZhMqvKW8b7KlfRTb9cH8zqFvzMmybQ4jv2hKc3bXYqVow3AoR7hN_CWXI3Dv6Kd2X5xhtxRHI6IL39oTVDUQ74LACe-9t4c3QRPuj6Pq1H4FAT2E2kW_0KOc6EQhCLWEhm2Z2__OZskDC8AiPpP8Kv4k2vB7l0IKQu8Pr4RcNBlqJdq8dA5D3hk5TLxP8V5nG1Ib80MOMMqoS3FQvSLyolFX-R_jZ3-zfq6Ebsqr0yEb0AH2CfsECF7935Pa0FKQ";

    const pubkey_bytes = try utils.base64Decode(alloc, pubkey);
    const public_key = try crypto_rsa.PublicKey.fromDer(pubkey_bytes);

    const p = SigningMethodPS384.init(alloc);
    var parsed = try p.parse(token_str, public_key);

    const claims2 = try parsed.getClaims();
    try testing.expectEqualStrings("bar", claims2.object.get("foo").?.string);

}

test "SigningMethodPS512 Check" {
    const alloc = std.heap.page_allocator;

    const pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";
    const token_str = "eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.GX1HWGzFaJevuSLavqqFYaW8_TpvcjQ8KfC5fXiSDzSiT9UD9nB_ikSmDNyDILNdtjZLSvVKfXxZJqCfefxAtiozEDDdJthZ-F0uO4SPFHlGiXszvKeodh7BuTWRI2wL9-ZO4mFa8nq3GMeQAfo9cx11i7nfN8n2YNQ9SHGovG7_T_AvaMZB_jT6jkDHpwGR9mz7x1sycckEo6teLdHRnH_ZdlHlxqknmyTu8Odr5Xh0sJFOL8BepWbbvIIn-P161rRHHiDWFv6nhlHwZnVzjx7HQrWSGb6-s2cdLie9QL_8XaMcUpjLkfOMKkDOfHo6AvpL7Jbwi83Z2ZTHjJWB-A";

    const pubkey_bytes = try utils.base64Decode(alloc, pubkey);
    const public_key = try crypto_rsa.PublicKey.fromDer(pubkey_bytes);

    const p = SigningMethodPS512.init(alloc);
    var parsed = try p.parse(token_str, public_key);

    const claims2 = try parsed.getClaims();
    try testing.expectEqualStrings("bar", claims2.object.get("foo").?.string);

}

test "SigningMethodPS256 Check fail" {
    const alloc = std.heap.page_allocator;

    const pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";
    const token_str = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.PPG4xyDVY8ffp4CcxofNmsTDXsrVG2npdQuibLhJbv4ClyPTUtR5giNSvuxo03kB6I8VXVr0Y9X7UxhJVEoJOmULAwRWaUsDnIewQa101cVhMa6iR8X37kfFoiZ6NkS-c7henVkkQWu2HtotkEtQvN5hFlk8IevXXPmvZlhQhwzB1sGzGYnoi1zOfuL98d3BIjUjtlwii5w6gYG2AEEzp7HnHCsb3jIwUPdq86Oe6hIFjtBwduIK90ca4UqzARpcfwxHwVLMpatKask00AgGVI0ysdk0BLMjmLutquD03XbThHScC2C2_Pp4cHWgMzvbgLU2RYYZcZRKr46QeNgz9W";

    const pubkey_bytes = try utils.base64Decode(alloc, pubkey);
    const public_key = try crypto_rsa.PublicKey.fromDer(pubkey_bytes);

    const p = SigningMethodPS256.init(alloc);

    var need_true: bool = false;
    _ = p.parse(token_str, public_key) catch |err| {
        need_true = true;
        try testing.expectEqual(Error.JWTVerifyFail, err);
    };
    try testing.expectEqual(true, need_true);

}
