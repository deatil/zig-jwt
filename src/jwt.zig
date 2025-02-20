const std = @import("std");
const fmt = std.fmt;
const testing = std.testing;
const Allocator = std.mem.Allocator;

pub const ecdsa = @import("ecdsa.zig");
pub const eddsa = @import("eddsa.zig");
pub const hmac = @import("hmac.zig");
pub const none = @import("none.zig");
pub const token = @import("token.zig");
pub const utils = @import("utils.zig");

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
    JWTSignatureInvalid,
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

            const header = try t.getHeader();
            if (!eq(header.typ, "JWT")) {
                return Error.JWTTypeInvalid;
            }
            if (!eq(header.alg, self.signer.alg())) {
                return Error.JWTAlgoInvalid;
            }

            const token_sign = t.getSignature();

            const sign_length = self.signer.signLength();
            if (token_sign.len != sign_length) {
                return Error.JWTSignatureInvalid;
            }

            var sign: [self.signer.signLength()]u8 = undefined;
            @memcpy(sign[0..], token_sign);
    
            const msg = try t.signingString();
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

    return Error.JWTSigningMethodNotExists;
}

pub fn getTokenHeader(alloc: Allocator, token_string: []const u8) !token.Token.Header {
    var t = token.Token.init(alloc);
    try t.parse(token_string);

    const header = try t.getHeader();
    return header;
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

    const kp = eddsa.Ed25519.KeyPair.generate();

    const token_string = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJleGFtcGxlLmNvbSIsImlhdCI6ImZvbyJ9.dGVzdC1zaWduYXR1cmU";

    const p = SigningMethodEdDSA.init(alloc);

    var need_true: bool = false;
    _ = p.parse(token_string, kp.public_key) catch |err| {
        need_true = true;
        try testing.expectEqual(Error.JWTAlgoInvalid, err);
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
    const token_string = try s.make(claims, secret_key);
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
    const token_string = try s.make(claims, secret_key);
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
        try testing.expectEqual(Error.JWTSignatureInvalid, err);
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
    const token_string = try s.make(claims, secret_key);
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
    const token_string = try s.make(claims, key_bytes);
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
    const token_string = try s.make(claims, key_bytes);
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
    const token_string = try s.make(claims, key_bytes);
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
