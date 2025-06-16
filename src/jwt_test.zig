const std = @import("std");
const fmt = std.fmt;
const time = std.time;
const testing = std.testing;

const jwt = @import("jwt.zig");

test "getSigningMethod" {
    try testing.expectEqual(jwt.SigningMethodRS256, try jwt.getSigningMethod("RS256"));
    try testing.expectEqual(jwt.SigningMethodRS384, try jwt.getSigningMethod("RS384"));
    try testing.expectEqual(jwt.SigningMethodRS512, try jwt.getSigningMethod("RS512"));

    try testing.expectEqual(jwt.SigningMethodPS256, try jwt.getSigningMethod("PS256"));
    try testing.expectEqual(jwt.SigningMethodPS384, try jwt.getSigningMethod("PS384"));
    try testing.expectEqual(jwt.SigningMethodPS512, try jwt.getSigningMethod("PS512"));

    try testing.expectEqual(jwt.SigningMethodES256, try jwt.getSigningMethod("ES256"));
    try testing.expectEqual(jwt.SigningMethodES384, try jwt.getSigningMethod("ES384"));

    try testing.expectEqual(jwt.SigningMethodES256K, try jwt.getSigningMethod("ES256K"));

    try testing.expectEqual(jwt.SigningMethodEdDSA, try jwt.getSigningMethod("EdDSA"));
    try testing.expectEqual(jwt.SigningMethodED25519, try jwt.getSigningMethod("ED25519"));

    try testing.expectEqual(jwt.SigningMethodHMD5, try jwt.getSigningMethod("HMD5"));
    try testing.expectEqual(jwt.SigningMethodHSHA1, try jwt.getSigningMethod("HSHA1"));
    try testing.expectEqual(jwt.SigningMethodHS224, try jwt.getSigningMethod("HS224"));
    try testing.expectEqual(jwt.SigningMethodHS256, try jwt.getSigningMethod("HS256"));
    try testing.expectEqual(jwt.SigningMethodHS384, try jwt.getSigningMethod("HS384"));
    try testing.expectEqual(jwt.SigningMethodHS512, try jwt.getSigningMethod("HS512"));

    try testing.expectEqual(jwt.SigningMethodBLAKE2B, try jwt.getSigningMethod("BLAKE2B"));

    try testing.expectEqual(jwt.SigningMethodNone, try jwt.getSigningMethod("none"));

    var need_true: bool = false;
    jwt.getSigningMethod("HS258") catch |err| {
        need_true = true;
        try testing.expectEqual(jwt.Error.JWTSigningMethodNotExists, err);
    };
    try testing.expectEqual(true, need_true);
}

test "parse JWTTypeInvalid" {
    const alloc = testing.allocator;

    const kp = jwt.eddsa.Ed25519.KeyPair.generate();

    const token_string = "eyJ0eXAiOiJKV0UiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJleGFtcGxlLmNvbSIsImlhdCI6ImZvbyJ9.dGVzdC1zaWduYXR1cmU";

    const p = jwt.SigningMethodEdDSA.init(alloc);

    var need_true: bool = false;
    _ = p.parse(token_string, kp.public_key) catch |err| {
        need_true = true;
        try testing.expectEqual(jwt.Error.JWTTypeInvalid, err);
    };
    try testing.expectEqual(true, need_true);
}

test "parse JWTSignatureInvalid" {
    const alloc = testing.allocator;

    const kp = jwt.ecdsa.ecdsa.EcdsaP256Sha256.KeyPair.generate();

    const token_string = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJleGFtcGxlLmNvbSIsImlhdCI6ImZvbyJ9.dGVzdC1zaWduYXR1cmU";

    const p = jwt.SigningMethodES256.init(alloc);

    var need_true: bool = false;
    _ = p.parse(token_string, kp.public_key) catch |err| {
        need_true = true;
        try testing.expectEqual(jwt.Error.JWTVerifyFail, err);
    };
    try testing.expectEqual(true, need_true);
}

test "Token Validator" {
    const alloc = testing.allocator;

    const check1 = "eyJ0eXAiOiJKV0UiLCJhbGciOiJFUzI1NiIsImtpZCI6ImtpZHMifQ.eyJpc3MiOiJpc3MiLCJpYXQiOjE1Njc4NDIzODgsImV4cCI6MTc2Nzg0MjM4OCwiYXVkIjoiZXhhbXBsZS5jb20iLCJzdWIiOiJzdWIiLCJqdGkiOiJqdGkgcnJyIiwibmJmIjoxNTY3ODQyMzg4fQ.dGVzdC1zaWduYXR1cmU";
    const now = time.timestamp();

    var token = jwt.Token.init(alloc);
    token.parse(check1);

    var validator = try jwt.Validator.init(token);
    defer validator.deinit();

    try testing.expectEqual(true, validator.hasBeenIssuedBy("iss"));
    try testing.expectEqual(true, validator.isRelatedTo("sub"));
    try testing.expectEqual(true, validator.isIdentifiedBy("jti rrr"));
    try testing.expectEqual(true, validator.isPermittedFor("example.com"));
    try testing.expectEqual(true, validator.hasBeenIssuedBefore(now));

    const claims = try token.getClaims();
    defer claims.deinit();
    try testing.expectEqual(true, claims.value.object.get("nbf").?.integer > 0);
}

test "SigningMethodEdDSA builder" {
    const alloc = testing.allocator;

    const kp = jwt.eddsa.Ed25519.KeyPair.generate();

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    var build = jwt.SigningMethodEdDSA.init(alloc).build();
    defer build.deinit();

    var c = build.claimsData();
    defer c.deinit();

    try c.begin();
    try c.permittedFor(claims.aud);
    try c.relatedTo(claims.sub);
    try c.end();

    var t = try build.getToken(kp.secret_key);
    defer t.deinit();

    const token_string = try t.signedString();
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = jwt.SigningMethodEdDSA.init(alloc);
    var parsed = try p.parse(token_string, kp.public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.value.object.get("sub").?.string);
}

test "SigningMethodEdDSA signWithHeader" {
    const alloc = testing.allocator;

    const kp = jwt.eddsa.Ed25519.KeyPair.generate();

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    const s = jwt.SigningMethodEdDSA.init(alloc);

    const header = .{
        .typ = "JWT",
        .alg = s.alg(),
        .tuy = "data123",
    };

    const token_string = try s.signWithHeader(header, claims, kp.secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);
    try testing.expectEqualStrings("EdDSA", header.alg);

    // ==========

    const p = jwt.SigningMethodEdDSA.init(alloc);
    var parsed = try p.parse(token_string, kp.public_key);
    defer parsed.deinit();

    const header2 = try parsed.getHeaderValue();
    defer header2.deinit();
    try testing.expectEqualStrings(header.typ, header2.value.object.get("typ").?.string);
    try testing.expectEqualStrings(header.alg, header2.value.object.get("alg").?.string);
    try testing.expectEqualStrings(header.tuy, header2.value.object.get("tuy").?.string);

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.value.object.get("sub").?.string);

    // ==========

    try testing.expectEqual(64, s.signLength());
    try testing.expectEqualStrings("EdDSA", s.alg());
}

test "SigningMethodEdDSA" {
    const alloc = testing.allocator;

    const kp = jwt.eddsa.Ed25519.KeyPair.generate();

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    const s = jwt.SigningMethodEdDSA.init(alloc);
    const token_string = try s.sign(claims, kp.secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = jwt.SigningMethodEdDSA.init(alloc);
    var parsed = try p.parse(token_string, kp.public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.value.object.get("sub").?.string);
}

test "SigningMethodES256" {
    const alloc = testing.allocator;

    const kp = jwt.ecdsa.ecdsa.EcdsaP256Sha256.KeyPair.generate();

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    const s = jwt.SigningMethodES256.init(alloc);
    const token_string = try s.sign(claims, kp.secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = jwt.SigningMethodES256.init(alloc);
    var parsed = try p.parse(token_string, kp.public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.value.object.get("sub").?.string);
}

test "SigningMethodES384" {
    const alloc = testing.allocator;

    const kp = jwt.ecdsa.ecdsa.EcdsaP384Sha384.KeyPair.generate();

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    const s = jwt.SigningMethodES384.init(alloc);
    const token_string = try s.sign(claims, kp.secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = jwt.SigningMethodES384.init(alloc);
    var parsed = try p.parse(token_string, kp.public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.value.object.get("sub").?.string);
}

test "SigningMethodES256K" {
    const alloc = testing.allocator;

    const kp = jwt.ecdsa.ecdsa.EcdsaSecp256k1Sha256.KeyPair.generate();

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    const s = jwt.SigningMethodES256K.init(alloc);
    const token_string = try s.sign(claims, kp.secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = jwt.SigningMethodES256K.init(alloc);
    var parsed = try p.parse(token_string, kp.public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.value.object.get("sub").?.string);
}

test "SigningMethodHMD5" {
    const alloc = testing.allocator;

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };
    const key = "test-key";

    const s = jwt.SigningMethodHMD5.init(alloc);
    const token_string = try s.sign(claims, key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = jwt.SigningMethodHMD5.init(alloc);
    var parsed = try p.parse(token_string, key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.value.object.get("sub").?.string);
}

test "SigningMethodHSHA1" {
    const alloc = testing.allocator;

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };
    const key = "test-key";

    const s = jwt.SigningMethodHSHA1.init(alloc);
    const token_string = try s.sign(claims, key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = jwt.SigningMethodHSHA1.init(alloc);
    var parsed = try p.parse(token_string, key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.value.object.get("sub").?.string);
}

test "SigningMethodHS224" {
    const alloc = testing.allocator;

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };
    const key = "test-key";

    const s = jwt.SigningMethodHS224.init(alloc);
    const token_string = try s.sign(claims, key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = jwt.SigningMethodHS224.init(alloc);
    var parsed = try p.parse(token_string, key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.value.object.get("sub").?.string);
}

test "SigningMethodHS256" {
    const alloc = testing.allocator;

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };
    const key = "test-key";

    const s = jwt.SigningMethodHS256.init(alloc);
    const token_string = try s.sign(claims, key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = jwt.SigningMethodHS256.init(alloc);
    var parsed = try p.parse(token_string, key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.value.object.get("sub").?.string);
}

test "SigningMethodHS384" {
    const alloc = testing.allocator;

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };
    const key = "test-key";

    const s = jwt.SigningMethodHS384.init(alloc);
    const token_string = try s.sign(claims, key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = jwt.SigningMethodHS384.init(alloc);
    var parsed = try p.parse(token_string, key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.value.object.get("sub").?.string);
}

test "SigningMethodHS512" {
    const alloc = testing.allocator;

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };
    const key = "test-key";

    const s = jwt.SigningMethodHS512.init(alloc);
    const token_string = try s.sign(claims, key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = jwt.SigningMethodHS512.init(alloc);
    var parsed = try p.parse(token_string, key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.value.object.get("sub").?.string);
}

test "SigningMethodBLAKE2B" {
    const alloc = testing.allocator;

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };
    const key = "12345678901234567890as1234567890";

    const s = jwt.SigningMethodBLAKE2B.init(alloc);
    const token_string = try s.sign(claims, key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = jwt.SigningMethodBLAKE2B.init(alloc);
    var parsed = try p.parse(token_string, key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.value.object.get("sub").?.string);
}

test "SigningMethodNone" {
    const alloc = testing.allocator;

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };
    const key = "";

    const s = jwt.SigningMethodNone.init(alloc);
    const token_string = try s.sign(claims, key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = jwt.SigningMethodNone.init(alloc);
    var parsed = try p.parse(token_string, key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.value.object.get("sub").?.string);
}

test "use JWTClaims to json" {
    const alloc = testing.allocator;

    const msg = jwt.JWTClaims{
        .iss = "test-data",
    };
    const check = "{\"iss\":\"test-data\"}";

    const res = try jwt.utils.jsonEncode(alloc, msg);
    defer alloc.free(res);
    try testing.expectEqualStrings(check, res);
}

test "SigningMethodES256 Check" {
    const alloc = testing.allocator;

    const pub_key = "04603e7857fbe9fb9e0ff435daad8ab1e0c3dc9be1ca44843335ab184a84501d0ffa4ba3ecf2da4c713f8abc8202f16fdef64d16ec29bbd8cd4ff6353b48b7ffbe";
    const pri_key = "603e7857fbe9fb9e0ff435daad8ab1e0c3dc9be1ca44843335ab184a84501d0f";
    const token_str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.feG39E-bn8HXAKhzDZq7yEAPWYDhZlwTn3sePJnU9VrGMmwdXAIEyoOnrjreYlVM_Z4N13eK9-TmMTWyfKJtHQ";

    const encoded_length = jwt.ecdsa.ecdsa.EcdsaP256Sha256.SecretKey.encoded_length;

    var pri_key_buf: [encoded_length]u8 = undefined;
    _ = try fmt.hexToBytes(&pri_key_buf, pri_key);

    var pub_key_buf: [pub_key.len / 2]u8 = undefined;
    const pub_key_bytes = try fmt.hexToBytes(&pub_key_buf, pub_key);

    const secret_key = try jwt.ecdsa.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(pri_key_buf);
    const public_key = try jwt.ecdsa.ecdsa.EcdsaP256Sha256.PublicKey.fromSec1(pub_key_bytes);

    const claims = .{
        .foo = "bar",
    };

    const s = jwt.SigningMethodES256.init(alloc);
    const token_string = try s.sign(claims, secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = jwt.SigningMethodES256.init(alloc);
    var parsed = try p.parse(token_str, public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.foo, claims2.value.object.get("foo").?.string);
}

test "SigningMethodES384 Check" {
    const alloc = testing.allocator;

    const pub_key = "04d86bbac9694edf78b32aac0c7a69d6453503a96941ff53295b64bae238b38de58155c2d554a4ed457c45d9508429a6d44fb5ce62c483d8eb9f3284149bea2adf2095123fd6984df94918a93f98390ae2df26581ce1883e41ea383d7041a11a00";
    const pri_key = "d86bbac9694edf78b32aac0c7a69d6453503a96941ff53295b64bae238b38de58155c2d554a4ed457c45d9508429a6d4";
    const token_str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCJ9.eyJmb28iOiJiYXIifQ.ngAfKMbJUh0WWubSIYe5GMsA-aHNKwFbJk_wq3lq23aPp8H2anb1rRILIzVR0gUf4a8WzDtrzmiikuPWyCS6CN4-PwdgTk-5nehC7JXqlaBZU05p3toM3nWCwm_LXcld";

    const encoded_length = jwt.ecdsa.ecdsa.EcdsaP384Sha384.SecretKey.encoded_length;

    var pri_key_buf: [encoded_length]u8 = undefined;
    _ = try fmt.hexToBytes(&pri_key_buf, pri_key);

    var pub_key_buf: [pub_key.len / 2]u8 = undefined;
    const pub_key_bytes = try fmt.hexToBytes(&pub_key_buf, pub_key);

    const secret_key = try jwt.ecdsa.ecdsa.EcdsaP384Sha384.SecretKey.fromBytes(pri_key_buf);
    const public_key = try jwt.ecdsa.ecdsa.EcdsaP384Sha384.PublicKey.fromSec1(pub_key_bytes);

    const claims = .{
        .foo = "bar",
    };

    const s = jwt.SigningMethodES384.init(alloc);
    const token_string = try s.sign(claims, secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = jwt.SigningMethodES384.init(alloc);
    var parsed = try p.parse(token_str, public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.foo, claims2.value.object.get("foo").?.string);
}

test "SigningMethodES256 Check fail" {
    const alloc = testing.allocator;

    const pub_key = "04603e7857fbe9fb9e0ff435daad8ab1e0c3dc9be1ca44843335ab184a84501d0ffa4ba3ecf2da4c713f8abc8202f16fdef64d16ec29bbd8cd4ff6353b48b7ffbe";
    const token_str = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.MEQCIHoSJnmGlPaVQDqacx_2XlXEhhqtWceVopjomc2PJLtdAiAUTeGPoNYxZw0z8mgOnnIcjoxRuNDVZvybRZF3wR1l8W";

    var pub_key_buf: [pub_key.len / 2]u8 = undefined;
    const pub_key_bytes = try fmt.hexToBytes(&pub_key_buf, pub_key);

    const public_key = try jwt.ecdsa.ecdsa.EcdsaP256Sha256.PublicKey.fromSec1(pub_key_bytes);

    const p = jwt.SigningMethodES256.init(alloc);

    var need_true: bool = false;
    _ = p.parse(token_str, public_key) catch |err| {
        need_true = true;
        try testing.expectEqual(jwt.Error.JWTVerifyFail, err);
    };
    try testing.expectEqual(true, need_true);
}

test "SigningMethodES256K Check" {
    const alloc = testing.allocator;

    const pub_key = "04cbcc2ebfaf9f5e874b3cb7e1c66d77db2d51f26e1d92783bb477bb37eb142d5d84b61e80c445d07ddf84e27b9c791db550d0af40aab1898c02cd5c0829c1defc";
    const pri_key = "c4e29dedecf2d4fef1bb300cce3fcfca3ec086066fd3d03ebc3cc7a36ee900dd";
    const token_str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJmb28iOiJiYXIifQ.Xe92dmU8MrI1d4edE2LEKqSmObZJpkIuz0fERihfn65ikTeeX5zjpyAdlHy9ZSBX8N8sqmJy5fxBTBzV26WvIQ";

    const encoded_length = jwt.ecdsa.ecdsa.EcdsaSecp256k1Sha256.SecretKey.encoded_length;

    var pri_key_buf: [encoded_length]u8 = undefined;
    _ = try fmt.hexToBytes(&pri_key_buf, pri_key);

    var pub_key_buf: [pub_key.len / 2]u8 = undefined;
    const pub_key_bytes = try fmt.hexToBytes(&pub_key_buf, pub_key);

    const secret_key = try jwt.ecdsa.ecdsa.EcdsaSecp256k1Sha256.SecretKey.fromBytes(pri_key_buf);
    const public_key = try jwt.ecdsa.ecdsa.EcdsaSecp256k1Sha256.PublicKey.fromSec1(pub_key_bytes);

    const claims = .{
        .foo = "bar",
    };

    const s = jwt.SigningMethodES256K.init(alloc);
    const token_string = try s.sign(claims, secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = jwt.SigningMethodES256K.init(alloc);
    var parsed = try p.parse(token_str, public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.foo, claims2.value.object.get("foo").?.string);
}

test "SigningMethodEdDSA Check" {
    const alloc = testing.allocator;

    const pub_key = "587ef3ea1a58aaf3e7b368b89fdcb29b0bc1dc03e18b82f243b887393e9caed1";
    const pri_key = "414c119ae6958c5ccd7285c4894dbcd191e4942f0e14e42e8bc9631c10777b9a587ef3ea1a58aaf3e7b368b89fdcb29b0bc1dc03e18b82f243b887393e9caed1";
    const token_str = "eyJhbGciOiJFRDI1NTE5IiwidHlwIjoiSldUIn0.eyJmb28iOiJiYXIifQ.ESuVzZq1cECrt9Od_gLPVG-_6uRP_8Nq-ajx6CtmlDqRJZqdejro2ilkqaQgSL-siE_3JMTUW7UwAorLaTyFCw";

    const encoded_length = jwt.eddsa.Ed25519.SecretKey.encoded_length;
    const encoded_length2 = jwt.eddsa.Ed25519.PublicKey.encoded_length;

    var pri_key_buf: [encoded_length]u8 = undefined;
    _ = try fmt.hexToBytes(&pri_key_buf, pri_key);

    var pub_key_buf: [encoded_length2]u8 = undefined;
    _ = try fmt.hexToBytes(&pub_key_buf, pub_key);

    const secret_key = try jwt.eddsa.Ed25519.SecretKey.fromBytes(pri_key_buf);
    const public_key = try jwt.eddsa.Ed25519.PublicKey.fromBytes(pub_key_buf);

    const claims = .{
        .foo = "bar",
    };

    const s = jwt.SigningMethodED25519.init(alloc);
    const token_string = try s.sign(claims, secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = jwt.SigningMethodED25519.init(alloc);
    var parsed = try p.parse(token_str, public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.foo, claims2.value.object.get("foo").?.string);
}

test "SigningMethodEdDSA Check fail" {
    const alloc = testing.allocator;

    const pub_key = "587ef3ea1a58aaf3e7b368b89fdcb29b0bc1dc03e18b82f243b887393e9caed1";
    const token_str = "eyJhbGciOiJFRDI1NTE5IiwidHlwIjoiSldUIn0.eyJmb28iOiJiYXoifQ.ESuVzZq1cECrt9Od_gLPVG-_6uRP_8Nq-ajx6CtmlDqRJZqdejro2ilkqaQgSL-siE_3JMTUW7UwAorLaTyFCw";

    const encoded_length2 = jwt.eddsa.Ed25519.PublicKey.encoded_length;

    var pub_key_buf: [encoded_length2]u8 = undefined;
    _ = try fmt.hexToBytes(&pub_key_buf, pub_key);

    const public_key = try jwt.eddsa.Ed25519.PublicKey.fromBytes(pub_key_buf);

    const p = jwt.SigningMethodED25519.init(alloc);

    var need_true: bool = false;
    _ = p.parse(token_str, public_key) catch |err| {
        need_true = true;
        try testing.expectEqual(jwt.Error.JWTVerifyFail, err);
    };
    try testing.expectEqual(true, need_true);
}

test "SigningMethodHS256 Check" {
    const alloc = testing.allocator;

    const key = "0323354b2b0fa5bc837e0665777ba68f5ab328e6f054c928a90f84b2d2502ebfd3fb5a92d20647ef968ab4c377623d223d2e2172052e4f08c0cd9af567d080a3";
    const token_str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    var key_buf: [key.len]u8 = undefined;
    const key_bytes = try fmt.hexToBytes(&key_buf, key);

    const claims = .{
        .iss = "joe",
        .exp = 1300819380,
        .@"http://example.com/is_root" = true,
    };

    const s = jwt.SigningMethodHS256.init(alloc);
    const token_string = try s.sign(claims, key_bytes);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = jwt.SigningMethodHS256.init(alloc);
    var parsed = try p.parse(token_str, key_bytes);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.iss, claims2.value.object.get("iss").?.string);
}

test "SigningMethodHS384 Check" {
    const alloc = testing.allocator;

    const key = "0323354b2b0fa5bc837e0665777ba68f5ab328e6f054c928a90f84b2d2502ebfd3fb5a92d20647ef968ab4c377623d223d2e2172052e4f08c0cd9af567d080a3";
    const token_str = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJleHAiOjEuMzAwODE5MzhlKzA5LCJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZSwiaXNzIjoiam9lIn0.KWZEuOD5lbBxZ34g7F-SlVLAQ_r5KApWNWlZIIMyQVz5Zs58a7XdNzj5_0EcNoOy";

    var key_buf: [key.len]u8 = undefined;
    const key_bytes = try fmt.hexToBytes(&key_buf, key);

    const claims = .{
        .iss = "joe",
        .exp = 1300819380,
        .@"http://example.com/is_root" = true,
    };

    const s = jwt.SigningMethodHS384.init(alloc);
    const token_string = try s.sign(claims, key_bytes);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = jwt.SigningMethodHS384.init(alloc);
    var parsed = try p.parse(token_str, key_bytes);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.iss, claims2.value.object.get("iss").?.string);
}

test "SigningMethodHS512 Check" {
    const alloc = testing.allocator;

    const key = "0323354b2b0fa5bc837e0665777ba68f5ab328e6f054c928a90f84b2d2502ebfd3fb5a92d20647ef968ab4c377623d223d2e2172052e4f08c0cd9af567d080a3";
    const token_str = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEuMzAwODE5MzhlKzA5LCJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZSwiaXNzIjoiam9lIn0.CN7YijRX6Aw1n2jyI2Id1w90ja-DEMYiWixhYCyHnrZ1VfJRaFQz1bEbjjA5Fn4CLYaUG432dEYmSbS4Saokmw";

    var key_buf: [key.len]u8 = undefined;
    const key_bytes = try fmt.hexToBytes(&key_buf, key);

    const claims = .{
        .iss = "joe",
        .exp = 1300819380,
        .@"http://example.com/is_root" = true,
    };

    const s = jwt.SigningMethodHS512.init(alloc);
    const token_string = try s.sign(claims, key_bytes);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = jwt.SigningMethodHS512.init(alloc);
    var parsed = try p.parse(token_str, key_bytes);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.iss, claims2.value.object.get("iss").?.string);
}

test "SigningMethodHS256 Check fail" {
    const alloc = testing.allocator;

    const key = "0323354b2b0fa5bc837e0665777ba68f5ab328e6f054c928a90f84b2d2502ebfd3fb5a92d20647ef968ab4c377623d223d2e2172052e4f08c0cd9af567d080a3";
    const token_str = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXo";

    var key_buf: [key.len]u8 = undefined;
    const key_bytes = try fmt.hexToBytes(&key_buf, key);

    const p = jwt.SigningMethodHS256.init(alloc);

    var need_true: bool = false;
    _ = p.parse(token_str, key_bytes) catch |err| {
        need_true = true;
        try testing.expectEqual(jwt.Error.JWTVerifyFail, err);
    };
    try testing.expectEqual(true, need_true);
}

test "SigningMethodBLAKE2B Check" {
    const alloc = testing.allocator;

    const key = "0323354b2b0fa5bc837e0665777ba68f5ab328e6f054c928a90f84b2d2502ebfd3fb5a92d20647ef968ab4c377623d223d2e2172052e4f08c0cd9af567d080a3";
    const token_str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJCTEFLRTJCIn0.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.zVtM3_PWCeOBjiV3bJcx1KoxeZCUs7zqfy6DF2mfb9M";

    var key_buf: [key.len]u8 = undefined;
    const key_bytes = try fmt.hexToBytes(&key_buf, key);

    const claims = .{
        .iss = "joe",
        .exp = 1300819380,
        .@"http://example.com/is_root" = true,
    };

    const s = jwt.SigningMethodBLAKE2B.init(alloc);
    const token_string = try s.sign(claims, key_bytes);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);
    try testing.expectEqualStrings(token_str, token_string);

    // ==========

    const p = jwt.SigningMethodBLAKE2B.init(alloc);
    var parsed = try p.parse(token_str, key_bytes);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.iss, claims2.value.object.get("iss").?.string);
}

test "SigningMethodBLAKE2B Check fail" {
    const alloc = testing.allocator;

    const key = "0323354b2b0fa5bc837e0665777ba68f5ab328e6f054c928a90f84b2d2502ebfd3fb5a92d20647ef968ab4c377623d223d2e2172052e4f08c0cd9af567d080a3";
    const token_str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJCTEFLRTJCIn0.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.zVtM3_PWCeOBjiV3bJcx1KoxeZCUs7zqfy6DF2mfb12";

    var key_buf: [key.len]u8 = undefined;
    const key_bytes = try fmt.hexToBytes(&key_buf, key);

    const p = jwt.SigningMethodBLAKE2B.init(alloc);

    var need_true: bool = false;
    _ = p.parse(token_str, key_bytes) catch |err| {
        need_true = true;
        try testing.expectEqual(jwt.Error.JWTVerifyFail, err);
    };
    try testing.expectEqual(true, need_true);
}

test "getTokenHeader" {
    const alloc = testing.allocator;

    const token_str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.feG39E-bn8HXAKhzDZq7yEAPWYDhZlwTn3sePJnU9VrGMmwdXAIEyoOnrjreYlVM_Z4N13eK9-TmMTWyfKJtHQ";

    var header = try jwt.getTokenHeader(alloc, token_str);
    defer header.deinit(alloc);
    try testing.expectEqualStrings("ES256", header.alg);
}

test "SigningMethodES256 with JWTClaims" {
    const alloc = testing.allocator;

    const kp = jwt.ecdsa.ecdsa.EcdsaP256Sha256.KeyPair.generate();

    const claims: jwt.JWTClaims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    const s = jwt.SigningMethodES256.init(alloc);
    const token_string = try s.sign(claims, kp.secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = jwt.SigningMethodES256.init(alloc);
    var parsed = try p.parse(token_string, kp.public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud.?, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub.?, claims2.value.object.get("sub").?.string);
}

test "SigningMethodRS256" {
    const alloc = testing.allocator;

    const prikey = "MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAyMaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdEKdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gMIvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDnFcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvYmEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghjFuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+UI5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNTOvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL04aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0KcnckbmDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ryeBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq";
    const pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";

    const prikey_bytes = try jwt.utils.base64Decode(alloc, prikey);
    const pubkey_bytes = try jwt.utils.base64Decode(alloc, pubkey);

    defer alloc.free(prikey_bytes);
    defer alloc.free(pubkey_bytes);

    const secret_key = try jwt.crypto_rsa.SecretKey.fromDer(prikey_bytes);
    const public_key = try jwt.crypto_rsa.PublicKey.fromDer(pubkey_bytes);

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    const s = jwt.SigningMethodRS256.init(alloc);
    const token_string = try s.sign(claims, secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = jwt.SigningMethodRS256.init(alloc);
    var parsed = try p.parse(token_string, public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.value.object.get("sub").?.string);
}

test "SigningMethodRS384" {
    const alloc = testing.allocator;

    const prikey = "MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAyMaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdEKdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gMIvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDnFcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvYmEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghjFuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+UI5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNTOvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL04aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0KcnckbmDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ryeBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq";
    const pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";

    const prikey_bytes = try jwt.utils.base64Decode(alloc, prikey);
    const pubkey_bytes = try jwt.utils.base64Decode(alloc, pubkey);

    defer alloc.free(prikey_bytes);
    defer alloc.free(pubkey_bytes);

    const secret_key = try jwt.crypto_rsa.SecretKey.fromDer(prikey_bytes);
    const public_key = try jwt.crypto_rsa.PublicKey.fromDer(pubkey_bytes);

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    const s = jwt.SigningMethodRS384.init(alloc);
    const token_string = try s.sign(claims, secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = jwt.SigningMethodRS384.init(alloc);
    var parsed = try p.parse(token_string, public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.value.object.get("sub").?.string);
}

test "SigningMethodRS512" {
    const alloc = testing.allocator;

    const prikey = "MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAyMaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdEKdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gMIvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDnFcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvYmEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghjFuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+UI5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNTOvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL04aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0KcnckbmDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ryeBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq";
    const pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";

    const prikey_bytes = try jwt.utils.base64Decode(alloc, prikey);
    const pubkey_bytes = try jwt.utils.base64Decode(alloc, pubkey);

    defer alloc.free(prikey_bytes);
    defer alloc.free(pubkey_bytes);

    const secret_key = try jwt.crypto_rsa.SecretKey.fromDer(prikey_bytes);
    const public_key = try jwt.crypto_rsa.PublicKey.fromDer(pubkey_bytes);

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    const s = jwt.SigningMethodRS512.init(alloc);
    const token_string = try s.sign(claims, secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = jwt.SigningMethodRS512.init(alloc);
    var parsed = try p.parse(token_string, public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.value.object.get("sub").?.string);
}

test "SigningMethodPS256" {
    const alloc = testing.allocator;

    const prikey = "MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAyMaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdEKdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gMIvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDnFcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvYmEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghjFuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+UI5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNTOvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL04aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0KcnckbmDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ryeBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq";
    const pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";

    const prikey_bytes = try jwt.utils.base64Decode(alloc, prikey);
    const pubkey_bytes = try jwt.utils.base64Decode(alloc, pubkey);

    defer alloc.free(prikey_bytes);
    defer alloc.free(pubkey_bytes);

    const secret_key = try jwt.crypto_rsa.SecretKey.fromDer(prikey_bytes);
    const public_key = try jwt.crypto_rsa.PublicKey.fromDer(pubkey_bytes);

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    const s = jwt.SigningMethodPS256.init(alloc);
    const token_string = try s.sign(claims, secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = jwt.SigningMethodPS256.init(alloc);
    var parsed = try p.parse(token_string, public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.value.object.get("sub").?.string);
}

test "SigningMethodPS384" {
    const alloc = testing.allocator;

    const prikey = "MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAyMaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdEKdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gMIvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDnFcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvYmEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghjFuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+UI5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNTOvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL04aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0KcnckbmDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ryeBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq";
    const pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";

    const prikey_bytes = try jwt.utils.base64Decode(alloc, prikey);
    const pubkey_bytes = try jwt.utils.base64Decode(alloc, pubkey);

    defer alloc.free(prikey_bytes);
    defer alloc.free(pubkey_bytes);

    const secret_key = try jwt.crypto_rsa.SecretKey.fromDer(prikey_bytes);
    const public_key = try jwt.crypto_rsa.PublicKey.fromDer(pubkey_bytes);

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    const s = jwt.SigningMethodPS384.init(alloc);
    const token_string = try s.sign(claims, secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = jwt.SigningMethodPS384.init(alloc);
    var parsed = try p.parse(token_string, public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.value.object.get("sub").?.string);
}

test "SigningMethodPS512" {
    const alloc = testing.allocator;

    const prikey = "MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAyMaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdEKdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gMIvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDnFcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvYmEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghjFuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+UI5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNTOvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL04aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0KcnckbmDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ryeBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq";
    const pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";

    const prikey_bytes = try jwt.utils.base64Decode(alloc, prikey);
    const pubkey_bytes = try jwt.utils.base64Decode(alloc, pubkey);

    defer alloc.free(prikey_bytes);
    defer alloc.free(pubkey_bytes);

    const secret_key = try jwt.crypto_rsa.SecretKey.fromDer(prikey_bytes);
    const public_key = try jwt.crypto_rsa.PublicKey.fromDer(pubkey_bytes);

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    const s = jwt.SigningMethodPS512.init(alloc);
    const token_string = try s.sign(claims, secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = jwt.SigningMethodPS512.init(alloc);
    var parsed = try p.parse(token_string, public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.value.object.get("sub").?.string);
}

test "SigningMethodRS256 Check" {
    const alloc = testing.allocator;

    // check data from golang-jwt
    const pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";
    const token_str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg";

    const pubkey_bytes = try jwt.utils.base64Decode(alloc, pubkey);
    defer alloc.free(pubkey_bytes);

    const public_key = try jwt.crypto_rsa.PublicKey.fromDer(pubkey_bytes);

    const p = jwt.SigningMethodRS256.init(alloc);
    var parsed = try p.parse(token_str, public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings("bar", claims2.value.object.get("foo").?.string);
}

test "SigningMethodRS384 Check" {
    const alloc = testing.allocator;

    const pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";
    const token_str = "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.W-jEzRfBigtCWsinvVVuldiuilzVdU5ty0MvpLaSaqK9PlAWWlDQ1VIQ_qSKzwL5IXaZkvZFJXT3yL3n7OUVu7zCNJzdwznbC8Z-b0z2lYvcklJYi2VOFRcGbJtXUqgjk2oGsiqUMUMOLP70TTefkpsgqDxbRh9CDUfpOJgW-dU7cmgaoswe3wjUAUi6B6G2YEaiuXC0XScQYSYVKIzgKXJV8Zw-7AN_DBUI4GkTpsvQ9fVVjZM9csQiEXhYekyrKu1nu_POpQonGd8yqkIyXPECNmmqH5jH4sFiF67XhD7_JpkvLziBpI-uh86evBUadmHhb9Otqw3uV3NTaXLzJw";

    const pubkey_bytes = try jwt.utils.base64Decode(alloc, pubkey);
    defer alloc.free(pubkey_bytes);

    const public_key = try jwt.crypto_rsa.PublicKey.fromDer(pubkey_bytes);

    const p = jwt.SigningMethodRS384.init(alloc);
    var parsed = try p.parse(token_str, public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings("bar", claims2.value.object.get("foo").?.string);
}

test "SigningMethodRS512 Check" {
    const alloc = testing.allocator;

    const pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";
    const token_str = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.zBlLlmRrUxx4SJPUbV37Q1joRcI9EW13grnKduK3wtYKmDXbgDpF1cZ6B-2Jsm5RB8REmMiLpGms-EjXhgnyh2TSHE-9W2gA_jvshegLWtwRVDX40ODSkTb7OVuaWgiy9y7llvcknFBTIg-FnVPVpXMmeV_pvwQyhaz1SSwSPrDyxEmksz1hq7YONXhXPpGaNbMMeDTNP_1oj8DZaqTIL9TwV8_1wb2Odt_Fy58Ke2RVFijsOLdnyEAjt2n9Mxihu9i3PhNBkkxa2GbnXBfq3kzvZ_xxGGopLdHhJjcGWXO-NiwI9_tiu14NRv4L2xC0ItD9Yz68v2ZIZEp_DuzwRQ";

    const pubkey_bytes = try jwt.utils.base64Decode(alloc, pubkey);
    defer alloc.free(pubkey_bytes);

    const public_key = try jwt.crypto_rsa.PublicKey.fromDer(pubkey_bytes);

    const p = jwt.SigningMethodRS512.init(alloc);
    var parsed = try p.parse(token_str, public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings("bar", claims2.value.object.get("foo").?.string);
}

test "SigningMethodRS256 Check fail" {
    const alloc = testing.allocator;

    const pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";
    const token_str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.EhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg";

    const pubkey_bytes = try jwt.utils.base64Decode(alloc, pubkey);
    defer alloc.free(pubkey_bytes);

    const public_key = try jwt.crypto_rsa.PublicKey.fromDer(pubkey_bytes);

    const p = jwt.SigningMethodRS256.init(alloc);

    var need_true: bool = false;
    _ = p.parse(token_str, public_key) catch |err| {
        need_true = true;
        try testing.expectEqual(jwt.Error.JWTVerifyFail, err);
    };
    try testing.expectEqual(true, need_true);
}

test "SigningMethodPS256 Check" {
    const alloc = testing.allocator;

    const pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";
    const token_str = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.PPG4xyDVY8ffp4CcxofNmsTDXsrVG2npdQuibLhJbv4ClyPTUtR5giNSvuxo03kB6I8VXVr0Y9X7UxhJVEoJOmULAwRWaUsDnIewQa101cVhMa6iR8X37kfFoiZ6NkS-c7henVkkQWu2HtotkEtQvN5hFlk8IevXXPmvZlhQhwzB1sGzGYnoi1zOfuL98d3BIjUjtlwii5w6gYG2AEEzp7HnHCsb3jIwUPdq86Oe6hIFjtBwduIK90ca4UqzARpcfwxHwVLMpatKask00AgGVI0ysdk0BLMjmLutquD03XbThHScC2C2_Pp4cHWgMzvbgLU2RYYZcZRKr46QeNgz9w";

    const pubkey_bytes = try jwt.utils.base64Decode(alloc, pubkey);
    defer alloc.free(pubkey_bytes);

    const public_key = try jwt.crypto_rsa.PublicKey.fromDer(pubkey_bytes);

    const p = jwt.SigningMethodPS256.init(alloc);
    var parsed = try p.parse(token_str, public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings("bar", claims2.value.object.get("foo").?.string);
}

test "SigningMethodPS384 Check" {
    const alloc = testing.allocator;

    const pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";
    const token_str = "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.w7-qqgj97gK4fJsq_DCqdYQiylJjzWONvD0qWWWhqEOFk2P1eDULPnqHRnjgTXoO4HAw4YIWCsZPet7nR3Xxq4ZhMqvKW8b7KlfRTb9cH8zqFvzMmybQ4jv2hKc3bXYqVow3AoR7hN_CWXI3Dv6Kd2X5xhtxRHI6IL39oTVDUQ74LACe-9t4c3QRPuj6Pq1H4FAT2E2kW_0KOc6EQhCLWEhm2Z2__OZskDC8AiPpP8Kv4k2vB7l0IKQu8Pr4RcNBlqJdq8dA5D3hk5TLxP8V5nG1Ib80MOMMqoS3FQvSLyolFX-R_jZ3-zfq6Ebsqr0yEb0AH2CfsECF7935Pa0FKQ";

    const pubkey_bytes = try jwt.utils.base64Decode(alloc, pubkey);
    defer alloc.free(pubkey_bytes);

    const public_key = try jwt.crypto_rsa.PublicKey.fromDer(pubkey_bytes);

    const p = jwt.SigningMethodPS384.init(alloc);
    var parsed = try p.parse(token_str, public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings("bar", claims2.value.object.get("foo").?.string);
}

test "SigningMethodPS512 Check" {
    const alloc = testing.allocator;

    const pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";
    const token_str = "eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.GX1HWGzFaJevuSLavqqFYaW8_TpvcjQ8KfC5fXiSDzSiT9UD9nB_ikSmDNyDILNdtjZLSvVKfXxZJqCfefxAtiozEDDdJthZ-F0uO4SPFHlGiXszvKeodh7BuTWRI2wL9-ZO4mFa8nq3GMeQAfo9cx11i7nfN8n2YNQ9SHGovG7_T_AvaMZB_jT6jkDHpwGR9mz7x1sycckEo6teLdHRnH_ZdlHlxqknmyTu8Odr5Xh0sJFOL8BepWbbvIIn-P161rRHHiDWFv6nhlHwZnVzjx7HQrWSGb6-s2cdLie9QL_8XaMcUpjLkfOMKkDOfHo6AvpL7Jbwi83Z2ZTHjJWB-A";

    const pubkey_bytes = try jwt.utils.base64Decode(alloc, pubkey);
    defer alloc.free(pubkey_bytes);

    const public_key = try jwt.crypto_rsa.PublicKey.fromDer(pubkey_bytes);

    const p = jwt.SigningMethodPS512.init(alloc);
    var parsed = try p.parse(token_str, public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings("bar", claims2.value.object.get("foo").?.string);
}

test "SigningMethodPS256 Check fail" {
    const alloc = testing.allocator;

    const pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";
    const token_str = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.PPG4xyDVY8ffp4CcxofNmsTDXsrVG2npdQuibLhJbv4ClyPTUtR5giNSvuxo03kB6I8VXVr0Y9X7UxhJVEoJOmULAwRWaUsDnIewQa101cVhMa6iR8X37kfFoiZ6NkS-c7henVkkQWu2HtotkEtQvN5hFlk8IevXXPmvZlhQhwzB1sGzGYnoi1zOfuL98d3BIjUjtlwii5w6gYG2AEEzp7HnHCsb3jIwUPdq86Oe6hIFjtBwduIK90ca4UqzARpcfwxHwVLMpatKask00AgGVI0ysdk0BLMjmLutquD03XbThHScC2C2_Pp4cHWgMzvbgLU2RYYZcZRKr46QeNgz9W";

    const pubkey_bytes = try jwt.utils.base64Decode(alloc, pubkey);
    defer alloc.free(pubkey_bytes);

    const public_key = try jwt.crypto_rsa.PublicKey.fromDer(pubkey_bytes);

    const p = jwt.SigningMethodPS256.init(alloc);

    var need_true: bool = false;
    _ = p.parse(token_str, public_key) catch |err| {
        need_true = true;
        try testing.expectEqual(jwt.Error.JWTVerifyFail, err);
    };
    try testing.expectEqual(true, need_true);
}

test "SigningMethodRS256 with pkcs8 key" {
    const alloc = testing.allocator;

    const prikey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDh/nCDmXaEqxN416b9XjV8acmbqA52uPzKbesWQRT/BPxEO2dKAURk5CkcSBDskvfzFR9TRjeDppjD1BPSEnuYKnP0SvmotoxcnBnHMfMBqGV8DSJyppu8k4y9C3MPq5C/rA8TJm0NNaJCL0BfAGkeyw+elgYifbRlm42VfYGsKVyIeEI9Qghk5Cf8yapMPfWNLKOhChXsyGExMBMonHZeseFH7UNwonNAFJMAaelhVqqmwBFqn6fBGKmvedRO7HIaiEFNKaMna6xJ5Bccjds4MhF7UC5PIdx4Bt7CfxvjrbIRYoBF2l30CNBblIhU992zPkHoaVhDkt1gq3OdO7LvAgMBAAECggEBALCJrWTv7ahnZ3efpqAIBuogTVBd8KaHjVmokds5jehFAbdfXClwYfgaT477MNVNXYmzN1w63sTl0DIxqiYRMCFHEHuGUg6cQ3tYqb50Y2spG9XTANTlF4UxEeDfX8ue7xz7kG8aNlf6TL084iEUVgmrAJGWikZJQjGZWPmtKC3OTeJY5Bev5qHVuMRe+XEM5aQc3ph+lXlOF0Qp0Eg8YRWprrev2faH6prMqu2JGomoac6sfM4QJhtEViF7Gw0XPthPTbF19IefuAwi9psMM/9CnQ+MTWN2i6IxoUdicsFuC+Wdlb3K5V/+uldNSr+ePEhcya+YTLK9IOcVwWKQHykCgYEA8XvuEribf+t0ZPtfxr+DC9nZHXbVoFx0/ARpSG+P/fp3Hn3rO9iYQ6OtZ9mEXTzf+dhYTaRWq6PbCOz6i0It+J8QSBdxU9OcQ4871mDe41IvSc1CCGMW4PeIYtNQEK0zrqhN7SMtKyUd7yAsYRCrIzMc7NjE2qJvFw5kh7xC3Q0CgYEA75Qjn5daNYSAOa/ILdOs5J/8oIaO27RNK/fSKm/btsMsyum8+YP/mWmm1MXBzG9WEKzZv5yEKOWCEVJYVsFQsGt9yLYW2WIKU5UxiuU0F1RImF/dphIbYOh7oGC3WfYKk2f+K7ftjc196ZkEkDuE2Xh1h75/67Mzztx1DbXj6OsCgYBcDRfFfyWXb5Og4smxo1M680H2H1RzmorlfnD7sbs733wE3Y8L8xanwf7Z9WqleA0Q2k1e22RGbWGTV3JyHzoS6d90+6qxf5qzjigLIkYUdUGdambfd5ZDD1ioA1Ej6kInM/TwjlYreiyc+LCyF36FHnjKOB9iEEU0jsH3k+YRCQKBgHMVLPuHX6zfhhyvxK/Gw4FbHKYbnNoKxRs+wvThoKAtJwIdv0n4TzppVttUV2CVhrkh3sM9MvrWLGGXtZmO6Oyl5dkZJuarQpydyRuYOCqQsQKI4lbY0c/+PQxwCQMsvi3KwXxMsM7yC+6/M0L5ZDp2s7ZOGvKktVlD6vJ4Eg+bAoGARnGGprSBW8dAb/s53r0paPh4k/bySrXdGEprLwk6g3S8+aylcmjUdjcIq4dEb4A/nv12dx1Sc4y99c62R0zi+TT6FYBIFDMz3HNVzO0Jr6SgC6CNVotL0D725CioR5U1NyTHHRLZth69HLuEZCZQlPJCbePXMRRHmOl1svzcVuo=";
    const pubkey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";

    const prikey_bytes = try jwt.utils.base64Decode(alloc, prikey);
    const pubkey_bytes = try jwt.utils.base64Decode(alloc, pubkey);

    defer alloc.free(prikey_bytes);
    defer alloc.free(pubkey_bytes);

    const secret_key = try jwt.crypto_rsa.SecretKey.fromPKCS8Der(prikey_bytes);
    const public_key = try jwt.crypto_rsa.PublicKey.fromPKCS8Der(pubkey_bytes);

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    const s = jwt.SigningMethodRS256.init(alloc);
    const token_string = try s.sign(claims, secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = jwt.SigningMethodRS256.init(alloc);
    var parsed = try p.parse(token_string, public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.value.object.get("sub").?.string);
}

test "SigningMethodPS256 with pkcs8 key" {
    const alloc = testing.allocator;

    const prikey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDh/nCDmXaEqxN416b9XjV8acmbqA52uPzKbesWQRT/BPxEO2dKAURk5CkcSBDskvfzFR9TRjeDppjD1BPSEnuYKnP0SvmotoxcnBnHMfMBqGV8DSJyppu8k4y9C3MPq5C/rA8TJm0NNaJCL0BfAGkeyw+elgYifbRlm42VfYGsKVyIeEI9Qghk5Cf8yapMPfWNLKOhChXsyGExMBMonHZeseFH7UNwonNAFJMAaelhVqqmwBFqn6fBGKmvedRO7HIaiEFNKaMna6xJ5Bccjds4MhF7UC5PIdx4Bt7CfxvjrbIRYoBF2l30CNBblIhU992zPkHoaVhDkt1gq3OdO7LvAgMBAAECggEBALCJrWTv7ahnZ3efpqAIBuogTVBd8KaHjVmokds5jehFAbdfXClwYfgaT477MNVNXYmzN1w63sTl0DIxqiYRMCFHEHuGUg6cQ3tYqb50Y2spG9XTANTlF4UxEeDfX8ue7xz7kG8aNlf6TL084iEUVgmrAJGWikZJQjGZWPmtKC3OTeJY5Bev5qHVuMRe+XEM5aQc3ph+lXlOF0Qp0Eg8YRWprrev2faH6prMqu2JGomoac6sfM4QJhtEViF7Gw0XPthPTbF19IefuAwi9psMM/9CnQ+MTWN2i6IxoUdicsFuC+Wdlb3K5V/+uldNSr+ePEhcya+YTLK9IOcVwWKQHykCgYEA8XvuEribf+t0ZPtfxr+DC9nZHXbVoFx0/ARpSG+P/fp3Hn3rO9iYQ6OtZ9mEXTzf+dhYTaRWq6PbCOz6i0It+J8QSBdxU9OcQ4871mDe41IvSc1CCGMW4PeIYtNQEK0zrqhN7SMtKyUd7yAsYRCrIzMc7NjE2qJvFw5kh7xC3Q0CgYEA75Qjn5daNYSAOa/ILdOs5J/8oIaO27RNK/fSKm/btsMsyum8+YP/mWmm1MXBzG9WEKzZv5yEKOWCEVJYVsFQsGt9yLYW2WIKU5UxiuU0F1RImF/dphIbYOh7oGC3WfYKk2f+K7ftjc196ZkEkDuE2Xh1h75/67Mzztx1DbXj6OsCgYBcDRfFfyWXb5Og4smxo1M680H2H1RzmorlfnD7sbs733wE3Y8L8xanwf7Z9WqleA0Q2k1e22RGbWGTV3JyHzoS6d90+6qxf5qzjigLIkYUdUGdambfd5ZDD1ioA1Ej6kInM/TwjlYreiyc+LCyF36FHnjKOB9iEEU0jsH3k+YRCQKBgHMVLPuHX6zfhhyvxK/Gw4FbHKYbnNoKxRs+wvThoKAtJwIdv0n4TzppVttUV2CVhrkh3sM9MvrWLGGXtZmO6Oyl5dkZJuarQpydyRuYOCqQsQKI4lbY0c/+PQxwCQMsvi3KwXxMsM7yC+6/M0L5ZDp2s7ZOGvKktVlD6vJ4Eg+bAoGARnGGprSBW8dAb/s53r0paPh4k/bySrXdGEprLwk6g3S8+aylcmjUdjcIq4dEb4A/nv12dx1Sc4y99c62R0zi+TT6FYBIFDMz3HNVzO0Jr6SgC6CNVotL0D725CioR5U1NyTHHRLZth69HLuEZCZQlPJCbePXMRRHmOl1svzcVuo=";
    const pubkey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";

    const prikey_bytes = try jwt.utils.base64Decode(alloc, prikey);
    const pubkey_bytes = try jwt.utils.base64Decode(alloc, pubkey);

    defer alloc.free(prikey_bytes);
    defer alloc.free(pubkey_bytes);

    const secret_key = try jwt.crypto_rsa.SecretKey.fromPKCS8Der(prikey_bytes);
    const public_key = try jwt.crypto_rsa.PublicKey.fromPKCS8Der(pubkey_bytes);

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    const s = jwt.SigningMethodPS256.init(alloc);
    const token_string = try s.sign(claims, secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = jwt.SigningMethodPS256.init(alloc);
    var parsed = try p.parse(token_string, public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.value.object.get("sub").?.string);
}

test "SigningMethodRS256 Check with pkcs8 key" {
    const alloc = testing.allocator;

    const pubkey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";
    const token_str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg";

    const pubkey_bytes = try jwt.utils.base64Decode(alloc, pubkey);
    defer alloc.free(pubkey_bytes);

    const public_key = try jwt.crypto_rsa.PublicKey.fromPKCS8Der(pubkey_bytes);

    const p = jwt.SigningMethodRS256.init(alloc);
    var parsed = try p.parse(token_str, public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings("bar", claims2.value.object.get("foo").?.string);
}

test "SigningMethodPS256 Check with pkcs8 key" {
    const alloc = testing.allocator;

    const pubkey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";
    const token_str = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.PPG4xyDVY8ffp4CcxofNmsTDXsrVG2npdQuibLhJbv4ClyPTUtR5giNSvuxo03kB6I8VXVr0Y9X7UxhJVEoJOmULAwRWaUsDnIewQa101cVhMa6iR8X37kfFoiZ6NkS-c7henVkkQWu2HtotkEtQvN5hFlk8IevXXPmvZlhQhwzB1sGzGYnoi1zOfuL98d3BIjUjtlwii5w6gYG2AEEzp7HnHCsb3jIwUPdq86Oe6hIFjtBwduIK90ca4UqzARpcfwxHwVLMpatKask00AgGVI0ysdk0BLMjmLutquD03XbThHScC2C2_Pp4cHWgMzvbgLU2RYYZcZRKr46QeNgz9w";

    const pubkey_bytes = try jwt.utils.base64Decode(alloc, pubkey);
    defer alloc.free(pubkey_bytes);

    const public_key = try jwt.crypto_rsa.PublicKey.fromPKCS8Der(pubkey_bytes);

    const p = jwt.SigningMethodPS256.init(alloc);
    var parsed = try p.parse(token_str, public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings("bar", claims2.value.object.get("foo").?.string);
}

test "SigningMethodEdDSA type" {
    const alloc = testing.allocator;

    const kp = jwt.eddsa.Ed25519.KeyPair.generate();

    const headers = .{
        .alg = "EdDSA",
    };
    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    const s = jwt.SigningMethodEdDSA.init(alloc);
    const token_string = try s.signWithHeader(headers, claims, kp.secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = jwt.SigningMethodEdDSA.init(alloc);
    var parsed = try p.parse(token_string, kp.public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.value.object.get("sub").?.string);

    var headers2 = try parsed.getHeader();
    defer headers2.deinit(alloc);
    try testing.expectEqualStrings("", headers2.typ);
    try testing.expectEqualStrings(headers.alg, headers2.alg);
}

test "SigningMethodEdDSA JWTTypeInvalid" {
    const alloc = testing.allocator;

    const kp = jwt.eddsa.Ed25519.KeyPair.generate();

    const headers = .{
        .typ = "JWE",
        .alg = "EdDSA",
    };
    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    const s = jwt.SigningMethodEdDSA.init(alloc);
    const token_string = try s.signWithHeader(headers, claims, kp.secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = jwt.SigningMethodEdDSA.init(alloc);

    var need_true: bool = false;
    _ = p.parse(token_string, kp.public_key) catch |err| {
        need_true = true;
        try testing.expectEqual(jwt.Error.JWTTypeInvalid, err);
    };
    try testing.expectEqual(true, need_true);
}

test "SigningMethodEdDSA JWTAlgoInvalid" {
    const alloc = testing.allocator;

    const kp = jwt.ecdsa.ecdsa.EcdsaP256Sha256.KeyPair.generate();

    const headers = .{
        .typ = "JWT",
        .alg = "ES384",
    };
    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    const s = jwt.SigningMethodES256.init(alloc);
    const token_string = try s.signWithHeader(headers, claims, kp.secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    const p = jwt.SigningMethodES256.init(alloc);

    var need_true: bool = false;
    _ = p.parse(token_string, kp.public_key) catch |err| {
        need_true = true;
        try testing.expectEqual(jwt.Error.JWTAlgoInvalid, err);
    };
    try testing.expectEqual(true, need_true);
}
