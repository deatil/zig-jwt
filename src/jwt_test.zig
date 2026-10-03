const std = @import("std");
const fmt = std.fmt;
const time = std.time;
const testing = std.testing;
const Random = std.Random;

const jwt = @import("jwt.zig");

const random = (Random.IoSource{
    .io = testing.io,
}).interface();

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

    try testing.expectEqual(jwt.SigningMethodMLDSA44, try jwt.getSigningMethod("ML-DSA-44"));
    try testing.expectEqual(jwt.SigningMethodMLDSA65, try jwt.getSigningMethod("ML-DSA-65"));
    try testing.expectEqual(jwt.SigningMethodMLDSA87, try jwt.getSigningMethod("ML-DSA-87"));

    try testing.expectEqual(jwt.SigningMethodHMD5, try jwt.getSigningMethod("HMD5"));
    try testing.expectEqual(jwt.SigningMethodHSHA1, try jwt.getSigningMethod("HSHA1"));
    try testing.expectEqual(jwt.SigningMethodHS224, try jwt.getSigningMethod("HS224"));
    try testing.expectEqual(jwt.SigningMethodHS256, try jwt.getSigningMethod("HS256"));
    try testing.expectEqual(jwt.SigningMethodHS384, try jwt.getSigningMethod("HS384"));
    try testing.expectEqual(jwt.SigningMethodHS512, try jwt.getSigningMethod("HS512"));

    try testing.expectEqual(jwt.SigningMethodBLAKE2B, try jwt.getSigningMethod("BLAKE2B"));

    try testing.expectEqual(jwt.SigningMethodNone, try jwt.getSigningMethod("none"));

    const res = jwt.getSigningMethod("HS258");
    try testing.expectError(jwt.Error.JWTSigningMethodNotExists, res);
}

test "parse JWTTypeInvalid" {
    const alloc = testing.allocator;

    const kp = jwt.eddsa.Ed25519.KeyPair.generate(testing.io);

    const token_string = "eyJ0eXAiOiJKV0UiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJleGFtcGxlLmNvbSIsImlhdCI6ImZvbyJ9.dGVzdC1zaWduYXR1cmU";

    var p = jwt.SigningMethodEdDSA.init(alloc);

    const res = p.parse(token_string, kp.public_key);
    try testing.expectError(jwt.Error.JWTTypeInvalid, res);
}

test "parse JWTSignatureInvalid" {
    const alloc = testing.allocator;

    const kp = jwt.ecdsa.ecdsa.EcdsaP256Sha256.KeyPair.generate(testing.io);

    const token_string = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJleGFtcGxlLmNvbSIsImlhdCI6ImZvbyJ9.dGVzdC1zaWduYXR1cmU";

    var p = jwt.SigningMethodES256.init(alloc);

    const res = p.parse(token_string, kp.public_key);
    try testing.expectError(jwt.Error.JWTVerifyFail, res);
}

test "Token Validator" {
    const alloc = testing.allocator;

    const check1 = "eyJ0eXAiOiJKV0UiLCJhbGciOiJFUzI1NiIsImtpZCI6ImtpZHMifQ.eyJpc3MiOiJpc3MiLCJpYXQiOjE1Njc4NDIzODgsImV4cCI6MTc2Nzg0MjM4OCwiYXVkIjoiZXhhbXBsZS5jb20iLCJzdWIiOiJzdWIiLCJqdGkiOiJqdGkgcnJyIiwibmJmIjoxNTY3ODQyMzg4fQ.dGVzdC1zaWduYXR1cmU";
    const ts = std.Io.Clock.real.now(testing.io).nanoseconds;
    const now = @as(i64, @intCast(ts));

    var token = jwt.Token.init(alloc);
    token.parse(check1);

    defer token.deinit();

    var validator = try jwt.Validator.init(alloc, &token);
    defer validator.deinit();

    try testing.expectEqual(true, validator.hasBeenIssuedBy(&.{"iss"}));
    try testing.expectEqual(true, validator.isRelatedTo(&.{"sub"}));
    try testing.expectEqual(true, validator.isIdentifiedBy("jti rrr"));
    try testing.expectEqual(true, validator.isPermittedFor(&.{"example.com"}));
    try testing.expectEqual(true, validator.hasBeenIssuedBefore(now));

    const claims = try token.getClaims();
    defer claims.deinit();
    try testing.expectEqual(true, claims.value.object.get("nbf").?.integer > 0);
}

test "SigningMethodEdDSA builder" {
    const alloc = testing.allocator;

    const kp = jwt.eddsa.Ed25519.KeyPair.generate(testing.io);

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    var build = jwt.SigningMethodEdDSA.init(alloc).build();
    defer build.deinit();

    var c = build.claimsData();

    try c.begin();
    try c.permittedFor(claims.aud);
    try c.relatedTo(claims.sub);
    try c.end();

    var t = try build.getToken(random, kp.secret_key);
    defer t.deinit();

    const token_string = try t.signedString();
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodEdDSA.init(alloc);
    var parsed = try p.parse(token_string, kp.public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.value.object.get("sub").?.string);
}

test "SigningMethodEdDSA signWithHeader" {
    const alloc = testing.allocator;

    const kp = jwt.eddsa.Ed25519.KeyPair.generate(testing.io);

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    var s = jwt.SigningMethodEdDSA.init(alloc);

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

    var p = jwt.SigningMethodEdDSA.init(alloc);
    var parsed = try p.parse(token_string, kp.public_key);
    defer parsed.deinit();

    const header2 = try parsed.getHeaders();
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

    const kp = jwt.eddsa.Ed25519.KeyPair.generate(testing.io);

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    var s = jwt.SigningMethodEdDSA.init(alloc);
    const token_string = try s.sign(claims, kp.secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodEdDSA.init(alloc);
    var parsed = try p.parse(token_string, kp.public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.value.object.get("sub").?.string);
}

test "SigningMethodES256" {
    const alloc = testing.allocator;

    const kp = jwt.ecdsa.ecdsa.EcdsaP256Sha256.KeyPair.generate(testing.io);

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    var s = jwt.SigningMethodES256.init(alloc);
    const token_string = try s.sign(claims, kp.secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodES256.init(alloc);
    var parsed = try p.parse(token_string, kp.public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.value.object.get("sub").?.string);
}

test "SigningMethodES384" {
    const alloc = testing.allocator;

    const kp = jwt.ecdsa.ecdsa.EcdsaP384Sha384.KeyPair.generate(testing.io);

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    var s = jwt.SigningMethodES384.init(alloc);
    const token_string = try s.sign(claims, kp.secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodES384.init(alloc);
    var parsed = try p.parse(token_string, kp.public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.value.object.get("sub").?.string);
}

test "SigningMethodES256K" {
    const alloc = testing.allocator;

    const kp = jwt.ecdsa.ecdsa.EcdsaSecp256k1Sha256.KeyPair.generate(testing.io);

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    var s = jwt.SigningMethodES256K.init(alloc);
    const token_string = try s.sign(claims, kp.secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodES256K.init(alloc);
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

    var s = jwt.SigningMethodHMD5.init(alloc);
    const token_string = try s.sign(claims, key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodHMD5.init(alloc);
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

    var s = jwt.SigningMethodHSHA1.init(alloc);
    const token_string = try s.sign(claims, key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodHSHA1.init(alloc);
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

    var s = jwt.SigningMethodHS224.init(alloc);
    const token_string = try s.sign(claims, key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodHS224.init(alloc);
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

    var s = jwt.SigningMethodHS256.init(alloc);
    const token_string = try s.sign(claims, key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodHS256.init(alloc);
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

    var s = jwt.SigningMethodHS384.init(alloc);
    const token_string = try s.sign(claims, key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodHS384.init(alloc);
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

    var s = jwt.SigningMethodHS512.init(alloc);
    const token_string = try s.sign(claims, key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodHS512.init(alloc);
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

    var s = jwt.SigningMethodBLAKE2B.init(alloc);
    const token_string = try s.sign(claims, key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodBLAKE2B.init(alloc);
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

    var s = jwt.SigningMethodNone.init(alloc);
    const token_string = try s.sign(claims, key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodNone.init(alloc);
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

    var s = jwt.SigningMethodES256.init(alloc);
    const token_string = try s.sign(claims, secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodES256.init(alloc);
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

    var s = jwt.SigningMethodES384.init(alloc);
    const token_string = try s.sign(claims, secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodES384.init(alloc);
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

    var p = jwt.SigningMethodES256.init(alloc);

    const res = p.parse(token_str, public_key);
    try testing.expectError(jwt.Error.JWTVerifyFail, res);
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

    var s = jwt.SigningMethodES256K.init(alloc);
    const token_string = try s.sign(claims, secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodES256K.init(alloc);
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

    var s = jwt.SigningMethodED25519.init(alloc);
    const token_string = try s.sign(claims, secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodED25519.init(alloc);
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

    var p = jwt.SigningMethodED25519.init(alloc);

    const res = p.parse(token_str, public_key);
    try testing.expectError(jwt.Error.JWTVerifyFail, res);
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

    var s = jwt.SigningMethodHS256.init(alloc);
    const token_string = try s.sign(claims, key_bytes);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodHS256.init(alloc);
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

    var s = jwt.SigningMethodHS384.init(alloc);
    const token_string = try s.sign(claims, key_bytes);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodHS384.init(alloc);
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

    var s = jwt.SigningMethodHS512.init(alloc);
    const token_string = try s.sign(claims, key_bytes);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodHS512.init(alloc);
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

    var p = jwt.SigningMethodHS256.init(alloc);

    const res = p.parse(token_str, key_bytes);
    try testing.expectError(jwt.Error.JWTVerifyFail, res);
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

    var s = jwt.SigningMethodBLAKE2B.init(alloc);
    const token_string = try s.sign(claims, key_bytes);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);
    try testing.expectEqualStrings(token_str, token_string);

    // ==========

    var p = jwt.SigningMethodBLAKE2B.init(alloc);
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

    var p = jwt.SigningMethodBLAKE2B.init(alloc);

    const res = p.parse(token_str, key_bytes);
    try testing.expectError(jwt.Error.JWTVerifyFail, res);
}

test "getTokenHeader" {
    const alloc = testing.allocator;

    const token_str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJmb28iOiJiYXIifQ.feG39E-bn8HXAKhzDZq7yEAPWYDhZlwTn3sePJnU9VrGMmwdXAIEyoOnrjreYlVM_Z4N13eK9-TmMTWyfKJtHQ";

    var header = try jwt.getTokenHeader(alloc, token_str);
    defer header.deinit();
    try testing.expectEqualStrings("ES256", header.getAlgorithm().?);
}

test "SigningMethodES256 with JWTClaims" {
    const alloc = testing.allocator;

    const kp = jwt.ecdsa.ecdsa.EcdsaP256Sha256.KeyPair.generate(testing.io);

    const claims: jwt.JWTClaims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    var s = jwt.SigningMethodES256.init(alloc);
    const token_string = try s.sign(claims, kp.secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodES256.init(alloc);
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

    var secret_key = try jwt.crypto_rsa.SecretKey.fromDer(alloc, prikey_bytes);
    const public_key = try jwt.crypto_rsa.PublicKey.fromDer(pubkey_bytes);

    defer secret_key.deinit(alloc);

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    var s = jwt.SigningMethodRS256.init(alloc);
    const token_string = try s.sign(claims, secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodRS256.init(alloc);
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

    var secret_key = try jwt.crypto_rsa.SecretKey.fromDer(alloc, prikey_bytes);
    const public_key = try jwt.crypto_rsa.PublicKey.fromDer(pubkey_bytes);

    defer secret_key.deinit(alloc);

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    var s = jwt.SigningMethodRS384.init(alloc);
    const token_string = try s.sign(claims, secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodRS384.init(alloc);
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

    var secret_key = try jwt.crypto_rsa.SecretKey.fromDer(alloc, prikey_bytes);
    const public_key = try jwt.crypto_rsa.PublicKey.fromDer(pubkey_bytes);

    defer secret_key.deinit(alloc);

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    var s = jwt.SigningMethodRS512.init(alloc);
    const token_string = try s.sign(claims, secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodRS512.init(alloc);
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

    var secret_key = try jwt.crypto_rsa.SecretKey.fromDer(alloc, prikey_bytes);
    const public_key = try jwt.crypto_rsa.PublicKey.fromDer(pubkey_bytes);

    defer secret_key.deinit(alloc);

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    var s = jwt.SigningMethodPS256.init(alloc);
    s.withRandom(random);
    const token_string = try s.sign(claims, secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodPS256.init(alloc);
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

    var secret_key = try jwt.crypto_rsa.SecretKey.fromDer(alloc, prikey_bytes);
    const public_key = try jwt.crypto_rsa.PublicKey.fromDer(pubkey_bytes);

    defer secret_key.deinit(alloc);

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    var s = jwt.SigningMethodPS384.init(alloc);
    s.withRandom(random);
    const token_string = try s.sign(claims, secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodPS384.init(alloc);
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

    var secret_key = try jwt.crypto_rsa.SecretKey.fromDer(alloc, prikey_bytes);
    const public_key = try jwt.crypto_rsa.PublicKey.fromDer(pubkey_bytes);

    defer secret_key.deinit(alloc);

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    var s = jwt.SigningMethodPS512.init(alloc);
    s.withRandom(random);
    const token_string = try s.sign(claims, secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodPS512.init(alloc);
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

    var p = jwt.SigningMethodRS256.init(alloc);
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

    var p = jwt.SigningMethodRS384.init(alloc);
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

    var p = jwt.SigningMethodRS512.init(alloc);
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

    var p = jwt.SigningMethodRS256.init(alloc);

    const res = p.parse(token_str, public_key);
    try testing.expectError(jwt.Error.JWTVerifyFail, res);
}

test "SigningMethodPS256 Check" {
    const alloc = testing.allocator;

    const pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";
    const token_str = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.PPG4xyDVY8ffp4CcxofNmsTDXsrVG2npdQuibLhJbv4ClyPTUtR5giNSvuxo03kB6I8VXVr0Y9X7UxhJVEoJOmULAwRWaUsDnIewQa101cVhMa6iR8X37kfFoiZ6NkS-c7henVkkQWu2HtotkEtQvN5hFlk8IevXXPmvZlhQhwzB1sGzGYnoi1zOfuL98d3BIjUjtlwii5w6gYG2AEEzp7HnHCsb3jIwUPdq86Oe6hIFjtBwduIK90ca4UqzARpcfwxHwVLMpatKask00AgGVI0ysdk0BLMjmLutquD03XbThHScC2C2_Pp4cHWgMzvbgLU2RYYZcZRKr46QeNgz9w";

    const pubkey_bytes = try jwt.utils.base64Decode(alloc, pubkey);
    defer alloc.free(pubkey_bytes);

    const public_key = try jwt.crypto_rsa.PublicKey.fromDer(pubkey_bytes);

    var p = jwt.SigningMethodPS256.init(alloc);
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

    var p = jwt.SigningMethodPS384.init(alloc);
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

    var p = jwt.SigningMethodPS512.init(alloc);
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

    var p = jwt.SigningMethodPS256.init(alloc);

    const res = p.parse(token_str, public_key);
    try testing.expectError(jwt.Error.JWTVerifyFail, res);
}

test "SigningMethodRS256 with pkcs8 key" {
    const alloc = testing.allocator;

    const prikey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDh/nCDmXaEqxN416b9XjV8acmbqA52uPzKbesWQRT/BPxEO2dKAURk5CkcSBDskvfzFR9TRjeDppjD1BPSEnuYKnP0SvmotoxcnBnHMfMBqGV8DSJyppu8k4y9C3MPq5C/rA8TJm0NNaJCL0BfAGkeyw+elgYifbRlm42VfYGsKVyIeEI9Qghk5Cf8yapMPfWNLKOhChXsyGExMBMonHZeseFH7UNwonNAFJMAaelhVqqmwBFqn6fBGKmvedRO7HIaiEFNKaMna6xJ5Bccjds4MhF7UC5PIdx4Bt7CfxvjrbIRYoBF2l30CNBblIhU992zPkHoaVhDkt1gq3OdO7LvAgMBAAECggEBALCJrWTv7ahnZ3efpqAIBuogTVBd8KaHjVmokds5jehFAbdfXClwYfgaT477MNVNXYmzN1w63sTl0DIxqiYRMCFHEHuGUg6cQ3tYqb50Y2spG9XTANTlF4UxEeDfX8ue7xz7kG8aNlf6TL084iEUVgmrAJGWikZJQjGZWPmtKC3OTeJY5Bev5qHVuMRe+XEM5aQc3ph+lXlOF0Qp0Eg8YRWprrev2faH6prMqu2JGomoac6sfM4QJhtEViF7Gw0XPthPTbF19IefuAwi9psMM/9CnQ+MTWN2i6IxoUdicsFuC+Wdlb3K5V/+uldNSr+ePEhcya+YTLK9IOcVwWKQHykCgYEA8XvuEribf+t0ZPtfxr+DC9nZHXbVoFx0/ARpSG+P/fp3Hn3rO9iYQ6OtZ9mEXTzf+dhYTaRWq6PbCOz6i0It+J8QSBdxU9OcQ4871mDe41IvSc1CCGMW4PeIYtNQEK0zrqhN7SMtKyUd7yAsYRCrIzMc7NjE2qJvFw5kh7xC3Q0CgYEA75Qjn5daNYSAOa/ILdOs5J/8oIaO27RNK/fSKm/btsMsyum8+YP/mWmm1MXBzG9WEKzZv5yEKOWCEVJYVsFQsGt9yLYW2WIKU5UxiuU0F1RImF/dphIbYOh7oGC3WfYKk2f+K7ftjc196ZkEkDuE2Xh1h75/67Mzztx1DbXj6OsCgYBcDRfFfyWXb5Og4smxo1M680H2H1RzmorlfnD7sbs733wE3Y8L8xanwf7Z9WqleA0Q2k1e22RGbWGTV3JyHzoS6d90+6qxf5qzjigLIkYUdUGdambfd5ZDD1ioA1Ej6kInM/TwjlYreiyc+LCyF36FHnjKOB9iEEU0jsH3k+YRCQKBgHMVLPuHX6zfhhyvxK/Gw4FbHKYbnNoKxRs+wvThoKAtJwIdv0n4TzppVttUV2CVhrkh3sM9MvrWLGGXtZmO6Oyl5dkZJuarQpydyRuYOCqQsQKI4lbY0c/+PQxwCQMsvi3KwXxMsM7yC+6/M0L5ZDp2s7ZOGvKktVlD6vJ4Eg+bAoGARnGGprSBW8dAb/s53r0paPh4k/bySrXdGEprLwk6g3S8+aylcmjUdjcIq4dEb4A/nv12dx1Sc4y99c62R0zi+TT6FYBIFDMz3HNVzO0Jr6SgC6CNVotL0D725CioR5U1NyTHHRLZth69HLuEZCZQlPJCbePXMRRHmOl1svzcVuo=";
    const pubkey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";

    const prikey_bytes = try jwt.utils.base64Decode(alloc, prikey);
    const pubkey_bytes = try jwt.utils.base64Decode(alloc, pubkey);

    defer alloc.free(prikey_bytes);
    defer alloc.free(pubkey_bytes);

    var secret_key = try jwt.crypto_rsa.SecretKey.fromPKCS8Der(alloc, prikey_bytes);
    const public_key = try jwt.crypto_rsa.PublicKey.fromPKCS8Der(pubkey_bytes);

    defer secret_key.deinit(alloc);

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    var s = jwt.SigningMethodRS256.init(alloc);
    const token_string = try s.sign(claims, secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodRS256.init(alloc);
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

    var secret_key = try jwt.crypto_rsa.SecretKey.fromPKCS8Der(alloc, prikey_bytes);
    const public_key = try jwt.crypto_rsa.PublicKey.fromPKCS8Der(pubkey_bytes);

    defer secret_key.deinit(alloc);

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    var s = jwt.SigningMethodPS256.init(alloc);
    const token_string = try s.sign(claims, secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodPS256.init(alloc);
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

    var p = jwt.SigningMethodRS256.init(alloc);
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

    var p = jwt.SigningMethodPS256.init(alloc);
    var parsed = try p.parse(token_str, public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings("bar", claims2.value.object.get("foo").?.string);
}

test "SigningMethodEdDSA type" {
    const alloc = testing.allocator;

    const kp = jwt.eddsa.Ed25519.KeyPair.generate(testing.io);

    const headers = .{
        .alg = "EdDSA",
    };
    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    var s = jwt.SigningMethodEdDSA.init(alloc);
    const token_string = try s.signWithHeader(headers, claims, kp.secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodEdDSA.init(alloc);
    var parsed = try p.parse(token_string, kp.public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.value.object.get("sub").?.string);

    var headers2 = try parsed.getHeader();
    defer headers2.deinit();
    try testing.expectEqualStrings("", headers2.getType() orelse "");
    try testing.expectEqualStrings(headers.alg, headers2.getAlgorithm().?);
}

test "SigningMethodEdDSA JWTTokenInvalid" {
    const alloc = testing.allocator;

    const kp = jwt.eddsa.Ed25519.KeyPair.generate(testing.io);

    const token_string = "eyJhbGciOiJFRDI1NTE5IiwidHlwIjoiSldUIn0";

    var p = jwt.SigningMethodEdDSA.init(alloc);

    const res = p.parse(token_string, kp.public_key);
    try testing.expectError(jwt.Error.JWTTokenInvalid, res);
}

test "SigningMethodEdDSA JWTTypeInvalid" {
    const alloc = testing.allocator;

    const kp = jwt.eddsa.Ed25519.KeyPair.generate(testing.io);

    const headers = .{
        .typ = "JWE",
        .alg = "EdDSA",
    };
    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    var s = jwt.SigningMethodEdDSA.init(alloc);
    const token_string = try s.signWithHeader(headers, claims, kp.secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodEdDSA.init(alloc);

    const res = p.parse(token_string, kp.public_key);
    try testing.expectError(jwt.Error.JWTTypeInvalid, res);
}

test "SigningMethodEdDSA JWTAlgoInvalid" {
    const alloc = testing.allocator;

    const kp = jwt.ecdsa.ecdsa.EcdsaP256Sha256.KeyPair.generate(testing.io);

    const headers = .{
        .typ = "JWT",
        .alg = "ES384",
    };
    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    var s = jwt.SigningMethodES256.init(alloc);
    const token_string = try s.signWithHeader(headers, claims, kp.secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodES256.init(alloc);

    const res = p.parse(token_string, kp.public_key);
    try testing.expectError(jwt.Error.JWTAlgoInvalid, res);
}

test "SigningMethodEdDSA with function" {
    const alloc = testing.allocator;
    const Ed25519 = std.crypto.sign.Ed25519;

    const kp = Ed25519.KeyPair.generate(testing.io);

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    const token_string = try jwt.sign(Ed25519.SecretKey, alloc, random, jwt.SigningMethodEdDSA, claims, kp.secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var parsed = try jwt.parse(Ed25519.PublicKey, alloc, jwt.SigningMethodEdDSA, token_string, kp.public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.value.object.get("sub").?.string);
}

test "Registered std" {
    try testing.expectEqualStrings("typ", jwt.RegisteredStdHeaders.Type);
    try testing.expectEqualStrings("aud", jwt.RegisteredStdClaims.Audience);
}

test "SigningMethodHS256 with JWTHeaders and JWTClaims" {
    const alloc = testing.allocator;

    const key = "0323354b2b0fa5bc837e0665777ba68f5ab328e6f054c928a90f84b2d2502ebfd3fb5a92d20647ef968ab4c377623d223d2e2172052e4f08c0cd9af567d080a3";

    var key_buf: [key.len]u8 = undefined;
    const key_bytes = try fmt.hexToBytes(&key_buf, key);

    const headers: jwt.JWTHeaders = .{
        .typ = "JWT",
        .alg = "HS256",
        .kid = "kidstr",
        .cty = "utf8",
    };

    const claims: jwt.JWTClaims = .{
        .iss = "joe",
        .iat = 1300819380,
        .exp = 1350819380,
        .aud = "aud str",
        .sub = "sub str",
        .jti = "idid55",
        .nbf = 1300819385,
    };

    var s = jwt.SigningMethodHS256.init(alloc);
    const token_string = try s.signWithHeader(headers, claims, key_bytes);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodHS256.init(alloc);
    var parsed = try p.parse(token_string, key_bytes);
    defer parsed.deinit();

    const headers2 = try parsed.getHeadersT(jwt.JWTHeaders);
    defer headers2.deinit();
    try testing.expectEqualStrings(headers.typ.?, headers2.value.typ.?);
    try testing.expectEqualStrings(headers.alg.?, headers2.value.alg.?);
    try testing.expectEqualStrings(headers.kid.?, headers2.value.kid.?);
    try testing.expectEqualStrings(headers.cty.?, headers2.value.cty.?);

    const claims2 = try parsed.getClaimsT(jwt.JWTClaims);
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.iss.?, claims2.value.iss.?);
    try testing.expectEqual(claims.iat.?, claims2.value.iat.?);
    try testing.expectEqual(claims.exp.?, claims2.value.exp.?);
    try testing.expectEqualStrings(claims.aud.?, claims2.value.aud.?);
    try testing.expectEqualStrings(claims.sub.?, claims2.value.sub.?);
    try testing.expectEqualStrings(claims.jti.?, claims2.value.jti.?);
    try testing.expectEqual(claims.nbf.?, claims2.value.nbf.?);
}

test "JWT getSigner" {
    const alloc = testing.allocator;

    var p = jwt.SigningMethodHS256.init(alloc);
    try testing.expectFmt("HS256", "{s}", .{p.getSigner().alg()});

    var p1 = jwt.SigningMethodRS256.init(alloc);
    try testing.expectFmt("RS256", "{s}", .{p1.getSigner().alg()});

    var p2 = jwt.SigningMethodEdDSA.init(alloc);
    try testing.expectFmt("EdDSA", "{s}", .{p2.getSigner().alg()});
}

test "SigningMethodMLDSA44" {
    const io = testing.io;
    const alloc = testing.allocator;

    const kp = jwt.mldsa.MLDSA44.KeyPair.generate(io);

    const secret_key = kp.secret_key;
    const public_key = kp.public_key;

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    var s = jwt.SigningMethodMLDSA44.init(alloc);
    const token_string = try s.sign(claims, secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodMLDSA44.init(alloc);
    var parsed = try p.parse(token_string, public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.value.object.get("sub").?.string);
}

test "SigningMethodMLDSA65" {
    const io = testing.io;
    const alloc = testing.allocator;

    const kp = jwt.mldsa.MLDSA65.KeyPair.generate(io);

    const secret_key = kp.secret_key;
    const public_key = kp.public_key;

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    var s = jwt.SigningMethodMLDSA65.init(alloc);
    const token_string = try s.sign(claims, secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodMLDSA65.init(alloc);
    var parsed = try p.parse(token_string, public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.value.object.get("sub").?.string);
}

test "SigningMethodMLDSA87" {
    const io = testing.io;
    const alloc = testing.allocator;

    const kp = jwt.mldsa.MLDSA87.KeyPair.generate(io);

    const secret_key = kp.secret_key;
    const public_key = kp.public_key;

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    var s = jwt.SigningMethodMLDSA87.init(alloc);
    const token_string = try s.sign(claims, secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodMLDSA87.init(alloc);
    var parsed = try p.parse(token_string, public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.value.object.get("sub").?.string);
}

test "SigningMethodMLDSA44 Check" {
    const alloc = testing.allocator;

    const pubkey = "unH59k4RuutY-pxvu24U5h8YZD2rSVtHU5qRZsoBmBMcRPgmu9VuNOVdteXi1zNIXjnqJg_GAAxepLqA00Vc3lO0bzRIKu39VFD8Lhuk8l0V-cFEJC-zm7UihxiQMMUEmOFxe3x1ixkKZ0jqmqP3rKryx8tSbtcXyfea64QhT6XNje2SoMP6FViBDxLHBQo2dwjRls0k5a-XSQSu2OTOiHLoaWsLe8pQ5FLNfTDqmkrawDEdZyxr3oSWJAsHQxRjcIiVzZuvwxYy1zl2STiP2vy_fTBaPemkleynQzqPg7oPCyXEE8bjnJbrfWkbNNN8438e6tHPIX4l7zTuzz98YPhLjt_d6EBdT4MldsYe-Y4KLyjaGHcAlTkk9oa5RhRwW89T0z_t1DSO3dvfKLUGXh8gd1BD6Fz5MfgpF5NjoafnQEqDjsAAhrCXY4b-Y3yYJEdX4_dp3dRGdHG_rWcPmgX4JG7lCnser4f8QGnDriqiAzJYEXeS8LzUngg_0bx0lqv_KcyU5IaLISFO0xZSU5mmEPvdSoDnyAcV8pV44qhLtAvd29n0ehG259oRihtljTWeiu9V60a1N2tbZVl5mEqSK-6_xZvNYA1TCdzNctvweH24unV7U3wer9XA9Q6kvJWDVJ4oKaQsKMrCSMlteBJMRxWbGK7ddUq6F7GdQw-3j2M-qdJvVKm9UPjY9rc1lPgol25-oJxTu7nxGlbJUH-4m5pevAN6NyZ6lfhbjWTKlxkrEKZvQXs_Yf6cpXEwpI_ZJeriq1UC1XHIpRkDwdOY9MH3an4RdDl2r9vGl_IwlKPNdh_5aF3jLgn7PCit1FNJAwC8fIncAXgAlgcXIpRXdfJk4bBiO89GGccSyDh2EgXYdpG3XvNgGWy7npuSoNTE7WIyblAk13UQuO4sdCbMIuriCdyfE73mvwj15xgb07RZRQtFGlFTmnFcIdZ90zDrWXDbANntv7KCKwNvoTuv64bY3HiGbj-NQ-U9eMylWVpvr4hrXcES8c9K3PqHWADZC0iIOvlzFv4VBoc_wVflcOrL_SIoaNFCNBAZZq-2v5lAgpJTqVOtqJ_HVraoSfcKy5g45p-qULunXj6Jwq21fobQiKubBKKOZwcJFyJD7F4ACKXOrz-HIvSHMCWW_9dVrRuCpJw0s0aVFbRqopDNhu446nqb4_EDYQM1tTHMozPd_jKxRRD0sH75X8ZoToxFSpLBDbtdWcenxj-zBf6IGWfZnmaetjKEBYJWC7QDQx1A91pJVJCEgieCkoIfTqkeQuePpIyu48g2FG3P1zjRF-kumhUTfSjo5qS0YiZQy0E1BMs6M11EvuxXRsHClLHoy5nLYI2Sj4zjVjYyxSHyPRPGGo9hwB34yWxzYNtPPGiqXS_dNCpi_zRZwRY4lCGrQ-hYTEWIK1Dm5OlttvC4_eiQ1dv63NiGkLRJ5kJA3bICN0fzCDY-MBqnd1cWn8YVBijVkgtaoascjL9EywDgJdeHnXK0eeOvUxHHhXJVkNqcibn8O4RQdpVU60TSA-uiu675ytIjcBHC6kTv8A8pmkj_4oypPd-F92YIJC741swkYQoeIHj8rE-ThcMUkF7KqC5VORbZTRp8HsZSqgiJcIPaouuxd1-8Rxrid3fXkE6p8bkrysPYoxWEJgh7ZFsRCPDWX-yTeJwFN0PKFP1j0F6YtlLfK5wv-c4F8ZQHA_-yc_gODicy7KmWDZgbTP07e7gEWzw4MFRrndjbDQ";
    const token_str = "eyJhbGciOiJNTC1EU0EtNDQiLCJraWQiOiJUNHhsNzBTN01UNlplcTZyOVY5ZlBKR1ZuNzZ3Zm5YSjIxLWd5bzBHdTZvIn0.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4.knI1Q_9CIzLH5Xy94Kkc7WVKqZcAgtJ3mNf0GUj1uLA6YXAWFJfXkh-zQxUtEl3UIC7zPCiUwKTDR6ZsuUmFj8Ctb_6aH64hElN7weS_1m5okCy8GqHNL2lsfclCH3Y2f4QNP-DLVS1XsuboDA7Dw3ir2IdYKIfWJyIU7ROHgd24nuun1zJbxcLJC2EKt2M8R0wZudcIE9nm5oPzYXq0z-hPsKoXp9leVYkqgMmO9Lo8SP_1YYIEth3B8v-GuP249KDTFRKPjISmK4aPCknjtjihHsQVv2XePXxKExatHl4qhsiiW-y-EJXa1Kfw4WYpLA7B4_5Ids--cIJmIx7f6xxAWKh5qoBWq1QIOaaFuzsAraRW3NOEuzThew1En85gI3GcRTZGp-VDGyxHm0Al04cyWo2bxAVOF0fbDc265iP2mCNw6Qg10jIJeAhGB4OAMYcBUWJAG0l1MN1U_koEmGh5dXKnQTRl461ea_Cq3DLkcA2Dj2woWUFyDTmQ8oO_yheASfJacyRm7_suj88z5XFNo8F53P8OxTG9xUPlrwvH-TAq7AH3NU4SNXApyVKTU3zhx1tJ34nlTILcTujXVJVo_f0DZfUxr6JSCYqvy4z1Kl0wDQzd55aopyFtQxvOPhcCHbAN34g2Ug750Jm835fl7NOxcqoMbuTcgH68kr37M-Pdh2K9WazXUJgCupgdIWW8WjfOjmTiF59CrVtfVtK2qDzF40OENCfqtNPQlZe5cN5p0P8arj4USB8HCPh7NdqQBAeWrw0wsYhdiM39lrSkA8mLRYMhZnqKGCTPCrHXDdEjRKYRNaqIUT44laYl5c27K0v-ozjKPu6tzEhkYSC4XZ3LehEFtmAzOE0mHbhKMgXqjoPJjOrGIPibX3jwK8_Q5RmMOXtXo8R3vXfBaUdQoLeeyywNYE0nIcsl4z5a8_utwEFiVf0VK2pdviyiOPVSi3zOMAmqz6gFhVy8aMMQOWZAEAuTyDw7ZWG6diwptmrgSXZotW63I19S2ZH7keCXRIq_pFLuYhOuG6dD4MkouILRdC9bXZMLrNDq7COpUOO86aQVlYd0pR935WpUw-V6obSRnHlRFZSmUSIB7h1Q0ImciRzojN93Xhw7qpzGzdzDEO3OOTayXaSG_0YHQyy-eH4hBbmgt_LBx120g1eY4XHeHFRfTfetHkL5ZZusX1jQ_nk9ez4XBG_6hRtTNSuVBsYlH8-KUuR5-qTP8dkvRf8Wk2hHoUr2sz5YO_xDFCMMTrt8ahiMyfjo5ih5Fwo3riFbFUGKibniTLXspFd4spcNK_WchlZLRgkPK4jh6Z_X8JJkHxvQhpyouHQFyGxgBrl24x-_EB1zbWMhJthmm8DiKt-nzKaJz8Cju1-HwCpg76CRqRsEz2hyKEpbb4M5KQSj3AsENCroVmQ5QIv3K2XNRkve4vjBmP6sV2b6GSY_UeRvPElA7SUgBGTKbn-c0aYhBuB8plPhRTBa55_cFqAmNmavF1-fdMktJuIaH2f-K0zZCzbHw54998T7kIWgyMsyGCAvynEB_khOqwT7tCjg5HQ8SIjdnRYW0kjZfjt5LJbGA-PnRo8gPVQVGeYDP2vsSXhNJY94AitKCY1srcSsuYDrhNBKrnoJ1uEsMPVHsgFw_ZHMyAEaVQughSNW4fm8q6_1Nv4zLutDITzmAL6a6i6-WS6QRIs_4VUtwr5cXXIFDDeHVWeGcNivQ6W9urEUP4crguiq7z_DTiYaGfUksub-T7mw0zU8ZoOSd5pUTpJLv-IYIUAl6CscHvunnRLEKqpW1Sa1dcFZs5VP4AfR3mg7wX4Vlq1AHnpFxE2L1LZiKoTc9jDEOvTDkxr86gMkwMm6RdyPF_q48AVJ1br8Qp88-4B84X52zZ5cw-IJYe-HiVJ29LpeYm340_rWivpy-UB5i9TKlMrxf94y1okzZTPbP3_v1_XX0nE7RTLz98EA96euJ7l3EpbEqks7mh6i1FJNnvvlM_u29sYobJ6PUT-i1VlQnF_JBARKEz74pBXm1l5Y5Lo15rsIlaQHinUBCO8fHCHI59LAfKusN4JmodDqLYwkWijEL_sfrC6LtrbXqpM1pw09zSrs_tS1RQ-LnWHuPrU5KLCzv53JKrh8lU_cdBowe_F-Ib_Ui4bQ2FME-0mnyG0XijHUsrGMZ9dfowvIkr83JpqwlFOZAwMmSGPNPEJRw9kDshjotndUB5S1UCfv_U4IoVn7WgvxeCS-BBxqyWfh7YTdf73EnmGwVYxVjlXaHCeeTZmUacnT4MQUAcbFjTq6BBlboAQGWP2FZWpd6HNnruv744VeWmfgLk9z5567wFhwuXMkmE2xvDo4wP80xutjUfsePx5YkLxhY1XsWqTZr19tInxJWWq8RLZsWPmtq5wZ5ucBMasCLpOABenYZdSAcQNhC73wLS0Z2s1HQhBoIl7lr1p372LZs_Seu1u_8Fo7DoJqRpKaNoc2_JUMmn7TUZS8zLyzxgeq8R8iNbRP20DwDBNXocsTDBKaQrtB-QiEPySQtJa4G61XeNZyh5aGzfoWZ9OmjZG9pbbehcqwIrt-ESjPyeT6sfSrvOfTZr7fBXwpUs2rS4BrlNse5g_h8CQiik8aaOTOEPkXiyg4s5DewRlgDZHS-3g-YXPUIBNO62_HxknkMpkJvKW-tkvDbgtxvy4nG80ul6W_KeRsoEKDTRYNKZWxXjZITNa0h6agnwNCJKEbFg3Qhre394c0i60mfP9YIgKTXrCX3Yt2eX-6mPzYmLbSbV5jH69v6WZqYV2WAj-9DU0diR4hOfYQaJnBZhTtKb-SQsYiFuN1BDJ3v9eM9K8hq91NBdCHVa-Thk9Dov-JkcTZnZGRRyW5yXHUV4NOEltBXh8GkjjDvs5Yo3u-2rPCXjK1aGPSI1W8BaUJLQY5sbfAVCAuUHBv-Vlh5Qamt-lgeKguhqTSuy-tjabOb5kiBOG7xGQt3z-XYXtnWFDCii-5h11XfZsQ-xQxy8gSfdMz4hDK9Nw_VQt6fzWiQY0Th_dHzVki0MUfVfsDUjgblhD6j0wgbs3zdj-GM3rtt8oit0wXx11bIOaOKgf07tP0wimVXMRqRWe7LCUAKTE5PkRKU1x_h4iusrzi5uwKDhc4SmRwm6KssNrmCAkiNDZCREVKd3yMnrjA4PAGDzdKWVplcHJ6jKmrsbrEztHd9QAAAAAAAAAAAAAAABIfMEQ";

    const pubkey_bytes = try jwt.utils.base64UrlDecode(alloc, pubkey);
    defer alloc.free(pubkey_bytes);

    const PublicKey = jwt.mldsa.MLDSA44.PublicKey;

    var pubkey_bytes2: [PublicKey.encoded_length]u8 = undefined;
    @memcpy(pubkey_bytes2[0..], pubkey_bytes[0..]);

    const public_key = try PublicKey.fromBytes(pubkey_bytes2);

    var p = jwt.SigningMethodMLDSA44.init(alloc);
    var parsed = try p.parse(token_str, public_key);
    defer parsed.deinit();

    const header2 = try parsed.getHeaderRaw();
    defer alloc.free(header2);
    const header_str =
        \\{"alg":"ML-DSA-44","kid":"T4xl70S7MT6Zeq6r9V9fPJGVn76wfnXJ21-gyo0Gu6o"}
    ;
    try testing.expectFmt(header_str, "{s}", .{header2});

    const claims2 = try parsed.getClaimsRaw();
    defer alloc.free(claims2);
    try testing.expectFmt("It’s a dangerous business, Frodo, going out your door.", "{s}", .{claims2});

    // =========

    const token_str2 = "eyJhbGciOiJNTC1EU0EtNDQiLCJraWQiOiJUNHhsNzBTN01UNlplcTZyOVY5ZlBKR1ZuNzZ3Zm5YSjIxLWd5bzBHdTZvIn0.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4.knI1Q_9CIzLH5Xy94Kkc7WVKqZcAgtJ3mNf0GUj1uLA6YXAWFJfXkh-zQxUtEl3UIC7zPCiUwKTDR6ZsuUmFj8Ctb_6aH64hElN7weS_1m5okCy8GqHNL2lsfclCH3Y2f4QNP-DLVS1XsuboDA7Dw3ir2IdYKIfWJyIU7ROHgd24nuun1zJbxcLJC2EKt2M8R0wZudcIE9nm5oPzYXq0z-hPsKoXp9leVYkqgMmO9Lo8SP_1YYIEth3B8v-GuP249KDTFRKPjISmK4aPCknjtjihHsQVv2XePXxKExatHl4qhsiiW-y-EJXa1Kfw4WYpLA7B4_5Ids--cIJmIx7f6xxAWKh5qoBWq1QIOaaFuzsAraRW3NOEuzThew1En85gI3GcRTZGp-VDGyxHm0Al04cyWo2bxAVOF0fbDc265iP2mCNw6Qg10jIJeAhGB4OAMYcBUWJAG0l1MN1U_koEmGh5dXKnQTRl461ea_Cq3DLkcA2Dj2woWUFyDTmQ8oO_yheASfJacyRm7_suj88z5XFNo8F53P8OxTG9xUPlrwvH-TAq7AH3NU4SNXApyVKTU3zhx1tJ34nlTILcTujXVJVo_f0DZfUxr6JSCYqvy4z1Kl0wDQzd55aopyFtQxvOPhcCHbAN34g2Ug750Jm835fl7NOxcqoMbuTcgH68kr37M-Pdh2K9WazXUJgCupgdIWW8WjfOjmTiF59CrVtfVtK2qDzF40OENCfqtNPQlZe5cN5p0P8arj4USB8HCPh7NdqQBAeWrw0wsYhdiM39lrSkA8mLRYMhZnqKGCTPCrHXDdEjRKYRNaqIUT44laYl5c27K0v-ozjKPu6tzEhkYSC4XZ3LehEFtmAzOE0mHbhKMgXqjoPJjOrGIPibX3jwK8_Q5RmMOXtXo8R3vXfBaUdQoLeeyywNYE0nIcsl4z5a8_utwEFiVf0VK2pdviyiOPVSi3zOMAmqz6gFhVy8aMMQOWZAEAuTyDw7ZWG6diwptmrgSXZotW63I19S2ZH7keCXRIq_pFLuYhOuG6dD4MkouILRdC9bXZMLrNDq7COpUOO86aQVlYd0pR935WpUw-V6obSRnHlRFZSmUSIB7h1Q0ImciRzojN93Xhw7qpzGzdzDEO3OOTayXaSG_0YHQyy-eH4hBbmgt_LBx120g1eY4XHeHFRfTfetHkL5ZZusX1jQ_nk9ez4XBG_6hRtTNSuVBsYlH8-KUuR5-qTP8dkvRf8Wk2hHoUr2sz5YO_xDFCMMTrt8ahiMyfjo5ih5Fwo3riFbFUGKibniTLXspFd4spcNK_WchlZLRgkPK4jh6Z_X8JJkHxvQhpyouHQFyGxgBrl24x-_EB1zbWMhJthmm8DiKt-nzKaJz8Cju1-HwCpg76CRqRsEz2hyKEpbb4M5KQSj3AsENCroVmQ5QIv3K2XNRkve4vjBmP6sV2b6GSY_UeRvPElA7SUgBGTKbn-c0aYhBuB8plPhRTBa55_cFqAmNmavF1-fdMktJuIaH2f-K0zZCzbHw54998T7kIWgyMsyGCAvynEB_khOqwT7tCjg5HQ8SIjdnRYW0kjZfjt5LJbGA-PnRo8gPVQVGeYDP2vsSXhNJY94AitKCY1srcSsuYDrhNBKrnoJ1uEsMPVHsgFw_ZHMyAEaVQughSNW4fm8q6_1Nv4zLutDITzmAL6a6i6-WS6QRIs_4VUtwr5cXXIFDDeHVWeGcNivQ6W9urEUP4crguiq7z_DTiYaGfUksub-T7mw0zU8ZoOSd5pUTpJLv-IYIUAl6CscHvunnRLEKqpW1Sa1dcFZs5VP4AfR3mg7wX4Vlq1AHnpFxE2L1LZiKoTc9jDEOvTDkxr86gMkwMm6RdyPF_q48AVJ1br8Qp88-4B84X52zZ5cw-IJYe-HiVJ29LpeYm340_rWivpy-UB5i9TKlMrxf94y1okzZTPbP3_v1_XX0nE7RTLz98EA96euJ7l3EpbEqks7mh6i1FJNnvvlM_u29sYobJ6PUT-i1VlQnF_JBARKEz74pBXm1l5Y5Lo15rsIlaQHinUBCO8fHCHI59LAfKusN4JmodDqLYwkWijEL_sfrC6LtrbXqpM1pw09zSrs_tS1RQ-LnWHuPrU5KLCzv53JKrh8lU_cdBowe_F-Ib_Ui4bQ2FME-0mnyG0XijHUsrGMZ9dfowvIkr83JpqwlFOZAwMmSGPNPEJRw9kDshjotndUB5S1UCfv_U4IoVn7WgvxeCS-BBxqyWfh7YTdf73EnmGwVYxVjlXaHCeeTZmUacnT4MQUAcbFjTq6BBlboAQGWP2FZWpd6HNnruv744VeWmfgLk9z5567wFhwuXMkmE2xvDo4wP80xutjUfsePx5YkLxhY1XsWqTZr19tInxJWWq8RLZsWPmtq5wZ5ucBMasCLpOABenYZdSAcQNhC73wLS0Z2s1HQhBoIl7lr1p372LZs_Seu1u_8Fo7DoJqRpKaNoc2_JUMmn7TUZS8zLyzxgeq8R8iNbRP20DwDBNXocsTDBKaQrtB-QiEPySQtJa4G61XeNZyh5aGzfoWZ9OmjZG9pbbehcqwIrt-ESjPyeT6sfSrvOfTZr7fBXwpUs2rS4BrlNse5g_h8CQiik8aaOTOEPkXiyg4s5DewRlgDZHS-3g-YXPUIBNO62_HxknkMpkJvKW-tkvDbgtxvy4nG80ul6W_KeRsoEKDTRYNKZWxXjZITNa0h6agnwNCJKEbFg3Qhre394c0i60mfP9YIgKTXrCX3Yt2eX-6mPzYmLbSbV5jH69v6WZqYV2WAj-9DU0diR4hOfYQaJnBZhTtKb-SQsYiFuN1BDJ3v9eM9K8hq91NBdCHVa-Thk9Dov-JkcTZnZGRRyW5yXHUV4NOEltBXh8GkjjDvs5Yo3u-2rPCXjK1aGPSI1W8BaUJLQY5sbfAVCAuUHBv-Vlh5Qamt-lgeKguhqTSuy-tjabOb5kiBOG7xGQt3z-XYXtnWFDCii-5h11XfZsQ-xQxy8gSfdMz4hDK9Nw_VQt6fzWiQY0Th_dHzVki0MUfVfsDUjgblhD6j0wgbs3zdj-GM3rtt8oit0wXx11bIOaOKgf07tP0wimVXMRqRWe7LCUAKTE5PkRKU1x_h4iusrzi5uwKDhc4SmRwm6KssNrmCAkiNDZCREVKd3yMnrjA4PAGDzdKWVplcHJ6jKmrsbrEztHd9QAAAAAAAAAAAAAAABIf111";
    var p2 = jwt.SigningMethodMLDSA44.init(alloc);
    const parsed2 = p2.parse(token_str2, public_key);
    try testing.expectError(error.JWTVerifyFail, parsed2);
}

test "SigningMethodMLDSA65 Check" {
    const alloc = testing.allocator;

    const pubkey = "QksvJn5Y1bO0TXGs_Gpla7JpUNV8YdsciAvPof6rRD8JQquL2619cIq7w1YHj22ZolInH-YsdAkeuUr7m5JkxQqIjg3-2AzV-yy9NmfmDVOevkSTAhnNT67RXbs0VaJkgCufSbzkLudVD-_91GQqVa3mk4aKRgy-wD9PyZpOMLzP-opHXlOVOWZ067galJN1h4gPbb0nvxxPWp7kPN2LDlOzt_tJxzrfvC1PjFQwNSDCm_l-Ju5X2zQtlXyJOTZSLQlCtB2C7jdyoAVwrftUXBFDkisElvgmoKlwBks23fU0tfjhwc0LVWXqhGtFQx8GGBQ-zol3e7P2EXmtIClf4KbgYq5u7Lwu848qwaItyTt7EmM2IjxVth64wHlVQruy3GXnIurcaGb_qWg764qZmteoPl5uAWwuTDX292Sa071S7GfsHFxue5lydxIYvpVUu6dyfwuExEubCovYMfz_LJd5zNTKMMatdbBJg-Qd6JPuXznqc1UYC3CccEXCLTOgg_auB6EUdG0b_cy-5bkEOHm7Wi4SDipGNig_ShzUkkot5qSqPZnd2I9IqqToi_0ep2nYLBB3ny3teW21Qpccoom3aGPt5Zl7fpzhg7Q8zsJ4sQ2SuHRCzgQ1uxYlFx21VUtHAjnFDSoMOkGyo4gH2wcLR7-z59EPPNl51pljyNefgCnMSkjrBPyz1wiET-uqi23f8Bq2TVk1jmUFxOwdfLsU7SIS30WOzvwD_gMDexUFpMlEQyL1-Y36kaTLjEWGCi2tx1FTULttQx5JpryPW6lW5oKw5RMyGpfRliYCiRyQePYqipZGoxOHpvCWhCZIN4meDY7H0RxWWQEpiyCzRQgWkOtMViwao6Jb7wZWbLNMebwLJeQJXWunk-gTEeQaMykVJobwDUiX-E_E7fSybVRTZXherY1jrvZKh8C5Gi5VADg5Vs319uN8-dVILRyOOlvjjxclmsRcn6HEvTvxd9MS7lKm2gI8BXIqhzgnTdqNGwTpmDHPV8hygqJWxWXCltBSSgY6OkGkioMAmXjZjYq_Ya9o6AE7WU_hUdm-wZmQLExwtJWEIBdDxrUxA9L9JL3weNyQtaGItPjXcheZiNBBbJTUxXwIYLnXtT1M0mHzMqGFFWXVKsN_AIdHyv4yDzY9m-tuQRfbQ_2K7r5eDOL1Tj8DZ-s8yXG74MMBqOUvlglJNgNcbuPKLRPbSDoN0E3BYkfeDgiUrXy34a5-vU-PkAWCsgAh539wJUUBxqw90V1Du7eTHFKDJEMSFYwusbPhEX4ZTwoeTHg--8Ysn4HCFWLQ00pfBCteqvMvMflcWwVfTnogcPsJb1bEFVSc3nTzhk6Ln8J-MplyS0Y5mGBEtVko_WlyeFsoDCWj4hqrgU7L-ww8vsCRSQfskH8lodiLzj0xmugiKjWUXbYq98x1zSnB9dmPy5P3UNwwMQdpebtR38N9I-jup4Bzok0-JsaOe7EORZ8ld7kAgDWa4K7BAxjc2eD540Apwxs-VLGFVkXbQgYYeDNG2tW1Xt20-XezJqZVUl6-IZXsqc7DijwNInO3fT5o8ZAcLKUUlzSlEXe8sIlHaxjLoJ-oubRtlKKUbzWOHeyxmYZSxYqQhSQj4sheedGXJEYWJ-Y5DRqB-xpy-cftxL10fdXIUhe1hWFBAoQU3b5xRY8KCytYnfLhsFF4O49xhnax3vuumLpJbCqTXpLureoKg5PvWfnpFPB0P-ZWQN35mBzqbb3ZV6U0rU55DvyXTuiZOK2Z1TxbaAd1OZMmg0cpuzewgueV-Nh_UubIqNto5RXCd7vqgqdXDUKAiWyYegYIkD4wbGMqIjxV8Oo2ggOcSj9UQPS1rD5u0rLckAzsxyty9Q5JsmKa0w8Eh7Jwe4Yob4xPVWWbJfm916avRgzDxXo5gmY7txdGFYHhlolJKdhBU9h6f0gtKEtbiUzhp4IWsqAR8riHQs7lLVEz6P537a4kL1r5FjfDf_yjJDBQmy_kdWMDqaNln-MlKK8eENjUO-qZGy0Ql4bMZtNbHXjfJUuSzapA-RqYfkqSLKgQUOW8NTDKhUk73yqCU3TQqDEKaGAoTsPscyMm7u_8QrvUK8kbc-XnxrWZ0BZJBjdinzh2w-QvjbWQ5mqFp4OMgY94__tIU8vvCUNJiYA1RdyodlfPfH5-avpxOCvBD6C7ZIDyQ-6huGEQEAb6DP8ydWIZQ8xY603DoEKKXkJWcP6CJo3nHFEdj_vcEbDQ-WESDpcQFa1fRIiGuALj-sEWcjGdSHyE8QATOcuWl4TLVzRPKAf4tCXx1zyvhJbXQu0jf0yfzVpOhPun4n-xqK4SxPBCeuJOkQ2VG9jDXWH4pnjbAcrqjveJqVti7huMXTLGuqU2uoihBw6mGqu_WSlOP2-XTEyRyvxbv2t-z9V6GPt1V9ceBukA0oGwtJqgD-q7NXFK8zhw7desI5PZMXf3nuVgbJ3xdvAlzkmm5f9RoqQS6_hqwPQEcclq1MEZ3yML5hc99TDtZWy9gGkhR0Hs3QJxxgP7bEqGFP-HjTPnJsrGaT6TjKP7qCxJlcFKLUr5AU_kxMULeUysWWtSGJ9mpxBvsyW1Juo";
    const token_str = "eyJhbGciOiJNTC1EU0EtNjUiLCJraWQiOiJTdWl1MjlxYmZ1YUJhUjRBdHMtYzZYUUJlUEJfT3BBeEF3Y1RSXzBLWFZNIn0.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4.zmO9_0bLgJAegoVNymfRo4nGPK5lVtSFGnDbzfzYAD5mUEXpaBUg4itvZ8rAUZi4HLb59QqDQSBSpMXC0axajXOMV_YttfmwGgC6FMyaMRZkx-A92bGiNLutqX9jcwRLJqXjMkUGhz2YpHe_mV9QpxokRCH9K6jkyFZp4hZIwFXhRt1z0OGIa5rOoHKsxOCAUZhTXKiASb3vk9lUASW0-Y58WKT4rVmst7_dvk7FVbe9A9I21IH-Tqlg1zSMoI8ozh1aBSG92uPursBd5KRcOlJwhNUYJDgHScIHXM6Hzk6u98W5orKPHu1rDIK7rHJI4Zrui4wBjmQLsPE01LcZHRx4zexDCTMCGSojbL1FiT9CU3oUep4oWOytTEAf2eCi3qDD0iSrp5IslCueoNjtGOFSnUKlsnCeiZF-tNqTy1KpJ3ErTaNPcCzCvsEalhJwFa7NOWyQOEJUzcLaPY_VEFwcCX1Gk4bEI-1rLDiyZqkXgny-U2oRnll0d3u-e2S_Rg-_eL1H_XEbPs_km-822G7JY9li4muZ5KVvfQf_5hza1V4GweqvmeWuZL1gBU2HPS7x1tWL798ALOk1rMnxsvBOPiSLxAEdPoIuw0_qMlKjTavJcDFaihgCgGMUk5SjU65IWQS9t4rgxv9Idu0OCsozo9iCBqrVcnaOwUpkMhV6KeiXA7kQNcegVaMio40cjSyMiEkhGIOEOf8L6eohOh_bPPRYs-8NrZ-VOBJCa0ubJcDU1cTuGNCa7nWWxAqfVjcMyNDx9XHBYBnSOcFNfMP7S9nvqw3KC50U_t2PH5SfwS9w4DLvcgrlEP_gwSgOXuf-i0tRGLQly3IMB7O8QOnkofyFaCUDZeurFkGTpoBfT6lzbJznQAMIDPNcWUsRlNTXsH7atC1nxl4xDJLmmPLCxiErfxbCW5gMWox0kLDwfsFj57hsXG75cZ4jiBbq9b0VjD7Vkf8xlc06ExdzBhGXz8oJiaT5WHDsuzGtrFmh6diN1cO4Cxjr6KdNE8IlyxsfXxQ4AI-0ke3gMyi0DOGeHgHuNc-JHD7oZ6njUMSTBkR1aUMNT7n_2nfFTDCdqW1HaMsMwIHfLOk6dayKXE1oMqY5Op8S5k_SAaknR0vNxmhlTA5h3bZJ28NZxM6R7D00_eBEYrH20rmRP7G7kXKzLvmWeaKAh4oQHiqjVhgauiePDRiMmjx0OhdQnMCtO8PWbx06SiviRn_5hswdVV08B48MVHqbM2AxCLLJYinC2Ep0302Uo0DI-rTNZ1Znn58kM7VCskcxDLsH9AYvPz-HQr3H7Xg0ElwjYn-jJXgZ_cdnLFt4_TuKQdpw_qhvyrNjOx0Mdc-1PrwoWqpA9sSv_pS5lwI2qNVHI2Vj2mZHByod1QUeOQExf3SBjP_FHEAUzUu1OK8M-1SQZGzJT2su3a6ZnMnp0U5qdXyMONFoI2jJ2hDjt7QEQsLx-rvaLxZMJtc2z0MHdwJGAC_kug7XjH3SWQZzBu7zzreIaSwr2A2oobeZiAydwb8LX2QsY9Jr_NphGAMAqzrpkuaMyBd_pFTKMp9s0GYxwyG1ZD9uRuPI9imA4CS7bt-O8YvbWg6eQ-qa9OqDlxNt3Xc32TniQFVxVxN6PDY33XXU-Rpvd1w47NZ48nkyJzjD8Xlbvk9p2ynxWHr-Sto5HXZdru4j8ETUW7ri3mEG1m_dxAbAe2kVbsBp2I1vQppugbmRexuMRLdYFIKqNm0qpQoWTr_k2t5KHnWolrSbFH7Usm8Pwyi4sNhh4_yRHADO2q2o19zCCx2plDSMeYI74CQPRGLlK_GLM4E5Bzfny3E2eaE5_gQBTSGNHpQtJB0ipPwDjqsjDCXqXupCkRta1vxng4coi2-vWYvKu6mq9HhdovHAaWrZRyvuPPI4ZDN_NkmfQR8HogR6NLVhLlRp1cwMArSSDA3f8QlnjdbaeutxRXvFnCCjBk79ws8VGdWAuRmIWgoEFeVAVxkJjJ07zOW8I3kNfB6pnxsZmJwWAGqWc1UlPmkNBstmSXinAzbdl-W-kn1XRDuhzTafHnkCbKS5XgJKsWD2FrhcnCaxxRxuxIGxijofjD4ihmJoYDFh1FYs9IcC-szEfMSekanWOIZCHd1fVzTSbLr5bNaOXR2sO1muFX7w22m8pBVD3fyOHK2JnK4FBCnEBrruMIDaqqu8Z4xesAHKfxY67w-25eUuvVCGL3xpXSyp90684ICkG4STztP1shLVsxKDA-37sKKplqemERlMPY4vDM1Np8JlVawbSGIuom20g6p2KV_zpIPwx9vd1nAiaeZbryf3N5gtL-dOq-c6uZhTCx9OLBtLGE3BcAmn5JFjMGQFxyTL07BluNu24Kf-lttGj9jzbwPZYrok-SnMilXGFEqB3D3cKCOlWjsgg_3cUW1uMp4KlWQvkimV9Pd7cY70w607jcYBJ3MlFZ8EeWeYPZ9qu6xwidA8XlLHxXxfLIJOgfpU8MTppfxdnMhqNSvH_Hx57oDphbUks5K1Z8-O4dSnNqQ-ZWbhaAydYQFDKuUF6HYTAvaWhJmACxhTkTp2t6-P3bev-FcdFIdszJC9LxWtJ96LY_GV4Qvp0hiIdyP1BukWNHtsXK2Rxres3_4Cndg2BOGxVcKZ9YpQDCUy76GRbTCenqjD-SG5sVUEVha5yxbKArPr2-Xpgk8cuZBRSAdmPNRdxCgUtldfCLeL7xhJvryMouxfQ75PMBaImHcsMd95075ePt_VkClUaUj55Y9E81FbOEchPfud2w3TtSvRPvB8-RgY8sLJUAclxcUGE4PnKSZJ7TIBUtHD6uyZ0-nC5KGxbXZsBEzUeHns4ix0Wmo6-6vAM4PGK3qRA1VAhtKXyvNcAfVccVi8KJMK9Mz2eIOXPATvyRy34Ltrcg8tcgK0ftYqEWYpAZ2fVpZBXcYfTIinuLN0-qLra388EZuu59jvmRD7mUv1msMWVMGVeBoNP3lJaJGGWK8iYyu4q7Grq-6WXr5qCz_7kwAtVJdb-zW8U3jLJ3tRSYlyjlpzeVAGjDQ6Yni5y9x4BF-5QUqcoGMLLglyx2WOCELT8IW7nsV21QnqqAbtCzZ76UtEdmUuEOTyqiKQZ0lrjMRm3YrCvJKxtR5thhTRka708NzBvwSRs-JxGG__EWjHhT-aB4VL3IL_oz3mt3iQoszfA-SzHcKU1laZMBuUCyxks6KiJgQGZRPXyaxxDtqZdaRP8Ic5CmuPeyu3kafi0L6LFijsUxnSGxTpgu7hfvcmowQijfE9_ylvg8k_EbI2miG11giODVCYb7k9Yjyriwc9dSUUZ7XoiS24hWYUX6BGGQNN3wVHPkDkOVSDBYTjto99ulquryx4K_UMCu9sQVNxBfMh8tLN7O9-MXlnJbHfKfqFHiPGdIYOBpwuqJdAJiyiuSG3gJxMG_wuwNkBWoO--iOm6PIarCyvL8_P-tuUfT4zIgjJJ3o6YJhbo-q2K82ZFmHuILyzfDSGtHDZpZIR7XnRQWet90cJEHL5k653kvyEHJg0iUiE0iwNA5d_4gBq3vmw1J74hwAHx0Z_iYEcPS6hDGow8M8D7UJTZDkUV_86zj2YqGm_QC_aAeD__NP6sa61bI9-gTOzvYc0JiExKTDjOK9fIvHaV-HN4xr2vWner8o6jPyETvGM8D7aEezlUVOEFwALmhJPSMAq_Fk9JlcIUuC-ITJZNtNz9Awfiru3wkPja1bXN76WAuRHjia0x5ptgMCy2py_vSHZybfIS85ZjsOQ-i_e_niBzhyzXwzBaLEyEitbF4ZQx5c88lXKDMpe9tirAI6XAcqLf4UZkD8Wm2YV7hhVfxLQ1AWLekWE9DZljCtE-SbS1EWNGR8faXKCvaZznRyoqdWz8IN3w7KvaA_ZrEKkIXkkreztG6pI06DlDHCl_sU6rCOoyQf6y1AY77Ob4SdkSRoBHGgR6Uv-LrxHpyJ6trzccu0kqxubHrkW2yHcqe6enVf43zYwWKUeJJZ10bt3a92ziSne-3aj6v3guiKoJoLnV_9h8rUF6zorTWE-Tq58tYfb5SmGf4iCJ5cy9LTY0COIfwJtPkUmyBCZwUhWJnV24P5pOZPe_CckQ28xv5J7Zf4Bvqrq_rhubFEhTJ5JvdMfz8Whc56WSHX7GRKEMqXVp3pHohBvOyT9BmotzIlibVklJy4gzkzUcjJJOld-BOaM_cnMiHpoyKXSJAXTNwXngzEpbvDP2Y0fnrgqDpO3RR3gINaZLRmeG0WI4wWBMMfw8PHjpyV17C_1hmfRI-darbZcX7PD3N4Rw4lBACyk_wnOHBcAS-5cLZEzNmFmhc4iO4msz_seQ1N0drbB0NoUVWBmcY3pGC9TiY6f6Pn-FBUnQkuBhIyPtgAAAAAAAAAABgwVHCUv";

    const pubkey_bytes = try jwt.utils.base64UrlDecode(alloc, pubkey);
    defer alloc.free(pubkey_bytes);

    const PublicKey = jwt.mldsa.MLDSA65.PublicKey;

    var pubkey_bytes2: [PublicKey.encoded_length]u8 = undefined;
    @memcpy(pubkey_bytes2[0..], pubkey_bytes[0..]);

    const public_key = try PublicKey.fromBytes(pubkey_bytes2);

    var p = jwt.SigningMethodMLDSA65.init(alloc);
    var parsed = try p.parse(token_str, public_key);
    defer parsed.deinit();

    const header2 = try parsed.getHeaderRaw();
    defer alloc.free(header2);
    const header_str =
        \\{"alg":"ML-DSA-65","kid":"Suiu29qbfuaBaR4Ats-c6XQBePB_OpAxAwcTR_0KXVM"}
    ;
    try testing.expectFmt(header_str, "{s}", .{header2});

    const claims2 = try parsed.getClaimsRaw();
    defer alloc.free(claims2);
    try testing.expectFmt("It’s a dangerous business, Frodo, going out your door.", "{s}", .{claims2});

    // =========

    const token_str2 = "eyJhbGciOiJNTC1EU0EtNjUiLCJraWQiOiJTdWl1MjlxYmZ1YUJhUjRBdHMtYzZYUUJlUEJfT3BBeEF3Y1RSXzBLWFZNIn0.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4.zmO9_0bLgJAegoVNymfRo4nGPK5lVtSFGnDbzfzYAD5mUEXpaBUg4itvZ8rAUZi4HLb59QqDQSBSpMXC0axajXOMV_YttfmwGgC6FMyaMRZkx-A92bGiNLutqX9jcwRLJqXjMkUGhz2YpHe_mV9QpxokRCH9K6jkyFZp4hZIwFXhRt1z0OGIa5rOoHKsxOCAUZhTXKiASb3vk9lUASW0-Y58WKT4rVmst7_dvk7FVbe9A9I21IH-Tqlg1zSMoI8ozh1aBSG92uPursBd5KRcOlJwhNUYJDgHScIHXM6Hzk6u98W5orKPHu1rDIK7rHJI4Zrui4wBjmQLsPE01LcZHRx4zexDCTMCGSojbL1FiT9CU3oUep4oWOytTEAf2eCi3qDD0iSrp5IslCueoNjtGOFSnUKlsnCeiZF-tNqTy1KpJ3ErTaNPcCzCvsEalhJwFa7NOWyQOEJUzcLaPY_VEFwcCX1Gk4bEI-1rLDiyZqkXgny-U2oRnll0d3u-e2S_Rg-_eL1H_XEbPs_km-822G7JY9li4muZ5KVvfQf_5hza1V4GweqvmeWuZL1gBU2HPS7x1tWL798ALOk1rMnxsvBOPiSLxAEdPoIuw0_qMlKjTavJcDFaihgCgGMUk5SjU65IWQS9t4rgxv9Idu0OCsozo9iCBqrVcnaOwUpkMhV6KeiXA7kQNcegVaMio40cjSyMiEkhGIOEOf8L6eohOh_bPPRYs-8NrZ-VOBJCa0ubJcDU1cTuGNCa7nWWxAqfVjcMyNDx9XHBYBnSOcFNfMP7S9nvqw3KC50U_t2PH5SfwS9w4DLvcgrlEP_gwSgOXuf-i0tRGLQly3IMB7O8QOnkofyFaCUDZeurFkGTpoBfT6lzbJznQAMIDPNcWUsRlNTXsH7atC1nxl4xDJLmmPLCxiErfxbCW5gMWox0kLDwfsFj57hsXG75cZ4jiBbq9b0VjD7Vkf8xlc06ExdzBhGXz8oJiaT5WHDsuzGtrFmh6diN1cO4Cxjr6KdNE8IlyxsfXxQ4AI-0ke3gMyi0DOGeHgHuNc-JHD7oZ6njUMSTBkR1aUMNT7n_2nfFTDCdqW1HaMsMwIHfLOk6dayKXE1oMqY5Op8S5k_SAaknR0vNxmhlTA5h3bZJ28NZxM6R7D00_eBEYrH20rmRP7G7kXKzLvmWeaKAh4oQHiqjVhgauiePDRiMmjx0OhdQnMCtO8PWbx06SiviRn_5hswdVV08B48MVHqbM2AxCLLJYinC2Ep0302Uo0DI-rTNZ1Znn58kM7VCskcxDLsH9AYvPz-HQr3H7Xg0ElwjYn-jJXgZ_cdnLFt4_TuKQdpw_qhvyrNjOx0Mdc-1PrwoWqpA9sSv_pS5lwI2qNVHI2Vj2mZHByod1QUeOQExf3SBjP_FHEAUzUu1OK8M-1SQZGzJT2su3a6ZnMnp0U5qdXyMONFoI2jJ2hDjt7QEQsLx-rvaLxZMJtc2z0MHdwJGAC_kug7XjH3SWQZzBu7zzreIaSwr2A2oobeZiAydwb8LX2QsY9Jr_NphGAMAqzrpkuaMyBd_pFTKMp9s0GYxwyG1ZD9uRuPI9imA4CS7bt-O8YvbWg6eQ-qa9OqDlxNt3Xc32TniQFVxVxN6PDY33XXU-Rpvd1w47NZ48nkyJzjD8Xlbvk9p2ynxWHr-Sto5HXZdru4j8ETUW7ri3mEG1m_dxAbAe2kVbsBp2I1vQppugbmRexuMRLdYFIKqNm0qpQoWTr_k2t5KHnWolrSbFH7Usm8Pwyi4sNhh4_yRHADO2q2o19zCCx2plDSMeYI74CQPRGLlK_GLM4E5Bzfny3E2eaE5_gQBTSGNHpQtJB0ipPwDjqsjDCXqXupCkRta1vxng4coi2-vWYvKu6mq9HhdovHAaWrZRyvuPPI4ZDN_NkmfQR8HogR6NLVhLlRp1cwMArSSDA3f8QlnjdbaeutxRXvFnCCjBk79ws8VGdWAuRmIWgoEFeVAVxkJjJ07zOW8I3kNfB6pnxsZmJwWAGqWc1UlPmkNBstmSXinAzbdl-W-kn1XRDuhzTafHnkCbKS5XgJKsWD2FrhcnCaxxRxuxIGxijofjD4ihmJoYDFh1FYs9IcC-szEfMSekanWOIZCHd1fVzTSbLr5bNaOXR2sO1muFX7w22m8pBVD3fyOHK2JnK4FBCnEBrruMIDaqqu8Z4xesAHKfxY67w-25eUuvVCGL3xpXSyp90684ICkG4STztP1shLVsxKDA-37sKKplqemERlMPY4vDM1Np8JlVawbSGIuom20g6p2KV_zpIPwx9vd1nAiaeZbryf3N5gtL-dOq-c6uZhTCx9OLBtLGE3BcAmn5JFjMGQFxyTL07BluNu24Kf-lttGj9jzbwPZYrok-SnMilXGFEqB3D3cKCOlWjsgg_3cUW1uMp4KlWQvkimV9Pd7cY70w607jcYBJ3MlFZ8EeWeYPZ9qu6xwidA8XlLHxXxfLIJOgfpU8MTppfxdnMhqNSvH_Hx57oDphbUks5K1Z8-O4dSnNqQ-ZWbhaAydYQFDKuUF6HYTAvaWhJmACxhTkTp2t6-P3bev-FcdFIdszJC9LxWtJ96LY_GV4Qvp0hiIdyP1BukWNHtsXK2Rxres3_4Cndg2BOGxVcKZ9YpQDCUy76GRbTCenqjD-SG5sVUEVha5yxbKArPr2-Xpgk8cuZBRSAdmPNRdxCgUtldfCLeL7xhJvryMouxfQ75PMBaImHcsMd95075ePt_VkClUaUj55Y9E81FbOEchPfud2w3TtSvRPvB8-RgY8sLJUAclxcUGE4PnKSZJ7TIBUtHD6uyZ0-nC5KGxbXZsBEzUeHns4ix0Wmo6-6vAM4PGK3qRA1VAhtKXyvNcAfVccVi8KJMK9Mz2eIOXPATvyRy34Ltrcg8tcgK0ftYqEWYpAZ2fVpZBXcYfTIinuLN0-qLra388EZuu59jvmRD7mUv1msMWVMGVeBoNP3lJaJGGWK8iYyu4q7Grq-6WXr5qCz_7kwAtVJdb-zW8U3jLJ3tRSYlyjlpzeVAGjDQ6Yni5y9x4BF-5QUqcoGMLLglyx2WOCELT8IW7nsV21QnqqAbtCzZ76UtEdmUuEOTyqiKQZ0lrjMRm3YrCvJKxtR5thhTRka708NzBvwSRs-JxGG__EWjHhT-aB4VL3IL_oz3mt3iQoszfA-SzHcKU1laZMBuUCyxks6KiJgQGZRPXyaxxDtqZdaRP8Ic5CmuPeyu3kafi0L6LFijsUxnSGxTpgu7hfvcmowQijfE9_ylvg8k_EbI2miG11giODVCYb7k9Yjyriwc9dSUUZ7XoiS24hWYUX6BGGQNN3wVHPkDkOVSDBYTjto99ulquryx4K_UMCu9sQVNxBfMh8tLN7O9-MXlnJbHfKfqFHiPGdIYOBpwuqJdAJiyiuSG3gJxMG_wuwNkBWoO--iOm6PIarCyvL8_P-tuUfT4zIgjJJ3o6YJhbo-q2K82ZFmHuILyzfDSGtHDZpZIR7XnRQWet90cJEHL5k653kvyEHJg0iUiE0iwNA5d_4gBq3vmw1J74hwAHx0Z_iYEcPS6hDGow8M8D7UJTZDkUV_86zj2YqGm_QC_aAeD__NP6sa61bI9-gTOzvYc0JiExKTDjOK9fIvHaV-HN4xr2vWner8o6jPyETvGM8D7aEezlUVOEFwALmhJPSMAq_Fk9JlcIUuC-ITJZNtNz9Awfiru3wkPja1bXN76WAuRHjia0x5ptgMCy2py_vSHZybfIS85ZjsOQ-i_e_niBzhyzXwzBaLEyEitbF4ZQx5c88lXKDMpe9tirAI6XAcqLf4UZkD8Wm2YV7hhVfxLQ1AWLekWE9DZljCtE-SbS1EWNGR8faXKCvaZznRyoqdWz8IN3w7KvaA_ZrEKkIXkkreztG6pI06DlDHCl_sU6rCOoyQf6y1AY77Ob4SdkSRoBHGgR6Uv-LrxHpyJ6trzccu0kqxubHrkW2yHcqe6enVf43zYwWKUeJJZ10bt3a92ziSne-3aj6v3guiKoJoLnV_9h8rUF6zorTWE-Tq58tYfb5SmGf4iCJ5cy9LTY0COIfwJtPkUmyBCZwUhWJnV24P5pOZPe_CckQ28xv5J7Zf4Bvqrq_rhubFEhTJ5JvdMfz8Whc56WSHX7GRKEMqXVp3pHohBvOyT9BmotzIlibVklJy4gzkzUcjJJOld-BOaM_cnMiHpoyKXSJAXTNwXngzEpbvDP2Y0fnrgqDpO3RR3gINaZLRmeG0WI4wWBMMfw8PHjpyV17C_1hmfRI-darbZcX7PD3N4Rw4lBACyk_wnOHBcAS-5cLZEzNmFmhc4iO4msz_seQ1N0drbB0NoUVWBmcY3pGC9TiY6f6Pn-FBUnQkuBhIyPtgAAAAAAAAAABgwVH111";
    var p2 = jwt.SigningMethodMLDSA65.init(alloc);
    const parsed2 = p2.parse(token_str2, public_key);
    try testing.expectError(error.JWTVerifyFail, parsed2);
}

test "SigningMethodMLDSA87 Check" {
    const alloc = testing.allocator;

    const pubkey = "5F_8jMc9uIXcZi5ioYzY44AylxF_pWWIFKmFtf8dt7Roz8gruSnx2Gt37RT1rhamU2h3LOUZEkEBBeBFaXWukf22Q7US8STV5gvWi4x-Mf4Bx7DcZa5HBQHMVlpuHfz8_RJWVDPEr-3VEYIeLpYQxFJ14oNt7jXO1p1--mcv0eQxi-9etuiX6LRRqiAt7QQrKq73envj9pkUbaIpqL2z_6SWRFln51IXv7yQSPmVZEPYcx-DPrMN4Q2slv_-fPZeoERcPjHoYB4TO-ahAHZP4xluJncmRB8xdR-_mm9YgGRPTnJ15X3isPEF5NsFXVDdHJyTT931NbjeKLDHTARJ8iLNLtC7j7x3XM7oyUBmW0D3EvT34AdQ6eHkzZz_JdGUXD6bylPM1PEu7nWBhW69aPJoRZVuPnvrdh8P51vdMb_i-gGBEzl7OHvVnWKmi4r3-iRauTLmn3eOLO79ITBPu4CZ6hPY6lfBgTGXovda4lEHW1Ha04-FNmnp1fmKNlUJiUGZOhWUhg-6cf5TDuXCn1jyl4r2iMy3Wlg4o1nBEumOJahYOsjawfhh_Vjir7pd5aUuAgkE9bQrwIdONb788-YRloR2jzbgCPBHEhd86-YnYHOB5W6q7hYcFym43lHb3kdNSMxoJJ6icWK4eZPmDITtbMZCPLNnbZ61CyyrWjoEnvExOB1iP6b7y8nbHnzAJeoEGLna0sxszU6V-izsJP7spwMYp1Fxa3IT9j7b9lpjM4NX-Dj5TsBxgiwkhRJIiFEHs9HE6SRnjHYU6hrwOBBGGfKuNylAvs-mninLtf9sPiCke-Sk90usNMEzwApqcGrMxv_T2OT71pqZcE4Sg8hQ2MWNHldTzZWHuDxMNGy5pYE3IT7BCDTGat_iu1xQGo7y7K3Rtnej3xpt64br8HIsT1Aw4g-QGN1bb8U-6iT9kre1tAJf6umW0-SP1MZQ2C261-r5NmOWmFEvJiU9LvaEfIUY6FZcyaVJXG__V83nMjiCxUp9tHCrLa-P_Sv3lPp8aS2ef71TLuzB14gOLKCzIWEovii0qfHRUfrJeAiwvZi3tDphKprIZYEr_qxvR0YCd4QLUqOwh_kWynztwPdo6ivRnqIRVfhLSgTEAArSrgWHFU1WC8Ckd6T5MpqJhN0x6x8qBePZGHAdYwz8qa9h7wiNLFWBrLRj5DmQLl1CVxnpVrjW33MFso4P8n060N4ghdKSSZsZozkNQ5b7O6yajYy-rSp6QpD8msb8oEX5imFKRaOcviQ2D4TRT45HJxKs63Tb9FtT1JoORzfkdv_E1bL3zSR6oYbTt2Stnpz-7kVqc8KR2N45EkFKxDkRw3IXOte0cq81xoU87S_ntf4KiVZaszuqb2XN2SgxnXBl4EDnpehPmqkD92SAlLrQcTaxaSe47G28K-8MwoVt4eeVkj4UEsSfJN7rbCH2yKl2XJx5huDaS0xn2ODQyNRmgk-5I9hXMUiZDNLvEzx4zuyrcu2d0oXFo3ZoUtVFNCB__TQCf2x27ej9GjLXLDAEi7qnl9Xfb94n0IfeVyGte3-j6NP3DWv8OrLiUjNTaLv6Fay1yzfUaU6LI86-Jd6ckloiGhg7kE0_hd-ZKakZxU1vh0Vzc6DW7MFAPky75iCZlDXoBpZjTNGo5HR-mCW_ozblu60U9zZA8bn-voANuu_hYwxh-uY1sHTFZOqp2xicnnMChz_GTm1Je8XCkICYegeiHUryEHA6T6B_L9gW8S_R4ptMD0Sv6b1KHqqKeubwKltCWPUsr2En9iYypnz06DEL5Wp8KMhrLid2AMPpLI0j1CWGJExXHpBWjfIC8vbYH4YKVl-euRo8eDcuKosb5hxUGM9Jvy1siVXUpIKpkZt2YLP5pEBP_EVOoHPh5LJomrLMpORr1wBKbEkfom7npX1g817bK4IeYmZELI8zXUUtUkx3LgNTckwjx90Vt6oVXpFEICIUDF_LAVMUftzz6JUvbwOZo8iAZqcnVslAmRXeY_ZPp5eEHFfHlsb8VQ73Rd_p8XlFf5R1WuWiUGp2TzJ-VQvj3BTdQfOwSxR9RUk4xjqNabLqTFcQ7As246bHJXH6XVnd4DbEIDPfNa8FaWb_DNEgQAiXGqa6n7l7aFq5_6Kp0XeBBM0sOzJt4fy8JC6U0DEcMnWxKFDtMM7q06LubQYFCEEdQ5b1Qh2LbQZ898tegmeF--EZ4F4hvYebZPV8sM0ZcsKBXyCr585qs00PRxr0S6rReekGRBIvXzMojmid3dxc6DPpdV3x5zxlxaIBxO3i_6axknSSdxnS04_bemWqQ3CLf6mpSqfTIQJT1407GB4QINAAC9Ch3AXUR_n1jr64TGWzbIr8uDcnoVCJlOgmlXpmOwubigAzJattbWRi7k4QYBnA3_4QMjt73n2Co4-F_Qh4boYLpmwWG2SwcIw2PeXGr2LY2zwkPR4bcSyx1Z6UK5trQpWlpQCxgsvV_RvGzpN22RtHoihPH74K0cBIzCz7tK-jqeuWl1A7af7KmQ66fpRBr5ykTLOsa17WblkcIB_jDvqKfEcdxhPWJUwmOo4TIQS-xH8arLOy_NQFG2m14_yxwUemXC-QxLUYi6_FIcqwPBKjCdpQtadRdyftQSKO0SP-GxUvamMZzWI780rXuOBkq5kyYLy9QF9bf_-bL6QLpe1WMCQlOeXZaCPoncgYoT0WZ17jB52Xb2lPWsyXYK54npszkbKJ4OIqfvF8xqRXcVe22VwJuqT9Uy4-4KKQgQ7TXla7Gdm2H7mKl8YXQlsGCT2Ypc8O4t0Sfw7qYAuaDGf752Hbm3fl1bupcB2huIPlIaDP6IRR9XvTYIW2flbwYfhKLmoVKnG85uUi2qtqCjPOIuU3-peT0othfmwKQXaoOqO-V4r6wPL1VHxVFtIYmEdVt0RccUOvpOVR_OAHG9uHOzTmueK5557Qxp0ojtZCHyN-hgoMZJLrvdKkTCxPNo2-mZQbHoVh2FnThZ9JbO49dB8lKXP4_MU5xAnjXMgKXtbfI8w6ZWATE_XWgf2VQMUpGp4wpy44yWQTxHxh_4T9540BGwG0FU0bkgrwA_erseGZnepqdmz5_ScCs84O5Xr5MbYhJLCGGxY6O5GqS-ooB2w0Mt87KbbE4bpYje9CAHH8FX3pDrJyLsyasA3zxmk4OmGpG7Z70ofONJtHRe56R5287vFmuazEEutXn81kNzB-3aJT1ga3vnWZw4CSvFKoWYSA7auLgrHSHFZdITfOrgtmQmGbFhM9kSBdY1UCnpzf65oos3PZWRa2twfUxxLAnPNtrxpRGyvtsapw7ljUagZmuyh3hLCjhAxYmnoE1dbyIWvpCqSlEtVjL1yb_nuLEzgvmZuV02fHxGuWgHTOMVGXpf81Rce3eoBK3lapW1wkzezlk3tcA2bZOtA9qbxdsbVR37kemzQ9K1e3Y0OWhtSj";
    const token_str = "eyJhbGciOiJNTC1EU0EtODciLCJraWQiOiJ0Um4xSk5Ja2dNc0FCVlFCbFhlREh4QUljY2xoLTJJWDBVZERFelB0NVhVIn0.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4.hmMrKkUgZwGPQV_WUoXUVq_Z9WOenDZbfMmHpKritl0btWi29TC8eIyQyT1FAuW2kg3h6ALsvCrjX5tn3QKFQZYC0sBdRt0VNiDm0BjyJ4jWcomSCgb0-cGXaLlODAz-njGridYfO1DpGMwHHshuKuvECv4qnX3XgZPE-6C8La43TZrYO8brzBXGiuyGMLq-TSmXavOeiadtpp6iTUqJDBgQSYvPB6PvipeCPlQH2ZQi8qkraxspi0lgy8Jh2aRYj44DX2ZKq-Ml-hfBJB4iHRpWmwPpEH7Ed4LkBIlaqZoPccrPgpGQpyz4_FcahrJc8CGGtTO5I34o5BcuZej7WOQvJ6mRmvYqIrYwoLs-3_YFZkVdX4KU38oprMvAHjObOhy_vZZArMnCgfYlCKrANbhOZG8O0BXgqow5Bqv_oRIztGQZMrivp_1CS0hELarwkwjdqyH5R747ndV26IQkeyn6y9daXRZIWxaC9KmAaDSm5-YsRVpiAAr0QmfaV51z065_r5qZmOMFIBERVi9Bbm_Z7ipJkoIL2SqVsePATfHeWB8huFpVFxdeEkJUPDuBtthax0HhxpRuECpFNJf2xA70Hp5C5VZIsi5EO21HuRpixiNKmXP5whhsn_uv_B7R4f4DX6X6A53lFrUfpFIrTfOQvBAvmEUUTSGcPeT-F7f_1lz34uFyN3ZT4FCeCh4n4yyZY1fSPVMNtOfK8GrLrRoWdi8gMk30oTKgb9zFkFU7uZhVEVRV86A_060bgFSHWDz5dlXLfyCoJsbsHlO9WBibTCkrMv6lnjh4czprro2prRtJAJB2jVwS1dv2mo4wP1lFYqY63yM9I9deU4fxy6mkwig7XwcVJskg8jX_0agATqmrKfYWMI4yGQ9fciYacgN8X2uSHqiPU1cgQ8VUGsSAsw4POdZpmcUt_DacVLT8-qwnq6NWpm8bqm_uUQu3JjqcHKLz7zWKopeLG_ZY7a45IqUQpwbMg9ICE1ZNTe5nsMHAJnevgLfWk14wnvVQyRVvlSvatdUTg0EjBc6P35a4lY12vIOq2ENpA-m52TfXeXxXK0vtZfT9SY33thi4EfZABWL_jQyiio6b6Akrh6_PgQ-bh2H2Fpu8Z3GImrbHodcbnqFpmKYlMLwxDHnKPxY7PpyyV8HsWfEjqVlAX56stAIIG4_owwzMZMcFwgucAP176TwjaXJqm9v2-DXisD2cNjyGlJ_rec670rv61thjiJF2uZrB9Z2zoQVYnc3Y9sJMMPPmunUcXpNVZWSsPlFDoPa1ABoFnRbP8rO-qbNGP5N7xY2DuPRYOp3CdyxeyDPmGBC2556FNeLRj-PhPAkd61fgXsQZyS9N2jHmFUIKbL8o-e3bQnqW7ebEn7zAjS_LQ2DtgIdIneUu84hh8AduoW9ky_aOpqvBUmdnHUwZHQiSSdeCPnEOssVBbuDd3gbcQf_VWvplwcjTTrJPsqqZpirjfVGPFUCVAz6kD0vhFcvTdQt6DGqys61xg_VOfj6wxpKsXuXDuqwaeb4KpGniHx-23nECgKG86N_1BBX8RRAvYnksxIIxIxgyrng-y44CV9FL_wGfP0Plx6JjSUFOL1gDZTc5NrAPoOztEo1FbJ2Lq8gqBR9Ku9Yza3aYANAJQvAraTXzA0t1j6qcmh-WtXeI1GE-8neOJtlRVbzT5RvPiRJZAVmu9Pg97wbLLQNPJoqIYp-c9mieGsDxAi75C2M1ArRnCa4kJJXrupgzQzzFefWyaRkIvC2MP9MwB_Z_NY3mp3opcNlT1TdKLr1sncLUkk3qJ0Pwyr-5dsKrC6aenapBHO7G0OnA0qTi8-Oy91VqJYYcVjcOUQaxNeMtnk-pLJL7j3MzqNiDkc-OfR19fcWvDmmd9Z8wtj20khL4mTDn7qTUo-PsVR7GnpqkImmEmE8sa4ZlPHa4_IcZGFbdcwp9xuOndINlzWGrIKywFPQ1x26zXDEa7fOx5f01aX8dIU_KWNAGdaZxPIlqLW5qbC6dipSqf9NwblZLJs5DCiLV8nHS-QM26xQJVUNH22n_3Z_8z1SA8AX8d7j0-g1Pf7NZC8e8Ipnm4B3YGpA7nn471aTbJb4OUamfgys17MV_hPDK_f7FF7NXp06-dtVYDmcs-87ZkrDuluOkUaRivKULwjEtSbiiKZAKirGfAOuwyCbbzygEpqYvEztABSmDYd_F_autklob_0deKuvvRYFpVCaxeaYQ7WIkpfBbMxeh9Qci7kPfgyB5H9ajWEJV3fgRk10Q1RaWyTUddQ_jWaluiDa3GD_t39sUrG7QhXc2Oz1NPPNoY6-A4jFbFCtXSF1muztqy0xaworcNiHY18yeL4Cw2iYLJ1Q3O4NnFo3E-wIXmYF4CLxZifr2Jkd6Ix1w-wlsN6vyCcDs8JeAgeJn0_Oahk1mgvRhVz8FFeidSdFqJBxGKbfZ32F_auJwrsLyjN_ShxTSFofyKQy2XCfoVMko4eu5o6md66xBmjZvTvItXL7f-eD0JxISBsBkZG3mFrApZKbdpI1lEa681ZbCxRTYpxUR7McTbs0Q5S9PCN5ElUz_axfeupIIbCTE4S0-ZQuIdQcQ2pn1j-4t2c04jtLE6WFI-1ASBCedlZmrZUiRegbezE01hMiFnfN32BhBu7ZcnlBCdWwj9hUfpEduJIgaA3acXhysGs40nqRzR9imvX9CBQYJZjrCHr-wORF6svmvF5FADRgwbM7Cc9puJgLBiQwXrhD43B6kjX_OXi5O2UNZFkAPr0WONBJsip8CgR6pt1u_mIKlIrYM9kM-idJGGT0DZ9UU4LMx0-9_2KCCkjDqgYN1rS9DA__GP9tS3dJ-XLSlk2URQuoHm4Xubv4vwgjUS7JzAxcQWHB0HtHFoZ3-tYVw_GRbRwyODm3E-N5O3L_R-pva9fvlPjkCNMrf2IlxAxBKML1gCxsSqhFr5yoPeW40LTxMF_dYPNLjC3l7mRRl_wfY_FhvayI7hrgCYfMgWeb-cXyx5eXumt9lMFOD3dQtEG1IUbdE7pVXG-barWK0Zl43DtQMNQzoCK_BLxfCsambyRRcI6E4QTfqe5lWtVf8Wi4KproenWyCjjzEjJQdWw4g-ae_bjGjfZCp38RgsXtWgI_tuzKyRF5WwjyN9VEoRXd8W2DctmBejHF2XDYzbMFkJ-384SokPX6intnlqBGMs0ssxriJhsFOA-vgDra6REx3DUMb8_u_Umc-zp4E6isX4D-eRYgElmj0ez945nqxp3YliO8mRLMW6E4OupLthfw4vmK3YqTAuXcnGxYrf7JqAkMfz5uAPi0SqPWDQZq7ycu9BmkMXAIhMb19XBDjL7hZGDwDRrn9yBBcYlPaFPNXjMJWJH_xxUKNsTFGg5-J_WdxXi8Zn6tDMxbxqqjIpw_FUaM00jJ2MhpbkzhEx7X85pBR47ScRgr6WJpf4ZLSFuV7NT1WI3PIBa_bYeCiq29fp3ShM-1bRFdJG_lGZd97TuAMF_QU6-KDXBv5i8kUZ1NXdJUz-YaA0RRVNFgMGM5n0pKB5IFncAPK-taTzHLIZJ9uuBdP2y2Hxwbw8YQlmy2-MT5XE5Ae_9kxuvIIlSzjpfLN9012HSnX4tZ8x3aWwof3E7s3jjzw7qbBtoUkYYpIGVOKf2EpmhEqevSlXYWpBYN3X2ZYjsrA9CL9PTvrPdyWLwKBmfh7cDJbjNXJSQLeKL7oHzicrllABzR9Ckkz7b24XGV1Klcat_Og4oB9qxiO2zJZWz2GDTAL0hosUlHLWnrQYvqFzzdIOzGlifwIyGgoRNb44IRMzzsErxuoqkdjZewVc4PzruHRlV3cWK6M7ZUiWLtxtMzas2sfAERy8BdS7ISLzj5PERoWyYXSW-898WD3ze5MJcpSsAYNEmPCBtdxF9l-Qz1LxuDa8hOCQ2Wzef1a2WFF5pCBaZRcAK_kef65xRst6WFpjWZGCLZUqHBhFDLEOd7Ikbw7d9V8dc4nAO65NQcxfT9JDUZadS2jmQJip8GLD4P9lGS1Ry-8rHCnMN7zXDp43TfyYhSgv9uj4xKi2wmAMMYBl0n2RNemx8nt-K_dknGgYYGOybDkg2uAUoXdxP33KfiRjbRpYqZVAiq0S45QLAIxxGiDJoZRnyIscdM6lryQtXj0PO67vRf6ifxC3wLv97HHUKergpXcAg-4_rNj_Zx_xiHMfCAe2q3DG1a_DcSmu5u1OPkBHmzHB9Vs8HV0E2-z44sl3Exqb5L8pMYpDnZ7QW-Qb1-S-zoESUy__AKhkRWPC7GmvmJJJHur6SRGSK0X2KyszkEYoe-8NhwpvLrYnNuVk7QknBS91KH2q8C0B8FKqcY40S5ILkImP9iOGIXYl5ZVRleoDBpH9BootWH2az5l7c_e-vfBGs7XpudoAq5wzhe_-AMBvKPCm0BoCX5B_NGUasXvEWobqUb61mpKCuVJdzVtexk-m8Jfvmdc8ooPJEYD_oosY5_S1LuHoc7GHLnoYdDVb2FhIPhOJCLQCef-Y3dtNThqOEo534Zg7R72nSeSQhdQ1hcBUsc50U2oF9OlOnV9z5hsfNwIxdUO9bdoXRYFmosmtpmDfGxAem0s5iPJ0EJ_8szlaX2pi6k6VP-ci-n7J8pEBwL2R3c-ei2iqB7JdLi7Gg6iXVMpQIFTxswh0HbgGtyZXgR_-AM91XRszm_kAlqAHTAJ7B-0Z5bJgMGEY2StBdhGzel_gNPVaxemC3DT0904GbCU2Z3avUHcedebI02_MdILdQxyXbw145KjqC15CqeaG--6x6WzpAuSjrFQRuz6Z5UyibW6Ay9R3P25c-gwmaRM8rPW5YkQtQdfzrtvGZ6wyhIcBXvbpU02OoChfRDF4xI2LvnaW3g6hQIUGe5lueI13ArYRAhZC0LHKPuVfv5OKeMqxYRtcN3YK6Ddc1t61rsA7MU1cAKzOGsiQ7aNyNBQHOV6z-W4-ws_DnZKYRMz0D_hwbeHO0ZKhciXng5VDCX4hyb47LExmO5N1mfihN3iHEkX_19rIgunfkSb9gd9B_AaazAttBEPPLtbsoZneQXBRl3PWiDpC_yXiLTWAd13AOBYHzBMKeJ4hplUqsAGTaGSztbpvV92wz_YX9kMEucHMu5hoM-TJbuWoheiiiKSFBNRK_g_rqXZo1UZjDOnHpHGJxOnlJBPp94Zvwh8sKLOpOd4qeOMLbnYKiag00al5x_3fBXq-KI0Y31OJfgDdCaKAQ0DUX71HN6XDOlvU1Iwh48iASJHdQGDmjhcS8YoeX9omwPiYhcbGJGzEVrn3H7h24eIf_7bVRpicMhjwghB0xtqTT0eVam1l8kr1-5kem7Dr2Kyqm2HpEwbi3KPXKYDXQRbHElEhazMCYr2wnjx_Bx2ai2uZa8uQyjN1zh1cjWHH0TicL2eAyc6YPKfKpmc5QwLrgT0ddQDhvXkCkN50fOR1Sbl56iFoAL8goFl3QA5wBk51vsDsquEt7nlz6sGTHzknENb-eEayrXnw-Q5FueFwqzoJpUrEYDXTxgOU8XVhrPv0Ot-BO6ORfzn3_1gREcHjhrc6RdF01NNqyzyVG0BdckywvAnzUGskWdCfP62dKdx46lAIRVPd3xG4tViaQ79GAeMVnqSeCLXbOyqfnJwhOT2fgQzLwxcj1tqGBBd3Pfx2d5-10WiL_mis0ven6golqaLq1EQsveb9AJpkYgJxdBeyHZXxNLMh4_XAuK1ZIs9F8Cz1vFEVcAFipev-cFyRvsdcNI2-HK2nOGkypEcuVATyLtA0jKeyPtE4TJ3_l8KXltEZjWycQAd_8Tj9is3wisC8bfzjll8UBjFZp-rzmCr8kA4cZih9gl27TiCmhyKhgMfDUIUmuDL_Rn9DLxEAT3Ebl1SW0ToCciNtKTH9oO-wnkPd-jg1HCooLcg-K_QkOTptJNZRFbXpooKqwH5Z9qsCxurZxnS_MscnE0qTa4EqrlpiDnj4FBs4q9SEPlKequfYzFmjQis1iwsReutf6pHmsvRmz9gx5vd6NMIkI05IeLNDElvlOGD04m1vR4ZISdmdHaAgaW9_AUPGx0vP1Rqe36cvebwUYSnzdbZ7y1s7PH7GXF5r7zNEzY9bHmXvsjb3N_u9BkenwkQfZGS6ez0AAAAAAAAAAALGSAlKzg7Qw";

    const pubkey_bytes = try jwt.utils.base64UrlDecode(alloc, pubkey);
    defer alloc.free(pubkey_bytes);

    const PublicKey = jwt.mldsa.MLDSA87.PublicKey;

    var pubkey_bytes2: [PublicKey.encoded_length]u8 = undefined;
    @memcpy(pubkey_bytes2[0..], pubkey_bytes[0..]);

    const public_key = try PublicKey.fromBytes(pubkey_bytes2);

    var p = jwt.SigningMethodMLDSA87.init(alloc);
    var parsed = try p.parse(token_str, public_key);
    defer parsed.deinit();

    const header2 = try parsed.getHeaderRaw();
    defer alloc.free(header2);
    const header_str =
        \\{"alg":"ML-DSA-87","kid":"tRn1JNIkgMsABVQBlXeDHxAIcclh-2IX0UdDEzPt5XU"}
    ;
    try testing.expectFmt(header_str, "{s}", .{header2});

    const claims2 = try parsed.getClaimsRaw();
    defer alloc.free(claims2);
    try testing.expectFmt("It’s a dangerous business, Frodo, going out your door.", "{s}", .{claims2});

    // =========

    const token_str2 = "eyJhbGciOiJNTC1EU0EtODciLCJraWQiOiJ0Um4xSk5Ja2dNc0FCVlFCbFhlREh4QUljY2xoLTJJWDBVZERFelB0NVhVIn0.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4.hmMrKkUgZwGPQV_WUoXUVq_Z9WOenDZbfMmHpKritl0btWi29TC8eIyQyT1FAuW2kg3h6ALsvCrjX5tn3QKFQZYC0sBdRt0VNiDm0BjyJ4jWcomSCgb0-cGXaLlODAz-njGridYfO1DpGMwHHshuKuvECv4qnX3XgZPE-6C8La43TZrYO8brzBXGiuyGMLq-TSmXavOeiadtpp6iTUqJDBgQSYvPB6PvipeCPlQH2ZQi8qkraxspi0lgy8Jh2aRYj44DX2ZKq-Ml-hfBJB4iHRpWmwPpEH7Ed4LkBIlaqZoPccrPgpGQpyz4_FcahrJc8CGGtTO5I34o5BcuZej7WOQvJ6mRmvYqIrYwoLs-3_YFZkVdX4KU38oprMvAHjObOhy_vZZArMnCgfYlCKrANbhOZG8O0BXgqow5Bqv_oRIztGQZMrivp_1CS0hELarwkwjdqyH5R747ndV26IQkeyn6y9daXRZIWxaC9KmAaDSm5-YsRVpiAAr0QmfaV51z065_r5qZmOMFIBERVi9Bbm_Z7ipJkoIL2SqVsePATfHeWB8huFpVFxdeEkJUPDuBtthax0HhxpRuECpFNJf2xA70Hp5C5VZIsi5EO21HuRpixiNKmXP5whhsn_uv_B7R4f4DX6X6A53lFrUfpFIrTfOQvBAvmEUUTSGcPeT-F7f_1lz34uFyN3ZT4FCeCh4n4yyZY1fSPVMNtOfK8GrLrRoWdi8gMk30oTKgb9zFkFU7uZhVEVRV86A_060bgFSHWDz5dlXLfyCoJsbsHlO9WBibTCkrMv6lnjh4czprro2prRtJAJB2jVwS1dv2mo4wP1lFYqY63yM9I9deU4fxy6mkwig7XwcVJskg8jX_0agATqmrKfYWMI4yGQ9fciYacgN8X2uSHqiPU1cgQ8VUGsSAsw4POdZpmcUt_DacVLT8-qwnq6NWpm8bqm_uUQu3JjqcHKLz7zWKopeLG_ZY7a45IqUQpwbMg9ICE1ZNTe5nsMHAJnevgLfWk14wnvVQyRVvlSvatdUTg0EjBc6P35a4lY12vIOq2ENpA-m52TfXeXxXK0vtZfT9SY33thi4EfZABWL_jQyiio6b6Akrh6_PgQ-bh2H2Fpu8Z3GImrbHodcbnqFpmKYlMLwxDHnKPxY7PpyyV8HsWfEjqVlAX56stAIIG4_owwzMZMcFwgucAP176TwjaXJqm9v2-DXisD2cNjyGlJ_rec670rv61thjiJF2uZrB9Z2zoQVYnc3Y9sJMMPPmunUcXpNVZWSsPlFDoPa1ABoFnRbP8rO-qbNGP5N7xY2DuPRYOp3CdyxeyDPmGBC2556FNeLRj-PhPAkd61fgXsQZyS9N2jHmFUIKbL8o-e3bQnqW7ebEn7zAjS_LQ2DtgIdIneUu84hh8AduoW9ky_aOpqvBUmdnHUwZHQiSSdeCPnEOssVBbuDd3gbcQf_VWvplwcjTTrJPsqqZpirjfVGPFUCVAz6kD0vhFcvTdQt6DGqys61xg_VOfj6wxpKsXuXDuqwaeb4KpGniHx-23nECgKG86N_1BBX8RRAvYnksxIIxIxgyrng-y44CV9FL_wGfP0Plx6JjSUFOL1gDZTc5NrAPoOztEo1FbJ2Lq8gqBR9Ku9Yza3aYANAJQvAraTXzA0t1j6qcmh-WtXeI1GE-8neOJtlRVbzT5RvPiRJZAVmu9Pg97wbLLQNPJoqIYp-c9mieGsDxAi75C2M1ArRnCa4kJJXrupgzQzzFefWyaRkIvC2MP9MwB_Z_NY3mp3opcNlT1TdKLr1sncLUkk3qJ0Pwyr-5dsKrC6aenapBHO7G0OnA0qTi8-Oy91VqJYYcVjcOUQaxNeMtnk-pLJL7j3MzqNiDkc-OfR19fcWvDmmd9Z8wtj20khL4mTDn7qTUo-PsVR7GnpqkImmEmE8sa4ZlPHa4_IcZGFbdcwp9xuOndINlzWGrIKywFPQ1x26zXDEa7fOx5f01aX8dIU_KWNAGdaZxPIlqLW5qbC6dipSqf9NwblZLJs5DCiLV8nHS-QM26xQJVUNH22n_3Z_8z1SA8AX8d7j0-g1Pf7NZC8e8Ipnm4B3YGpA7nn471aTbJb4OUamfgys17MV_hPDK_f7FF7NXp06-dtVYDmcs-87ZkrDuluOkUaRivKULwjEtSbiiKZAKirGfAOuwyCbbzygEpqYvEztABSmDYd_F_autklob_0deKuvvRYFpVCaxeaYQ7WIkpfBbMxeh9Qci7kPfgyB5H9ajWEJV3fgRk10Q1RaWyTUddQ_jWaluiDa3GD_t39sUrG7QhXc2Oz1NPPNoY6-A4jFbFCtXSF1muztqy0xaworcNiHY18yeL4Cw2iYLJ1Q3O4NnFo3E-wIXmYF4CLxZifr2Jkd6Ix1w-wlsN6vyCcDs8JeAgeJn0_Oahk1mgvRhVz8FFeidSdFqJBxGKbfZ32F_auJwrsLyjN_ShxTSFofyKQy2XCfoVMko4eu5o6md66xBmjZvTvItXL7f-eD0JxISBsBkZG3mFrApZKbdpI1lEa681ZbCxRTYpxUR7McTbs0Q5S9PCN5ElUz_axfeupIIbCTE4S0-ZQuIdQcQ2pn1j-4t2c04jtLE6WFI-1ASBCedlZmrZUiRegbezE01hMiFnfN32BhBu7ZcnlBCdWwj9hUfpEduJIgaA3acXhysGs40nqRzR9imvX9CBQYJZjrCHr-wORF6svmvF5FADRgwbM7Cc9puJgLBiQwXrhD43B6kjX_OXi5O2UNZFkAPr0WONBJsip8CgR6pt1u_mIKlIrYM9kM-idJGGT0DZ9UU4LMx0-9_2KCCkjDqgYN1rS9DA__GP9tS3dJ-XLSlk2URQuoHm4Xubv4vwgjUS7JzAxcQWHB0HtHFoZ3-tYVw_GRbRwyODm3E-N5O3L_R-pva9fvlPjkCNMrf2IlxAxBKML1gCxsSqhFr5yoPeW40LTxMF_dYPNLjC3l7mRRl_wfY_FhvayI7hrgCYfMgWeb-cXyx5eXumt9lMFOD3dQtEG1IUbdE7pVXG-barWK0Zl43DtQMNQzoCK_BLxfCsambyRRcI6E4QTfqe5lWtVf8Wi4KproenWyCjjzEjJQdWw4g-ae_bjGjfZCp38RgsXtWgI_tuzKyRF5WwjyN9VEoRXd8W2DctmBejHF2XDYzbMFkJ-384SokPX6intnlqBGMs0ssxriJhsFOA-vgDra6REx3DUMb8_u_Umc-zp4E6isX4D-eRYgElmj0ez945nqxp3YliO8mRLMW6E4OupLthfw4vmK3YqTAuXcnGxYrf7JqAkMfz5uAPi0SqPWDQZq7ycu9BmkMXAIhMb19XBDjL7hZGDwDRrn9yBBcYlPaFPNXjMJWJH_xxUKNsTFGg5-J_WdxXi8Zn6tDMxbxqqjIpw_FUaM00jJ2MhpbkzhEx7X85pBR47ScRgr6WJpf4ZLSFuV7NT1WI3PIBa_bYeCiq29fp3ShM-1bRFdJG_lGZd97TuAMF_QU6-KDXBv5i8kUZ1NXdJUz-YaA0RRVNFgMGM5n0pKB5IFncAPK-taTzHLIZJ9uuBdP2y2Hxwbw8YQlmy2-MT5XE5Ae_9kxuvIIlSzjpfLN9012HSnX4tZ8x3aWwof3E7s3jjzw7qbBtoUkYYpIGVOKf2EpmhEqevSlXYWpBYN3X2ZYjsrA9CL9PTvrPdyWLwKBmfh7cDJbjNXJSQLeKL7oHzicrllABzR9Ckkz7b24XGV1Klcat_Og4oB9qxiO2zJZWz2GDTAL0hosUlHLWnrQYvqFzzdIOzGlifwIyGgoRNb44IRMzzsErxuoqkdjZewVc4PzruHRlV3cWK6M7ZUiWLtxtMzas2sfAERy8BdS7ISLzj5PERoWyYXSW-898WD3ze5MJcpSsAYNEmPCBtdxF9l-Qz1LxuDa8hOCQ2Wzef1a2WFF5pCBaZRcAK_kef65xRst6WFpjWZGCLZUqHBhFDLEOd7Ikbw7d9V8dc4nAO65NQcxfT9JDUZadS2jmQJip8GLD4P9lGS1Ry-8rHCnMN7zXDp43TfyYhSgv9uj4xKi2wmAMMYBl0n2RNemx8nt-K_dknGgYYGOybDkg2uAUoXdxP33KfiRjbRpYqZVAiq0S45QLAIxxGiDJoZRnyIscdM6lryQtXj0PO67vRf6ifxC3wLv97HHUKergpXcAg-4_rNj_Zx_xiHMfCAe2q3DG1a_DcSmu5u1OPkBHmzHB9Vs8HV0E2-z44sl3Exqb5L8pMYpDnZ7QW-Qb1-S-zoESUy__AKhkRWPC7GmvmJJJHur6SRGSK0X2KyszkEYoe-8NhwpvLrYnNuVk7QknBS91KH2q8C0B8FKqcY40S5ILkImP9iOGIXYl5ZVRleoDBpH9BootWH2az5l7c_e-vfBGs7XpudoAq5wzhe_-AMBvKPCm0BoCX5B_NGUasXvEWobqUb61mpKCuVJdzVtexk-m8Jfvmdc8ooPJEYD_oosY5_S1LuHoc7GHLnoYdDVb2FhIPhOJCLQCef-Y3dtNThqOEo534Zg7R72nSeSQhdQ1hcBUsc50U2oF9OlOnV9z5hsfNwIxdUO9bdoXRYFmosmtpmDfGxAem0s5iPJ0EJ_8szlaX2pi6k6VP-ci-n7J8pEBwL2R3c-ei2iqB7JdLi7Gg6iXVMpQIFTxswh0HbgGtyZXgR_-AM91XRszm_kAlqAHTAJ7B-0Z5bJgMGEY2StBdhGzel_gNPVaxemC3DT0904GbCU2Z3avUHcedebI02_MdILdQxyXbw145KjqC15CqeaG--6x6WzpAuSjrFQRuz6Z5UyibW6Ay9R3P25c-gwmaRM8rPW5YkQtQdfzrtvGZ6wyhIcBXvbpU02OoChfRDF4xI2LvnaW3g6hQIUGe5lueI13ArYRAhZC0LHKPuVfv5OKeMqxYRtcN3YK6Ddc1t61rsA7MU1cAKzOGsiQ7aNyNBQHOV6z-W4-ws_DnZKYRMz0D_hwbeHO0ZKhciXng5VDCX4hyb47LExmO5N1mfihN3iHEkX_19rIgunfkSb9gd9B_AaazAttBEPPLtbsoZneQXBRl3PWiDpC_yXiLTWAd13AOBYHzBMKeJ4hplUqsAGTaGSztbpvV92wz_YX9kMEucHMu5hoM-TJbuWoheiiiKSFBNRK_g_rqXZo1UZjDOnHpHGJxOnlJBPp94Zvwh8sKLOpOd4qeOMLbnYKiag00al5x_3fBXq-KI0Y31OJfgDdCaKAQ0DUX71HN6XDOlvU1Iwh48iASJHdQGDmjhcS8YoeX9omwPiYhcbGJGzEVrn3H7h24eIf_7bVRpicMhjwghB0xtqTT0eVam1l8kr1-5kem7Dr2Kyqm2HpEwbi3KPXKYDXQRbHElEhazMCYr2wnjx_Bx2ai2uZa8uQyjN1zh1cjWHH0TicL2eAyc6YPKfKpmc5QwLrgT0ddQDhvXkCkN50fOR1Sbl56iFoAL8goFl3QA5wBk51vsDsquEt7nlz6sGTHzknENb-eEayrXnw-Q5FueFwqzoJpUrEYDXTxgOU8XVhrPv0Ot-BO6ORfzn3_1gREcHjhrc6RdF01NNqyzyVG0BdckywvAnzUGskWdCfP62dKdx46lAIRVPd3xG4tViaQ79GAeMVnqSeCLXbOyqfnJwhOT2fgQzLwxcj1tqGBBd3Pfx2d5-10WiL_mis0ven6golqaLq1EQsveb9AJpkYgJxdBeyHZXxNLMh4_XAuK1ZIs9F8Cz1vFEVcAFipev-cFyRvsdcNI2-HK2nOGkypEcuVATyLtA0jKeyPtE4TJ3_l8KXltEZjWycQAd_8Tj9is3wisC8bfzjll8UBjFZp-rzmCr8kA4cZih9gl27TiCmhyKhgMfDUIUmuDL_Rn9DLxEAT3Ebl1SW0ToCciNtKTH9oO-wnkPd-jg1HCooLcg-K_QkOTptJNZRFbXpooKqwH5Z9qsCxurZxnS_MscnE0qTa4EqrlpiDnj4FBs4q9SEPlKequfYzFmjQis1iwsReutf6pHmsvRmz9gx5vd6NMIkI05IeLNDElvlOGD04m1vR4ZISdmdHaAgaW9_AUPGx0vP1Rqe36cvebwUYSnzdbZ7y1s7PH7GXF5r7zNEzY9bHmXvsjb3N_u9BkenwkQfZGS6ez0AAAAAAAAAAALGSAlKzg111";
    var p2 = jwt.SigningMethodMLDSA87.init(alloc);
    const parsed2 = p2.parse(token_str2, public_key);
    try testing.expectError(error.JWTVerifyFail, parsed2);
}

test "SigningMethodMLDSA44 with der key" {
    const alloc = testing.allocator;

    const prikey = "MDQCAQAwCwYJYIZIAWUDBAMRBCKAIPBmiRIBWe97N3Ilbp37aFah7jNzvMbhJsWqviXrcfzP";
    const pubkey = "MIIFMjALBglghkgBZQMEAxEDggUhACy1v7qduwKMRYFy3xwYzRCOX00e64AHP/psTVfYeJVIFemX6CIiyXwV6qCanbT6hLfQqMs6+G3OZBjEj5zLvS6Eu/iAE2x445rmGBe3iHdLpJiwyRe1xg6L4CGEqjd8vwVaTI/jCruH7hAx6VbtnjZQcwnW5uC23UIuFje16NvgTMNzntf3OEaKeu34KsWcXhl5FBjcZUGJlEYE6+WRcT8/1RukCE4o1OqMEspj88l0VkMclNn+kdeZAhwh8hAle8u+VrvUZqX+Wr6sySXysPbXjK7s2vYZOIaiWj8rvjcdoHdHgkWFjq82BnSkvL2X5pQvW+XGj4pNMFOWH8hHEqPABe3xyBJL+4EO4mVl1A7PfYLxE1zqoTZB+Zccti4B5dPYZvw6jNYHbeTOhREVKsFzgJ+YsKbYictUZpdl8bZwCGXGPssSvcXF9HDEC42pwNK1niyz1pERZS6lAJMYflT64mkuwKPsWnZzVIG3VkVRdtsbRjzb6rmGFKk5H0GBxadpt0RIC++csBVTcDQhRrJck204BMpPrVycSRFhzfu35n3i1Yow39H3dyrr0odSaVYVhA3lOXoofcswlz68SIOkab/jiqz4Ts6X2UPtgCJlxa0B/Bkq+7siYvDIL1iOykJwPunWILtw6bFzFsnDwxbvjOzbff1Jfkv7J284UiO95cbvgtkEij8aJQN56zAcoxfs4X5pYGiNPpYePRrMNYZqndl3+if9bdkh66lRVDUxeMJY29vSXuFaojHEebyJMrBpwZeoUBJJYzTol2He0+g9u6d1inbjlVT+9E/XP0lEkKfUhdkdyLM9x19YdxcFx99HLz5KOuy/B1kbru8Xs+GVuyveVzwNWsyfZ13wljKTtdpU2tDn6jlS3KJ7Dt5QtQfHXirncwNWTGUPk2E5ZTRMgtRhUyXoK+y0adVSmzPvBn+hPoO5uR4zPpIMXdIuPyv9wVknVbch3txLrkNIPf8NZ+YyQvgki8AasIep3zq8B0amVs4F9c9mKSAuGwXRNtmjHiWsfFZ7CS4BjiRNXTnT8iLH1tSRl4nMoZVGLntsgpGPYH+d/xYRWAxOZKD++tpNGGM0iVqBwqQM6OwiqT4vhx6GQFObEb8alvTfvT6hQ/BBUnVjT5YF4L46hphJ+iW9/cBVgWdkGkbYUvbxsk3wTuqsj7J4mdggLqqwCAcNFdLu/9Qw40t83rZXSYESK91d2oeZTTvCUqcTedI31ZEs8gbTMZfjfAOZ1+S4H3ZtWS16+CclOP5DpTaxcNmTkz8Mo8wAhRV699Gt6FYaEhZWzmpNRcnnflRu0tjT+SvvIv6HgJr6NsLtio41+31aJuKh9AV2BG2Udmo0CW2GJCYvDxEjzxEgRLZXgD3OvZrnkXg1Zx+Ww6sdLpqITZkiT6GkJWkpLxVWktIr5qrz2YTL5kCu+stxfafzEc4tyETlNrZ18F/BLIzYmJvYNB/A3nK3ftEFSyDhy2b+INumOWJzD96uecv0uysnWMP92vvMit8B5/d90esXr2qrTYs5CAiJmQbA+n25J+5VIc6jFTWIV4gO668EK4FLhNldKjrHB/fh8BfVQU+Qfmz2XKH+VPjyulbSI/cthvY6c794e6DOrPg3O6jOGp1MFVsfMcw/pXHORkapnOWsKpgaezLQEVUiRWhcxRKwSPPj0C4m9bO17MufszVsxAOmworZNNVd5CeKwC1LV/plg6fhSWhfkqycXQIu8013n5Gviit5+FY=";

    const prikey_bytes = try jwt.utils.base64Decode(alloc, prikey);
    const pubkey_bytes = try jwt.utils.base64Decode(alloc, pubkey);

    defer alloc.free(prikey_bytes);
    defer alloc.free(pubkey_bytes);

    const secret_key = try jwt.mldsa.ParseMLDSA44Der.parseSecretKeyDer(prikey_bytes);
    const public_key = try jwt.mldsa.ParseMLDSA44Der.parsePublicKeyDer(pubkey_bytes);

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    var s = jwt.SigningMethodMLDSA44.init(alloc);
    const token_string = try s.sign(claims, secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodMLDSA44.init(alloc);
    var parsed = try p.parse(token_string, public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.value.object.get("sub").?.string);
}

test "SigningMethodMLDSA65 with der key" {
    const alloc = testing.allocator;

    const prikey = "MDQCAQAwCwYJYIZIAWUDBAMSBCKAIBbRB15gndF8gEtIQokaAYvOTNfW9a5U3mthqjNJjkVN";
    const pubkey = "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";

    const prikey_bytes = try jwt.utils.base64Decode(alloc, prikey);
    const pubkey_bytes = try jwt.utils.base64Decode(alloc, pubkey);

    defer alloc.free(prikey_bytes);
    defer alloc.free(pubkey_bytes);

    const secret_key = try jwt.mldsa.ParseMLDSA65Der.parseSecretKeyDer(prikey_bytes);
    const public_key = try jwt.mldsa.ParseMLDSA65Der.parsePublicKeyDer(pubkey_bytes);

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    var s = jwt.SigningMethodMLDSA65.init(alloc);
    const token_string = try s.sign(claims, secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodMLDSA65.init(alloc);
    var parsed = try p.parse(token_string, public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.value.object.get("sub").?.string);
}

test "SigningMethodMLDSA87 with der key" {
    const alloc = testing.allocator;

    const prikey = "MDQCAQAwCwYJYIZIAWUDBAMTBCKAIJyDndFRrRdpmTm4biGGzJGW6DGvhGkkDnGdRnsu6kFm";
    const pubkey = "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";

    const prikey_bytes = try jwt.utils.base64Decode(alloc, prikey);
    const pubkey_bytes = try jwt.utils.base64Decode(alloc, pubkey);

    defer alloc.free(prikey_bytes);
    defer alloc.free(pubkey_bytes);

    const secret_key = try jwt.mldsa.ParseMLDSA87Der.parseSecretKeyDer(prikey_bytes);
    const public_key = try jwt.mldsa.ParseMLDSA87Der.parsePublicKeyDer(pubkey_bytes);

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    var s = jwt.SigningMethodMLDSA87.init(alloc);
    const token_string = try s.sign(claims, secret_key);
    defer alloc.free(token_string);
    try testing.expectEqual(true, token_string.len > 0);

    // ==========

    var p = jwt.SigningMethodMLDSA87.init(alloc);
    var parsed = try p.parse(token_string, public_key);
    defer parsed.deinit();

    const claims2 = try parsed.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.sub, claims2.value.object.get("sub").?.string);
}
