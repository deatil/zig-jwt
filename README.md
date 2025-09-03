## Zig-jwt 

A JWT (JSON Web Token) library for zig.


### Env

 - Zig >= 0.15.1


### What the heck is a JWT?

JWT.io has [a great introduction](https://jwt.io/introduction) to JSON Web Tokens.

In short, it's a signed JSON object that does something useful (for example, authentication).  It's commonly used for `Bearer` tokens in Oauth 2.  A token is made of three parts, separated by `.`'s.  The first two parts are JSON objects, that have been [base64url](https://datatracker.ietf.org/doc/html/rfc4648) encoded.  The last part is the signature, encoded the same way.

The first part is called the header.  It contains the necessary information for verifying the last part, the signature.  For example, which encryption method was used for signing and what key was used.

The part in the middle is the interesting bit.  It's called the Claims and contains the actual stuff you care about.  Refer to [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) for information about reserved keys and the proper way to add your own.


### What's in the box?

This library supports the parsing and verification as well as the generation and signing of JWTs.  Current supported signing algorithms are HMAC SHA, RSA, RSA-PSS, and ECDSA, though hooks are present for adding your own.


### Adding zig-jwt as a dependency

Add the dependency to your project:

```sh
zig fetch --save=zig-jwt git+https://github.com/deatil/zig-jwt#main
```

or use local path to add dependency at `build.zig.zon` file

```zig
.{
    .dependencies = .{
        .@"zig-jwt" = .{
            .path = "./lib/zig-jwt",
        },
        ...
    }
}
```

And the following to your `build.zig` file:

```zig
const zig_jwt_dep = b.dependency("zig-jwt", .{});
exe.root_module.addImport("zig-jwt", zig_jwt_dep.module("zig-jwt"));
```

The `zig-jwt` structure can be imported in your application with:

```zig
const jwt = @import("zig-jwt");
```


### Get Starting

~~~zig
const std = @import("std");
const jwt = @import("zig-jwt");

pub fn main() !void {
    const alloc = std.heap.page_allocator;

    const kp = jwt.eddsa.Ed25519.KeyPair.generate();

    const claims = .{
        .aud = "example.com",
        .sub = "foo",
    };

    const s = jwt.SigningMethodEdDSA.init(alloc);
    const token_string = try s.sign(claims, kp.secret_key);

    defer alloc.free(token_string);
    
    // output: 
    // make jwt: eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJhdWQiOiJleGFtcGxlLmNvbSIsInN1YiI6ImZvbyJ9.8aYTV-9_Z1RQUPepUlut9gvniX_Cx_z8P60Z5FbnMMgNLPNP29ZtNG3k6pcU2TY_O3DkSsdxbN2HkmgvjDUPBg
    std.debug.print("make jwt: {s} \n", .{token_string});

    const p = jwt.SigningMethodEdDSA.init(alloc);
    var token = try p.parse(token_string, kp.public_key);

    defer p.deinit();
    
    // output: 
    // claims aud: example.com
    const claims2 = try token.getClaims();
    defer claims2.deinit();
    std.debug.print("claims aud: {s} \n", .{claims2.value.object.get("aud").?.string});
}
~~~


### Token Validator

~~~zig
const std = @import("std");
const jwt = @import("zig-jwt");

pub fn main() !void {
    const alloc = std.heap.page_allocator;

    const token_string = "eyJ0eXAiOiJKV0UiLCJhbGciOiJFUzI1NiIsImtpZCI6ImtpZHMifQ.eyJpc3MiOiJpc3MiLCJpYXQiOjE1Njc4NDIzODgsImV4cCI6MTc2Nzg0MjM4OCwiYXVkIjoiZXhhbXBsZS5jb20iLCJzdWIiOiJzdWIiLCJqdGkiOiJqdGkgcnJyIiwibmJmIjoxNTY3ODQyMzg4fQ.dGVzdC1zaWduYXR1cmU";

    var token = jwt.Token.init(alloc);
    token.parse(token_string);

    var validator = try jwt.Validator.init(token);
    defer validator.deinit();

    // validator.withLeeway(3);

    // output: 
    // hasBeenIssuedBy: true
    std.debug.print("hasBeenIssuedBy: {} \n", .{validator.hasBeenIssuedBy("iss")});

    // const now = std.time.timestamp();

    // have functions:
    // validator.hasBeenIssuedBy("iss") // iss
    // validator.isRelatedTo("sub") // sub
    // validator.isIdentifiedBy("jti rrr") // jti
    // validator.isPermittedFor("example.com") // audience
    // validator.hasBeenIssuedBefore(now) // iat, now is time timestamp
    // validator.isMinimumTimeBefore(now) // nbf, now is time timestamp
    // validator.isExpired(now) // exp, now is time timestamp
}
~~~


### Signing Methods

The JWT library have signing methods:

 - `RS256`: jwt.SigningMethodRS256
 - `RS384`: jwt.SigningMethodRS384
 - `RS512`: jwt.SigningMethodRS512

 - `PS256`: jwt.SigningMethodPS256
 - `PS384`: jwt.SigningMethodPS384
 - `PS512`: jwt.SigningMethodPS512

 - `ES256`: jwt.SigningMethodES256
 - `ES384`: jwt.SigningMethodES384

 - `ES256K`: jwt.SigningMethodES256K
 
 - `EdDSA`: jwt.SigningMethodEdDSA
 - `ED25519`: jwt.SigningMethodED25519

 - `HSHA1`: jwt.SigningMethodHSHA1
 - `HS224`: jwt.SigningMethodHS224
 - `HS256`: jwt.SigningMethodHS256
 - `HS384`: jwt.SigningMethodHS384
 - `HS512`: jwt.SigningMethodHS512

 - `BLAKE2B`: jwt.SigningMethodBLAKE2B

 - `none`: jwt.SigningMethodNone


### Sign PublicKey

RSA PublicKey:
~~~zig
var secret_key: jwt.crypto_rsa.SecretKey = undefined;
var public_key: jwt.crypto_rsa.PublicKey = undefined;

// rsa no generate

// from pkcs1 der bytes
const secret_key = try jwt.crypto_rsa.SecretKey.fromDer(prikey_bytes);
const public_key = try jwt.crypto_rsa.PublicKey.fromDer(pubkey_bytes);

// from pkcs8 der bytes
const secret_key = try jwt.crypto_rsa.SecretKey.fromPKCS8Der(prikey_bytes);
const public_key = try jwt.crypto_rsa.PublicKey.fromPKCS8Der(pubkey_bytes);
~~~

ECDSA PublicKey:
~~~zig
const ecdsa = std.crypto.sign.ecdsa;

var p256_secret_key: ecdsa.EcdsaP256Sha256.SecretKey = undefined;
var p256_public_key: ecdsa.EcdsaP256Sha256.PublicKey = undefined;

var p384_secret_key: ecdsa.EcdsaP384Sha384.SecretKey = undefined;
var p384_public_key: ecdsa.EcdsaP384Sha384.PublicKey = undefined;

var p256k_secret_key: ecdsa.EcdsaSecp256k1Sha256.SecretKey = undefined;
var p256k_public_key: ecdsa.EcdsaSecp256k1Sha256.PublicKey = undefined;

// generate p256 public key
const p256_kp = ecdsa.EcdsaP256Sha256.KeyPair.generate();
// from plain bytes
const p256_secret_key = try ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(pri_key_bytes);
const p256_public_key = try ecdsa.EcdsaP256Sha256.PublicKey.fromSec1(pub_key_bytes);
// from der bytes
const p256_secret_key = try jwt.ecdsa.ParseP256Sha256Der.parseSecretKeyDer(pri_key_bytes);
const p256_secret_key = try jwt.ecdsa.ParseP256Sha256Der.parseSecretKeyPKCS8Der(pri_key_bytes);
const p256_public_key = try jwt.ecdsa.ParseP256Sha256Der.parsePublicKeyDer(pub_key_bytes);

// generate p384 public key
const p384_kp = ecdsa.EcdsaP384Sha384.KeyPair.generate();
// from plain bytes
const p384_secret_key = try ecdsa.EcdsaP384Sha384.SecretKey.fromBytes(pri_key_bytes);
const p384_public_key = try ecdsa.EcdsaP384Sha384.PublicKey.fromSec1(pub_key_bytes);
// from der bytes
const p384_secret_key = try jwt.ecdsa.ParseP384Sha384Der.parseSecretKeyDer(pri_key_bytes);
const p384_secret_key = try jwt.ecdsa.ParseP384Sha384Der.parseSecretKeyPKCS8Der(pri_key_bytes);
const p384_public_key = try jwt.ecdsa.ParseP384Sha384Der.parsePublicKeyDer(pub_key_bytes);

// generate p256k public key
const p256k_kp = ecdsa.EcdsaSecp256k1Sha256.KeyPair.generate();
// from plain bytes
const p256k_secret_key = try ecdsa.EcdsaSecp256k1Sha256.SecretKey.fromBytes(pri_key_bytes);
const p256k_public_key = try ecdsa.EcdsaSecp256k1Sha256.PublicKey.fromSec1(pub_key_bytes);
// from der bytes
const p256k_secret_key = try jwt.ecdsa.ParseSecp256k1Sha256Der.parseSecretKeyDer(pri_key_bytes);
const p256k_secret_key = try jwt.ecdsa.ParseSecp256k1Sha256Der.parseSecretKeyPKCS8Der(pri_key_bytes);
const p256k_public_key = try jwt.ecdsa.ParseSecp256k1Sha256Der.parsePublicKeyDer(pub_key_bytes);
~~~

EdDSA PublicKey:
~~~zig
const Ed25519 = std.crypto.sign.Ed25519;

var secret_key: Ed25519.SecretKey = undefined;
var public_key: Ed25519.PublicKey = undefined;

// generate public key
const kp = Ed25519.KeyPair.generate();

// from plain bytes
const secret_key = try Ed25519.SecretKey.fromBytes(pri_key_bytes);
const public_key = try Ed25519.PublicKey.fromBytes(pub_key_bytes);
// from der bytes
const secret_key = try jwt.eddsa.parseSecretKeyDer(pri_key_bytes);
const public_key = try jwt.eddsa.parsePublicKeyDer(pub_key_bytes);
~~~


### Custom Signing Method

~~~zig
const std = @import("std");
const jwt = @import("zig-jwt");

const ecdsa = std.crypto.sign.ecdsa;

// public custom signing method
pub const SigningMethodES3_384 = jwt.JWT(SigningES3_384, ecdsa.EcdsaP384Sha3_384.SecretKey, ecdsa.EcdsaP384Sha3_384.PublicKey);

// example: use EcdsaP384Sha3_384 signer
const SigningES3_384 = SignCustom(ecdsa.EcdsaP384Sha3_384, "ES3_384");

// sign and verify custom struct
fn SignCustom(comptime EC: type, comptime name: []const u8) type {
    return struct {
        alloc: Allocator, 

        const Self = @This();

        pub const encoded_length = EC.Signature.encoded_length;

        pub fn init(alloc: Allocator) Self {
            return .{
                .alloc = alloc,
            };
        }

        pub fn alg(self: Self) []const u8 {
            _ = self;
            return name;
        }

        pub fn signLength(self: Self) isize {
            _ = self;
            return encoded_length;
        }

        pub fn sign(self: Self, msg: []const u8, key: EC.SecretKey) ![]u8 {
            var secret_key = try EC.KeyPair.fromSecretKey(key);

            const sig = try secret_key.sign(msg[0..], null);
            const out = sig.toBytes();

            return self.alloc.dupe(u8, out[0..]);
        }

        pub fn verify(self: Self, msg: []const u8, signature: []u8, key: EC.PublicKey) bool {
            const sign_length = self.signLength();
            if (signature.len != sign_length) {
                return false;
            }
            
            var signed: [encoded_length]u8 = undefined;
            @memcpy(signed[0..], signature);

            const sig = EC.Signature.fromBytes(signed);
            sig.verify(msg, key) catch {
                return false;
            };

            return true;
        }
    };
}

~~~


### LICENSE

*  The library LICENSE is `Apache2`, using the library need keep the LICENSE.


### Copyright

*  Copyright deatil(https://github.com/deatil).
