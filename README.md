## Zig-jwt 

A JWT (JSON Web Token) library for zig.


### Env

 - Zig >= 0.14.0-dev.3451+d8d2aa9af


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
const zig_jwt = @import("zig-jwt");
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
    
    // output: 
    // make jwt: eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJhdWQiOiJleGFtcGxlLmNvbSIsInN1YiI6ImZvbyJ9.8aYTV-9_Z1RQUPepUlut9gvniX_Cx_z8P60Z5FbnMMgNLPNP29ZtNG3k6pcU2TY_O3DkSsdxbN2HkmgvjDUPBg
    std.debug.print("make jwt: {s} \n", .{token_string});

    const p = jwt.SigningMethodEdDSA.init(alloc);
    var token = try p.parse(token_string, kp.public_key);
    
    // output: 
    // claims aud: example.com
    const claims2 = try token.getClaims();
    std.debug.print("claims aud: {s} \n", .{claims2.object.get("aud").?.string});
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
    try token.parse(token_string);

    var validator = try jwt.Validator.init(token);
    defer validator.deinit();

    // validator.withLeeway(3);

    // output: 
    // hasBeenIssuedBy: true
    std.debug.print("hasBeenIssuedBy: {} \n", .{validator.hasBeenIssuedBy("iss")});

    // have functions:
    // validator.hasBeenIssuedBy("iss")
    // validator.isRelatedTo("sub")
    // validator.isIdentifiedBy("jti rrr")
    // validator.isPermittedFor("example.com") // audience
    // validator.hasBeenIssuedBefore(now) // now is time timestamp
    // validator.isMinimumTimeBefore(now)
    // validator.isExpired(now)
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

 - `HS256`: jwt.SigningMethodHS256
 - `HS384`: jwt.SigningMethodHS384
 - `HS512`: jwt.SigningMethodHS512

 - `BLAKE2B`: jwt.SigningMethodBLAKE2B

 - `none`: jwt.SigningMethodNone


### Sign PublicKey

RSA PublicKey:
~~~zig
const secret_key = jwt.crypto_rsa.SecretKey;
const public_key = jwt.crypto_rsa.PublicKey;

// rsa no generate

// from plain bytes
const secret_key = try jwt.crypto_rsa.SecretKey.fromDer(prikey_bytes);
const public_key = try jwt.crypto_rsa.PublicKey.fromDer(pubkey_bytes);
~~~

ECDSA PublicKey:
~~~zig
const ecdsa = std.crypto.sign.ecdsa;

const p256_secret_key = ecdsa.EcdsaP256Sha256.SecretKey;
const p256_public_key = ecdsa.EcdsaP256Sha256.PublicKey;

const p384_secret_key = ecdsa.EcdsaP384Sha384.SecretKey;
const p384_public_key = ecdsa.EcdsaP384Sha384.PublicKey;

const p256k_secret_key = ecdsa.EcdsaSecp256k1Sha256.SecretKey;
const p256k_public_key = ecdsa.EcdsaSecp256k1Sha256.PublicKey;

// generate p256 public key
const p256_kp = ecdsa.EcdsaP256Sha256.KeyPair.generate();
// from plain bytes
const p256_secret_key = try ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(pri_key_buf);
const p256_public_key = try ecdsa.EcdsaP256Sha256.PublicKey.fromSec1(pub_key_bytes);

// generate p384 public key
const p384_kp = ecdsa.EcdsaP384Sha384.KeyPair.generate();
// from plain bytes
const p384_secret_key = try ecdsa.EcdsaP384Sha384.SecretKey.fromBytes(pri_key_buf);
const p384_public_key = try ecdsa.EcdsaP384Sha384.PublicKey.fromSec1(pub_key_bytes);

// generate p256k public key
const p256k_kp = ecdsa.EcdsaSecp256k1Sha256.KeyPair.generate();
// from plain bytes
const p256k_secret_key = try ecdsa.EcdsaSecp256k1Sha256.SecretKey.fromBytes(pri_key_buf);
const p256k_public_key = try ecdsa.EcdsaSecp256k1Sha256.PublicKey.fromSec1(pub_key_bytes);
~~~

EdDSA PublicKey:
~~~zig
const Ed25519 = std.crypto.sign.Ed25519;

const secret_key = Ed25519.SecretKey;
const public_key = Ed25519.PublicKey;

// generate public key
const kp = Ed25519.KeyPair.generate();

// from plain bytes
const secret_key = try Ed25519.SecretKey.fromBytes(pri_key_buf);
const public_key = try Ed25519.PublicKey.fromBytes(pub_key_buf);
~~~


### LICENSE

*  The library LICENSE is `Apache2`, using the library need keep the LICENSE.


### Copyright

*  Copyright deatil(https://github.com/deatil).
