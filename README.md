## Zig-jwt 

A JWT library for zig.


### Env

 - Zig >= 0.14.0-dev.2851+b074fb7dd


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
    const token_string = try s.make(claims, kp.secret_key);
    
    // output: 
    // make jwt: eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJhdWQiOiJleGFtcGxlLmNvbSIsInN1YiI6ImZvbyJ9.8aYTV-9_Z1RQUPepUlut9gvniX_Cx_z8P60Z5FbnMMgNLPNP29ZtNG3k6pcU2TY_O3DkSsdxbN2HkmgvjDUPBg
    std.debug.print("make jwt: {s} \n", .{token_string});

    const p = jwt.SigningMethodEdDSA.init(alloc);
    var parsed = try p.parse(token_string, kp.public_key);
    
    // output: 
    // claims aud: example.com
    const claims2 = try parsed.getClaims();
    std.debug.print("claims aud: {s} \n", .{claims2.object.get("aud").?.string});
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
 
 - `EdDSA`: jwt.SigningMethodEdDSA
 - `ED25519`: jwt.SigningMethodED25519

 - `HS256`: jwt.SigningMethodHS256
 - `HS384`: jwt.SigningMethodHS384
 - `HS512`: jwt.SigningMethodHS512

 - `none`: jwt.SigningMethodNone


### LICENSE

*  The library LICENSE is `Apache2`, using the library need keep the LICENSE.


### Copyright

*  Copyright deatil(https://github.com/deatil).
