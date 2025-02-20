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
        .iat = "foo",
    };

    const s = jwt.SigningMethodEdDSA.init(alloc);
    const token_string = try s.make(claims, kp.secret_key);
    
    // output: 
    // make jwt: eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJhdWQiOiJleGFtcGxlLmNvbSIsImlhdCI6ImZvbyJ9.OeM7QPhXckIpT3TJiP1Q_GXCBTZ_ZR9FCLvfm-894YCu4h_AIuI91biaHvXqgYYSMHA8Ey197RDcf-Iav0VmAg
    std.debug.print("make jwt: {s} \n", .{token_string});

    const p = jwt.SigningMethodEdDSA.init(alloc);
    var parsed = try p.parse(token_string, kp.public_key);
    
    // output: 
    // claims aud: example.com
    const claims = try parsed.getClaims();
    std.debug.print("claims aud: {} \n", .{claims.object.get("aud").?.string});
}
~~~


### LICENSE

*  The library LICENSE is `Apache2`, using the library need keep the LICENSE.


### Copyright

*  Copyright deatil(https://github.com/deatil).
