// SPDX-License-Identifier: MIT

//! Dead-stack burn for every secret-touching entry point (`P521.mul`/
//! `mulInto`, `ecdh`/`ecdhInto`, the `EcdsaP521Sha512` key-pair and signing
//! paths). Each public entry point runs its body one frame down (`run`, a
//! `never_inline` call), then zeroes the bytes that body dirtied at that
//! depth. The body is a separate frame on purpose: inlined into the entry
//! point, the burn would land above the body's locals. `stackprobe_test.zig`
//! goes red when a body outgrows its burn. `stack` and `run` are copied from
//! `aes192/src/burn.zig` (identical in every module).

/// Zero `n` bytes of stack below the caller.
pub noinline fn stack(comptime n: usize) void {
    // Volatile 16-byte vector stores (`secureZero` is a volatile byte memset,
    // ~3 B/ns without libc; this is ~50 B/ns, 2026-10-09). 16, not 32: with a
    // 32-byte vector LLVM raised the buffer's alignment to 32 for small burns
    // (n <= 2 KiB) and realigned the frame (`and $-32, %rsp`), leaving 32..63 bytes
    // between the buffer top and the saved frame pointer unzeroed -- a callee's
    // 32-byte scalar survived there (voprf stack probe, 2026-10-09; `align(16)` on
    // the buffer alone did not stop it). At 16 the frame needs no realignment and
    // the buffer ends at the saved frame pointer.
    const V = @Vector(2, u64);
    var buf: [n / @sizeOf(V)]V align(16) = undefined;
    const p: [*]align(16) volatile V = &buf;
    for (0..buf.len) |i| p[i] = @splat(0);
}

/// `f(args)` in a frame of its own, then `stack(n)` at the same depth.
/// `inline`, so the argument tuple lives in the entry point's frame — it holds
/// only pointers and public values, never a secret by value.
pub inline fn run(comptime n: usize, comptime R: type, comptime f: anytype, args: anytype) R {
    const r: R = @call(.never_inline, f, args);
    stack(n);
    return r;
}

/// A constant-time scalar multiply: the 17-point projective table (3.7
/// KiB), its affine form (2.3 KiB), the signed digits (1.7 KiB) and the
/// inlined Jacobian formulas' temporaries. Sized from `stackprobe_test.zig`
/// in ReleaseFast (ecdhInto dirtied 19.2 KiB, 2026-10-11).
pub const mul_burn = 24 * 1024;

/// A signature or key derivation: a scalar multiply, the RFC 6979 HMAC
/// states, the scalar inversion's 16-entry table.
pub const sign_burn = 24 * 1024;
