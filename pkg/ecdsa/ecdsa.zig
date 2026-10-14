const std = @import("std");

pub const field = @import("field.zig");
pub const scalar = @import("scalar.zig");
const group = @import("group.zig");
const sign = @import("sign.zig");

// first code from https://github.com/zaxified/zig-libs

/// A base-field element.
pub const Fe = field.Fe;
/// A P-521 point (std `P384`'s shape).
pub const P521 = group.P521;
/// A point in affine coordinates.
pub const AffineCoordinates = group.AffineCoordinates;
/// A scalar mod the group order n.
pub const Scalar = scalar.Scalar;

/// ECDH: x-coordinate of `secret · peer` (66 bytes); compressed or
/// uncompressed peer points. `ecdhInto` is the dead-stack-clean form.
pub const ecdh = group.ecdh;
pub const ecdhInto = group.ecdhInto;
pub const EcdhError = group.EcdhError;

/// ECDSA over P-521 with SHA-512 — the drop-in for a std `Ecdsa` type.
pub const EcdsaP521Sha512 = sign.EcdsaP521Sha512;
/// ECDSA over P-521 with another hash (digest ≤ 65 bytes), e.g. X.509's
/// rarer `ecdsa-with-SHA256` + P-521 key.
pub const Ecdsa = sign.Ecdsa;

// Pull every submodule's tests into the test binary (CONVENTIONS.md §6
// dark-tests rule).
test {
    _ = field;
    _ = scalar;
    _ = group;
    _ = sign;
    _ = @import("kat_test.zig");
    _ = @import("oracle_test.zig");
}
