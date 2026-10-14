// SPDX-License-Identifier: MIT

//! p521 — NIST P-521 (secp521r1): field, group, ECDH and ECDSA-P521, the
//! curve Zig 0.16's std does not ship (it has P-256 and P-384 only).
//!
//! Consumers it exists for: ssh `ecdh-sha2-nistp521` / `ecdsa-sha2-nistp521`,
//! jwt `ES512`, x509 P-521 certificates, hpke DHKEM(P-521, HKDF-SHA512),
//! acme. The surface mirrors `std.crypto.ecc.P384` and
//! `std.crypto.sign.ecdsa.EcdsaP384Sha384`, so a consumer written against
//! std's curves takes this one by swapping the type.
//!
//! * Field: GF(2^521 − 1) in nine 58/57-bit limbs, Mersenne reduction by
//!   shifts and adds (`field.zig`).
//! * Scalars: Montgomery mod n, nine 64-bit limbs (`scalar.zig`).
//! * Group: complete Renes–Costello–Batina formulas; secret scalars through
//!   one fixed-window, masked-table constant-time multiply; public ones
//!   through a vartime signed-window path (`group.zig`).
//! * ECDSA: RFC 6979 deterministic nonces (optional §3.6 additional data),
//!   raw and strict-DER signatures (`sign.zig`).
//!
//! Verified against NIST CAVP (186-4 ECDSA SigGen/SigVer/KeyPair/PKV, ECC
//! CDH), Wycheproof (ECDH, ECDSA DER and P1363) and OpenSSL (keys, RFC 6979
//! signatures byte for byte, ECDH).

const std = @import("std");

pub const field = @import("field.zig");
pub const scalar = @import("scalar.zig");
const group = @import("group.zig");
const sign = @import("sign.zig");

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

pub const meta = .{
    // The module catalog's one-line entry. README.md's table is rendered
    // from it by `zig build gen-catalog`.
    .doc = "NIST P-521 (secp521r1): Mersenne field, constant-time ECDH and ECDSA-P521 (RFC 6979) with std `P384`/`Ecdsa`-shaped API; CAVP + Wycheproof + OpenSSL anchored.",
    .platform_note = "any (portable, no asm)",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util, // pure computation, no I/O
    .concurrency = .reentrant, // no globals; values are plain types
    .model_after = "std.crypto.ecc.P384 + std.crypto.sign.ecdsa (API shape); FIPS 186-5, SP 800-186, RFC 6979; OpenSSL ecp_nistp521 as the differential oracle",
    .deps = .{"entropy"},
};

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
