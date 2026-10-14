// SPDX-License-Identifier: MIT

//! Differential against OpenSSL (frozen; `tools/openssl_oracle.py`): for
//! each of 24 OpenSSL-generated keys, our public key (both SEC1 forms), our
//! RFC 6979 signature byte for byte against OpenSSL's `nonce-type:1`, our
//! verification of OpenSSL's random-nonce signature, and our ECDH against
//! OpenSSL's `pkeyutl -derive`.

const std = @import("std");
const testing = std.testing;
const root = @import("ecdsa.zig");
const ov = @import("oracle_vectors.zig");

const E = root.EcdsaP521Sha512;

fn hex(comptime n: usize, s: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "OpenSSL oracle: keys, RFC 6979 signatures, random-nonce verify, ECDH (24 rows)" {
    try testing.expectEqual(@as(usize, 24), ov.rows.len);
    try testing.expectEqual(ov.count, ov.rows.len);
    for (ov.rows) |r| {
        const d = hex(66, r.d);
        var kp: E.KeyPair = undefined;
        try E.KeyPair.fromSecretKeyInto(&kp, &.{ .bytes = d });
        try testing.expectEqualSlices(u8, &hex(133, r.pub_u), &kp.public_key.toUncompressedSec1());
        try testing.expectEqualSlices(u8, &hex(67, r.pub_c), &kp.public_key.toCompressedSec1());
        // Compressed and uncompressed decode to the same key.
        const pc = try E.PublicKey.fromSec1(&hex(67, r.pub_c));
        try testing.expect(pc.p.equivalent(kp.public_key.p));

        var mbuf: [128]u8 = undefined;
        const msg = std.fmt.hexToBytes(&mbuf, r.msg) catch unreachable;
        const sig = try kp.sign(msg, null);
        try testing.expectEqualSlices(u8, &hex(132, r.sig_det), &sig.toBytes());
        try E.Signature.fromBytes(hex(132, r.sig_rnd)).verify(msg, kp.public_key);
        // A different message must not verify under OpenSSL's signature.
        var other: [129]u8 = undefined;
        @memcpy(other[0..msg.len], msg);
        other[msg.len] = 0x5a;
        try testing.expectError(error.SignatureVerificationFailed, E.Signature.fromBytes(hex(132, r.sig_rnd)).verify(other[0 .. msg.len + 1], kp.public_key));

        var z: [66]u8 = undefined;
        try root.ecdhInto(&z, &d, &hex(133, r.peer));
        try testing.expectEqualSlices(u8, &hex(66, r.shared), &z);
    }
}
