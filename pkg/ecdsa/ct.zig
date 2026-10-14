// SPDX-License-Identifier: MIT

//! Constant-time helpers shared by the module.

const std = @import("std");

/// Mark `v` as defined for memcheck: a no-op unless the build has
/// `-fvalgrind`. Used ONLY on a value the API reveals anyway — an error
/// verdict on a secret's range, `r`/`s` of a published signature, the
/// RFC 6979 retry bit (probability < 2^-259 per signature) — so ctgrind keeps
/// measuring the secret instead of flagging the one branch every such API
/// must take. Each call site names which of these it is.
pub inline fn declassify(v: anytype) void {
    std.valgrind.memcheck.makeMemDefined(std.mem.asBytes(v));
}
