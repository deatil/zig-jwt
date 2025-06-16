const std = @import("std");
const fmt = std.fmt;
const Allocator = std.mem.Allocator;

pub const crypto_rsa = @import("rsa/rsa.zig");

pub const rsa = @import("rsa.zig");
pub const rsa_pss = @import("rsa_pss.zig");
pub const ecdsa = @import("ecdsa.zig");
pub const eddsa = @import("eddsa.zig");
pub const hmac = @import("hmac.zig");
pub const blake2b = @import("blake2b.zig");
pub const none = @import("none.zig");
pub const utils = @import("utils.zig");
pub const builder = @import("builder.zig");

pub const Token = @import("token.zig").Token;
pub const Validator = @import("validator.zig").Validator;

pub const SigningMethodRS256 = JWT(rsa.SigningRS256, crypto_rsa.SecretKey, crypto_rsa.PublicKey);
pub const SigningMethodRS384 = JWT(rsa.SigningRS384, crypto_rsa.SecretKey, crypto_rsa.PublicKey);
pub const SigningMethodRS512 = JWT(rsa.SigningRS512, crypto_rsa.SecretKey, crypto_rsa.PublicKey);

pub const SigningMethodPS256 = JWT(rsa_pss.SigningPS256, crypto_rsa.SecretKey, crypto_rsa.PublicKey);
pub const SigningMethodPS384 = JWT(rsa_pss.SigningPS384, crypto_rsa.SecretKey, crypto_rsa.PublicKey);
pub const SigningMethodPS512 = JWT(rsa_pss.SigningPS512, crypto_rsa.SecretKey, crypto_rsa.PublicKey);

pub const SigningMethodES256 = JWT(ecdsa.SigningES256, ecdsa.ecdsa.EcdsaP256Sha256.SecretKey, ecdsa.ecdsa.EcdsaP256Sha256.PublicKey);
pub const SigningMethodES384 = JWT(ecdsa.SigningES384, ecdsa.ecdsa.EcdsaP384Sha384.SecretKey, ecdsa.ecdsa.EcdsaP384Sha384.PublicKey);
// pub const SigningMethodES512 = JWT(ecdsa.SigningES512, ecdsa.ecdsa.EcdsaP521Sha512.SecretKey, ecdsa.ecdsa.EcdsaP521Sha512.PublicKey);

pub const SigningMethodES256K = JWT(ecdsa.SigningES256K, ecdsa.ecdsa.EcdsaSecp256k1Sha256.SecretKey, ecdsa.ecdsa.EcdsaSecp256k1Sha256.PublicKey);

pub const SigningMethodEdDSA = JWT(eddsa.SigningEdDSA, eddsa.Ed25519.SecretKey, eddsa.Ed25519.PublicKey);
pub const SigningMethodED25519 = JWT(eddsa.SigningED25519, eddsa.Ed25519.SecretKey, eddsa.Ed25519.PublicKey);

pub const SigningMethodHMD5 = JWT(hmac.SigningHMD5, []const u8, []const u8);
pub const SigningMethodHSHA1 = JWT(hmac.SigningHSHA1, []const u8, []const u8);
pub const SigningMethodHS224 = JWT(hmac.SigningHS224, []const u8, []const u8);
pub const SigningMethodHS256 = JWT(hmac.SigningHS256, []const u8, []const u8);
pub const SigningMethodHS384 = JWT(hmac.SigningHS384, []const u8, []const u8);
pub const SigningMethodHS512 = JWT(hmac.SigningHS512, []const u8, []const u8);

pub const SigningMethodBLAKE2B = JWT(blake2b.SigningBLAKE2B, []const u8, []const u8);

pub const SigningMethodNone = JWT(none.SigningNone, []const u8, []const u8);

pub const Error = error{ JWTVerifyFail, JWTSigningMethodNotExists, JWTTypeInvalid, JWTAlgoInvalid };

pub fn JWT(comptime Signer: type, comptime SignKeyType: type, comptime VerifyKeyType: type) type {
    const BuilderType = builder.Builder(Signer, SignKeyType);

    return struct {
        signer: Signer,
        alloc: Allocator,

        const Self = @This();

        pub fn init(alloc: Allocator) Self {
            return .{
                .signer = Signer.init(alloc),
                .alloc = alloc,
            };
        }

        pub fn alg(self: Self) []const u8 {
            return self.signer.alg();
        }

        pub fn signLength(self: Self) isize {
            return self.signer.signLength();
        }

        // use SigningMethod to make token
        pub fn sign(self: Self, claims: anytype, sign_key: SignKeyType) ![]const u8 {
            const header = .{
                .typ = "JWT",
                .alg = self.signer.alg(),
            };

            return self.signWithHeader(header, claims, sign_key);
        }

        // use SigningMethod with header to make token
        pub fn signWithHeader(self: Self, header: anytype, claims: anytype, sign_key: SignKeyType) ![]const u8 {
            var t = Token.init(self.alloc);
            try t.setHeader(header);
            try t.setClaims(claims);

            defer t.deinit();

            const signing_string = try t.signingString();
            defer self.alloc.free(signing_string);

            const signature = try self.signer.sign(signing_string, sign_key);
            defer self.alloc.free(signature);

            try t.withSignature(signature);

            return t.signedString();
        }

        // parse token and token signature verify
        pub fn parse(self: Self, token_string: []const u8, verify_key: VerifyKeyType) !Token {
            var t = Token.init(self.alloc);
            t.parse(token_string);

            var header = try t.getHeader();
            defer header.deinit(self.alloc);

            if (header.typ.len > 0 and !utils.eq(header.typ, "JWT")) {
                defer t.deinit();

                return Error.JWTTypeInvalid;
            }

            if (!utils.eq(header.alg, self.signer.alg())) {
                defer t.deinit();

                return Error.JWTAlgoInvalid;
            }

            const signature = try t.getSignature();
            defer self.alloc.free(signature);

            const token_sign = try self.alloc.alloc(u8, signature.len);
            @memcpy(token_sign[0..], signature[0..]);

            defer self.alloc.free(token_sign);

            const signing_string = try t.signingString();
            defer self.alloc.free(signing_string);

            if (!self.signer.verify(signing_string, token_sign, verify_key)) {
                defer t.deinit();

                return Error.JWTVerifyFail;
            }

            return t;
        }

        pub fn build(self: Self) BuilderType {
            return BuilderType.init(self.alloc);
        }
    };
}

// jwt claims struct
pub const JWTClaims = struct {
    // Issuer
    iss: ?[]const u8 = null,
    // Issued At
    iat: ?i64 = null,
    // Expiration Time
    exp: ?i64 = null,
    // Audience
    aud: ?[]const u8 = null,
    // Subject
    sub: ?[]const u8 = null,
    // JWT ID
    jti: ?[]const u8 = null,
    // Not Before
    nbf: ?i64 = null,
};

pub fn getSigningMethod(name: []const u8) !type {
    if (utils.eq(name, "RS256")) {
        return SigningMethodRS256;
    }
    if (utils.eq(name, "RS384")) {
        return SigningMethodRS384;
    }
    if (utils.eq(name, "RS512")) {
        return SigningMethodRS512;
    }

    if (utils.eq(name, "PS256")) {
        return SigningMethodPS256;
    }
    if (utils.eq(name, "PS384")) {
        return SigningMethodPS384;
    }
    if (utils.eq(name, "PS512")) {
        return SigningMethodPS512;
    }

    if (utils.eq(name, "ES256")) {
        return SigningMethodES256;
    }
    if (utils.eq(name, "ES384")) {
        return SigningMethodES384;
    }

    if (utils.eq(name, "ES256K")) {
        return SigningMethodES256K;
    }

    if (utils.eq(name, "EdDSA")) {
        return SigningMethodEdDSA;
    }
    if (utils.eq(name, "ED25519")) {
        return SigningMethodED25519;
    }

    if (utils.eq(name, "HMD5")) {
        return SigningMethodHMD5;
    }
    if (utils.eq(name, "HSHA1")) {
        return SigningMethodHSHA1;
    }
    if (utils.eq(name, "HS224")) {
        return SigningMethodHS224;
    }
    if (utils.eq(name, "HS256")) {
        return SigningMethodHS256;
    }
    if (utils.eq(name, "HS384")) {
        return SigningMethodHS384;
    }
    if (utils.eq(name, "HS512")) {
        return SigningMethodHS512;
    }

    if (utils.eq(name, "BLAKE2B")) {
        return SigningMethodBLAKE2B;
    }

    if (utils.eq(name, "none")) {
        return SigningMethodNone;
    }

    return Error.JWTSigningMethodNotExists;
}

pub fn getTokenHeader(alloc: Allocator, token_string: []const u8) !Token.Header {
    var t = Token.init(alloc);
    t.parse(token_string);

    defer t.deinit();

    return t.getHeader();
}

test {
    _ = @import("jwt_test.zig");
}
