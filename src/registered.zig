const std = @import("std");
const testing = std.testing;

// Defines the list of headers that are registered in the IANA "JSON Web Token Headers" registry
pub const RegisteredStdHeaders = struct {
    pub const Type = "typ";
    pub const Algorithm = "alg";
    pub const KeyID = "kid";
    pub const ContentType = "cty";
    pub const Encryption = "enc";
};

// Defines the list of claims that are registered in the IANA "JSON Web Token Claims" registry
pub const RegisteredStdClaims = struct {
    pub const Audience = "aud";
    pub const ExpirationTime = "exp";
    pub const ID = "jti";
    pub const IssuedAt = "iat";
    pub const Issuer = "iss";
    pub const NotBefore = "nbf";
    pub const Subject = "sub";
};

test "Registered" {
    try testing.expectEqualStrings("typ", RegisteredStdHeaders.Type);
    try testing.expectEqualStrings("alg", RegisteredStdHeaders.Algorithm);
    try testing.expectEqualStrings("kid", RegisteredStdHeaders.KeyID);
    try testing.expectEqualStrings("cty", RegisteredStdHeaders.ContentType);
    try testing.expectEqualStrings("enc", RegisteredStdHeaders.Encryption);

    try testing.expectEqualStrings("aud", RegisteredStdClaims.Audience);
    try testing.expectEqualStrings("exp", RegisteredStdClaims.ExpirationTime);
    try testing.expectEqualStrings("jti", RegisteredStdClaims.ID);
    try testing.expectEqualStrings("iat", RegisteredStdClaims.IssuedAt);
    try testing.expectEqualStrings("iss", RegisteredStdClaims.Issuer);
    try testing.expectEqualStrings("nbf", RegisteredStdClaims.NotBefore);
    try testing.expectEqualStrings("sub", RegisteredStdClaims.Subject);
}
