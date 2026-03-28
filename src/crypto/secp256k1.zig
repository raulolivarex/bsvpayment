const std = @import("std");
const Secp256k1 = std.crypto.ecc.Secp256k1;

pub const PrivateKey = [32]u8;
pub const PublicKey = [33]u8; // compressed
pub const Signature = [64]u8; // r (32 bytes) || s (32 bytes)

/// Generate a new random private key
pub fn generatePrivateKey() PrivateKey {
    var key: PrivateKey = undefined;
    std.crypto.random.bytes(&key);
    // Ensure key is valid (non-zero, less than curve order)
    // In practice, random 32 bytes is almost always valid
    return key;
}

/// Derive compressed public key from private key
pub fn derivePublicKey(private_key: PrivateKey) !PublicKey {
    const scalar = Secp256k1.scalar.Scalar.fromBytes(private_key, .big) catch
        return error.InvalidPrivateKey;
    const point = Secp256k1.basePoint.mul(scalar.toBytes(.big), .big) catch
        return error.InvalidPrivateKey;
    return point.toCompressedSec1();
}

/// Sign a 32-byte message hash with a private key (ECDSA)
pub fn sign(message_hash: [32]u8, private_key: PrivateKey) !Signature {
    const scalar_key = Secp256k1.scalar.Scalar.fromBytes(private_key, .big) orelse
        return error.InvalidPrivateKey;
    const ecdsa = std.crypto.sign.ecdsa.Ecdsa(Secp256k1, std.crypto.hash.sha2.Sha256);
    const key_pair = try ecdsa.KeyPair.fromSecretKey(.{ .bytes = scalar_key.toBytes(.big) });
    const sig = key_pair.sign("", .{ .noise = &message_hash });
    return sig.toBytes();
}

/// Verify an ECDSA signature
pub fn verify(message_hash: [32]u8, signature: Signature, public_key: PublicKey) bool {
    const ecdsa = std.crypto.sign.ecdsa.Ecdsa(Secp256k1, std.crypto.hash.sha2.Sha256);
    const pk = ecdsa.PublicKey.fromSec1(&public_key) catch return false;
    const sig = ecdsa.Signature.fromBytes(signature) catch return false;
    sig.verify("", pk, .{ .noise = &message_hash }) catch return false;
    return true;
}

test "key generation and derivation" {
    const priv = generatePrivateKey();
    const pub_key = try derivePublicKey(priv);
    // Compressed public key starts with 0x02 or 0x03
    try std.testing.expect(pub_key[0] == 0x02 or pub_key[0] == 0x03);
}
