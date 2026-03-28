const std = @import("std");
const Secp256k1 = std.crypto.ecc.Secp256k1;
const hash_mod = @import("../crypto/hash.zig");
const secp = @import("../crypto/secp256k1.zig");

/// BIP32 Extended Key
pub const ExtendedKey = struct {
    private_key: [32]u8,
    chain_code: [32]u8,
    depth: u8,
    parent_fingerprint: [4]u8,
    child_index: u32,

    /// Derive master key from BIP39 seed using HMAC-SHA512
    pub fn fromSeed(seed: [64]u8) !ExtendedKey {
        const HmacSha512 = std.crypto.auth.hmac.sha2.HmacSha512;
        var hmac_out: [64]u8 = undefined;
        HmacSha512.create(&hmac_out, &seed, "Bitcoin seed");

        return ExtendedKey{
            .private_key = hmac_out[0..32].*,
            .chain_code = hmac_out[32..64].*,
            .depth = 0,
            .parent_fingerprint = [_]u8{ 0, 0, 0, 0 },
            .child_index = 0,
        };
    }

    /// Derive a child key (hardened if index >= 0x80000000)
    pub fn deriveChild(self: ExtendedKey, index: u32) !ExtendedKey {
        const HmacSha512 = std.crypto.auth.hmac.sha2.HmacSha512;
        var data: [37]u8 = undefined;

        if (index >= 0x80000000) {
            // Hardened: 0x00 || private_key || index
            data[0] = 0x00;
            @memcpy(data[1..33], &self.private_key);
        } else {
            // Normal: public_key || index
            const pub_key = try secp.derivePublicKey(self.private_key);
            @memcpy(data[0..33], &pub_key);
        }
        std.mem.writeInt(u32, data[33..37], index, .big);

        var hmac_out: [64]u8 = undefined;
        HmacSha512.create(&hmac_out, &data, &self.chain_code);

        // child_key = parse256(IL) + parent_key (mod n)
        const il = hmac_out[0..32].*;
        var child_key: [32]u8 = undefined;

        // Add il to private_key mod curve order using scalar arithmetic
        const il_scalar = Secp256k1.scalar.Scalar.fromBytes(il, .big) catch
            return error.InvalidKey;
        const parent_scalar = Secp256k1.scalar.Scalar.fromBytes(self.private_key, .big) catch
            return error.InvalidKey;
        const child_scalar = il_scalar.add(parent_scalar);
        child_key = child_scalar.toBytes(.big);

        // Fingerprint of parent
        const parent_pub = try secp.derivePublicKey(self.private_key);
        const parent_hash = hash_mod.hash160(&parent_pub);
        var fingerprint: [4]u8 = undefined;
        @memcpy(&fingerprint, parent_hash[0..4]);

        return ExtendedKey{
            .private_key = child_key,
            .chain_code = hmac_out[32..64].*,
            .depth = self.depth + 1,
            .parent_fingerprint = fingerprint,
            .child_index = index,
        };
    }

    /// Derive BSV path: m/44'/236'/0'/0/index
    /// BSV uses coin type 236
    pub fn deriveBSVKey(self: ExtendedKey, address_index: u32) !ExtendedKey {
        const purpose = try self.deriveChild(0x80000000 + 44); // 44'
        const coin = try purpose.deriveChild(0x80000000 + 236); // 236' (BSV)
        const account = try coin.deriveChild(0x80000000 + 0); // 0'
        const change = try account.deriveChild(0); // 0 (external)
        return change.deriveChild(address_index); // index
    }

    /// Get the public key for this extended key
    pub fn getPublicKey(self: ExtendedKey) !secp.PublicKey {
        return secp.derivePublicKey(self.private_key);
    }
};

test "master key from seed" {
    var seed: [64]u8 = undefined;
    @memset(&seed, 0x01);
    const master = try ExtendedKey.fromSeed(seed);
    try std.testing.expect(master.depth == 0);
    try std.testing.expect(master.private_key[0] != 0 or master.private_key[1] != 0);
}

test "child derivation" {
    var seed: [64]u8 = undefined;
    @memset(&seed, 0x42);
    const master = try ExtendedKey.fromSeed(seed);
    const child = try master.deriveChild(0);
    try std.testing.expect(child.depth == 1);
    try std.testing.expect(!std.mem.eql(u8, &child.private_key, &master.private_key));
}

test "BSV path derivation" {
    var seed: [64]u8 = undefined;
    @memset(&seed, 0xAB);
    const master = try ExtendedKey.fromSeed(seed);
    const key0 = try master.deriveBSVKey(0);
    const key1 = try master.deriveBSVKey(1);
    try std.testing.expect(key0.depth == 5);
    try std.testing.expect(!std.mem.eql(u8, &key0.private_key, &key1.private_key));
}
