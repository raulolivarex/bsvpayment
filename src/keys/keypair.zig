const std = @import("std");
const secp = @import("../crypto/secp256k1.zig");
const hash = @import("../crypto/hash.zig");

pub const BSV_MAINNET_PUBKEY_PREFIX: u8 = 0x00;
pub const BSV_TESTNET_PUBKEY_PREFIX: u8 = 0x6F;
pub const BSV_MAINNET_WIF_PREFIX: u8 = 0x80;
pub const BSV_TESTNET_WIF_PREFIX: u8 = 0xEF;

pub const KeyPair = struct {
    private_key: secp.PrivateKey,
    public_key: secp.PublicKey,

    /// Generate a new random keypair
    pub fn generate() !KeyPair {
        const priv = secp.generatePrivateKey();
        const pub_key = try secp.derivePublicKey(priv);
        return KeyPair{
            .private_key = priv,
            .public_key = pub_key,
        };
    }

    /// Create from existing private key
    pub fn fromPrivateKey(private_key: secp.PrivateKey) !KeyPair {
        const pub_key = try secp.derivePublicKey(private_key);
        return KeyPair{
            .private_key = private_key,
            .public_key = pub_key,
        };
    }

    /// Create from WIF (Wallet Import Format) string
    pub fn fromWIF(wif: []const u8) !KeyPair {
        const decoded = try base58_decode(wif);
        // WIF: [1 prefix][32 privkey][1 compression flag][4 checksum]
        if (decoded.len < 37) return error.InvalidWIF;

        const prefix = decoded[0];
        if (prefix != BSV_MAINNET_WIF_PREFIX and prefix != BSV_TESTNET_WIF_PREFIX)
            return error.InvalidWIFPrefix;

        var private_key: secp.PrivateKey = undefined;
        @memcpy(&private_key, decoded[1..33]);

        return fromPrivateKey(private_key);
    }

    /// Get BSV address (mainnet)
    pub fn getAddress(self: KeyPair, allocator: std.mem.Allocator) ![]u8 {
        return getAddressWithPrefix(self, BSV_MAINNET_PUBKEY_PREFIX, allocator);
    }

    /// Get BSV address (testnet)
    pub fn getTestnetAddress(self: KeyPair, allocator: std.mem.Allocator) ![]u8 {
        return getAddressWithPrefix(self, BSV_TESTNET_PUBKEY_PREFIX, allocator);
    }

    fn getAddressWithPrefix(self: KeyPair, prefix: u8, allocator: std.mem.Allocator) ![]u8 {
        // HASH160 of public key
        const h160 = hash.hash160(&self.public_key);

        // Prepend version byte
        var payload: [21]u8 = undefined;
        payload[0] = prefix;
        @memcpy(payload[1..21], &h160);

        return hash.base58check_encode(&payload, allocator);
    }

    /// Export private key as WIF (Wallet Import Format)
    pub fn toWIF(self: KeyPair, allocator: std.mem.Allocator) ![]u8 {
        // [0x80][32 bytes privkey][0x01 compressed flag]
        var payload: [34]u8 = undefined;
        payload[0] = BSV_MAINNET_WIF_PREFIX;
        @memcpy(payload[1..33], &self.private_key);
        payload[33] = 0x01; // compressed

        return hash.base58check_encode(&payload, allocator);
    }
};

fn base58_decode(encoded: []const u8) ![]u8 {
    _ = encoded;
    // TODO: implement base58 decode for WIF import
    return error.NotImplemented;
}

test "keypair generation" {
    const kp = try KeyPair.generate();
    try std.testing.expect(kp.public_key[0] == 0x02 or kp.public_key[0] == 0x03);
}

test "address generation" {
    const kp = try KeyPair.generate();
    const addr = try kp.getAddress(std.testing.allocator);
    defer std.testing.allocator.free(addr);
    // BSV mainnet address starts with '1'
    try std.testing.expect(addr[0] == '1');
}
