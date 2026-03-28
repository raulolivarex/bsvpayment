const std = @import("std");
const hash_mod = @import("../crypto/hash.zig");
const secp = @import("../crypto/secp256k1.zig");
const keypair_mod = @import("../keys/keypair.zig");
const mnemonic_mod = @import("../bip39/mnemonic.zig");
const hd_mod = @import("../bip32/hd.zig");
const broadcast_mod = @import("../net/broadcast.zig");

/// Encrypted wallet stored on disk
/// Format: [16 salt][12 nonce][encrypted_data][16 tag]
pub const EncryptedWallet = struct {
    name: []const u8,
    allocator: std.mem.Allocator,

    pub fn getWalletDir(allocator: std.mem.Allocator) ![]u8 {
        const home = std.process.getEnvVarOwned(allocator, "USERPROFILE") catch
            try std.process.getEnvVarOwned(allocator, "HOME");
        defer allocator.free(home);
        return std.fmt.allocPrint(allocator, "{s}/.bsv-pay/wallets", .{home});
    }

    pub fn getWalletPath(name: []const u8, allocator: std.mem.Allocator) ![]u8 {
        const dir = try getWalletDir(allocator);
        defer allocator.free(dir);
        return std.fmt.allocPrint(allocator, "{s}/{s}.dat", .{ dir, name });
    }

    /// Create a new encrypted wallet with mnemonic
    pub fn create(
        name: []const u8,
        password: []const u8,
        allocator: std.mem.Allocator,
    ) !WalletData {
        // Generate mnemonic
        const words = mnemonic_mod.generateMnemonic();
        const mnemonic_str = try mnemonic_mod.mnemonicToString(words, allocator);

        // Derive seed from mnemonic
        const seed = try mnemonic_mod.mnemonicToSeed(words, "", allocator);

        // Derive master key and first BSV key
        const master = try hd_mod.ExtendedKey.fromSeed(seed);
        const bsv_key = try master.deriveBSVKey(0);
        const pub_key = try secp.derivePublicKey(bsv_key.private_key);

        // Get address
        const kp = keypair_mod.KeyPair{
            .private_key = bsv_key.private_key,
            .public_key = pub_key,
        };
        const address = try kp.getAddress(allocator);

        // Build wallet data to encrypt
        const wallet_data = WalletData{
            .name = name,
            .mnemonic = mnemonic_str,
            .address = address,
            .public_key = pub_key,
            .private_key = bsv_key.private_key,
            .seed = seed,
            .allocator = allocator,
        };

        // Serialize and encrypt
        const serialized = try wallet_data.serialize(allocator);
        defer allocator.free(serialized);

        const encrypted = try encrypt(serialized, password, allocator);
        defer allocator.free(encrypted);

        // Save to file
        try saveToFile(name, encrypted, allocator);

        return wallet_data;
    }

    /// Restore wallet from mnemonic phrase
    pub fn restore(
        name: []const u8,
        mnemonic_str: []const u8,
        password: []const u8,
        allocator: std.mem.Allocator,
    ) !WalletData {
        const words = try mnemonic_mod.parseMnemonic(mnemonic_str);
        const seed = try mnemonic_mod.mnemonicToSeed(words, "", allocator);
        const master = try hd_mod.ExtendedKey.fromSeed(seed);
        const bsv_key = try master.deriveBSVKey(0);
        const pub_key = try secp.derivePublicKey(bsv_key.private_key);

        const kp = keypair_mod.KeyPair{
            .private_key = bsv_key.private_key,
            .public_key = pub_key,
        };
        const address = try kp.getAddress(allocator);

        const mnemonic_copy = try allocator.alloc(u8, mnemonic_str.len);
        @memcpy(mnemonic_copy, mnemonic_str);

        const wallet_data = WalletData{
            .name = name,
            .mnemonic = mnemonic_copy,
            .address = address,
            .public_key = pub_key,
            .private_key = bsv_key.private_key,
            .seed = seed,
            .allocator = allocator,
        };

        const serialized = try wallet_data.serialize(allocator);
        defer allocator.free(serialized);

        const encrypted = try encrypt(serialized, password, allocator);
        defer allocator.free(encrypted);

        try saveToFile(name, encrypted, allocator);

        return wallet_data;
    }

    /// Open an existing encrypted wallet
    pub fn open(
        name: []const u8,
        password: []const u8,
        allocator: std.mem.Allocator,
    ) !WalletData {
        const path = try getWalletPath(name, allocator);
        defer allocator.free(path);

        const file = std.fs.openFileAbsolute(path, .{}) catch
            return error.WalletNotFound;
        defer file.close();

        const stat = try file.stat();
        const encrypted = try allocator.alloc(u8, stat.size);
        defer allocator.free(encrypted);
        const n = try file.readAll(encrypted);

        const decrypted = try decrypt(encrypted[0..n], password, allocator);
        defer allocator.free(decrypted);

        return WalletData.deserialize(name, decrypted, allocator);
    }

    /// List all saved wallets
    pub fn listWallets(allocator: std.mem.Allocator) ![][]u8 {
        const dir_path = try getWalletDir(allocator);
        defer allocator.free(dir_path);

        var dir = std.fs.openDirAbsolute(dir_path, .{ .iterate = true }) catch {
            // No wallets directory
            return try allocator.alloc([]u8, 0);
        };
        defer dir.close();

        var names: std.ArrayList([]u8) = .{};

        var it = dir.iterate();
        while (try it.next()) |entry| {
            if (entry.kind == .file) {
                const fname = entry.name;
                if (std.mem.endsWith(u8, fname, ".dat")) {
                    const name_len = fname.len - 4;
                    const name = try allocator.alloc(u8, name_len);
                    @memcpy(name, fname[0..name_len]);
                    try names.append(allocator, name);
                }
            }
        }

        return names.toOwnedSlice(allocator);
    }

    /// Delete a wallet file
    pub fn deleteWallet(name: []const u8, allocator: std.mem.Allocator) !void {
        const path = try getWalletPath(name, allocator);
        defer allocator.free(path);
        std.fs.deleteFileAbsolute(path) catch return error.WalletNotFound;
    }
};

/// Decrypted wallet data in memory
pub const WalletData = struct {
    name: []const u8,
    mnemonic: []const u8,
    address: []const u8,
    public_key: [33]u8,
    private_key: [32]u8,
    seed: [64]u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *WalletData) void {
        self.allocator.free(self.mnemonic);
        self.allocator.free(self.address);
    }

    /// Serialize wallet data to bytes
    /// Format: [32 privkey][64 seed][mnemonic_len(u16)][mnemonic_bytes]
    pub fn serialize(self: *const WalletData, allocator: std.mem.Allocator) ![]u8 {
        const total = 32 + 64 + 2 + self.mnemonic.len;
        var buf = try allocator.alloc(u8, total);
        var offset: usize = 0;

        @memcpy(buf[offset..][0..32], &self.private_key);
        offset += 32;
        @memcpy(buf[offset..][0..64], &self.seed);
        offset += 64;
        std.mem.writeInt(u16, buf[offset..][0..2], @intCast(self.mnemonic.len), .little);
        offset += 2;
        @memcpy(buf[offset .. offset + self.mnemonic.len], self.mnemonic);

        return buf;
    }

    /// Deserialize wallet data from bytes
    pub fn deserialize(name: []const u8, data: []const u8, allocator: std.mem.Allocator) !WalletData {
        if (data.len < 98) return error.InvalidWalletData;

        var offset: usize = 0;

        var private_key: [32]u8 = undefined;
        @memcpy(&private_key, data[offset..][0..32]);
        offset += 32;

        var seed: [64]u8 = undefined;
        @memcpy(&seed, data[offset..][0..64]);
        offset += 64;

        const mnemonic_len = std.mem.readInt(u16, data[offset..][0..2], .little);
        offset += 2;

        if (offset + mnemonic_len > data.len) return error.InvalidWalletData;

        const mnemonic = try allocator.alloc(u8, mnemonic_len);
        @memcpy(mnemonic, data[offset .. offset + mnemonic_len]);

        const pub_key = try secp.derivePublicKey(private_key);
        const kp = keypair_mod.KeyPair{
            .private_key = private_key,
            .public_key = pub_key,
        };
        const address = try kp.getAddress(allocator);

        return WalletData{
            .name = name,
            .mnemonic = mnemonic,
            .address = address,
            .public_key = pub_key,
            .private_key = private_key,
            .seed = seed,
            .allocator = allocator,
        };
    }
};

/// Derive encryption key from password using PBKDF2
fn deriveEncryptionKey(password: []const u8, salt: [16]u8) [32]u8 {
    var key: [32]u8 = undefined;
    std.crypto.pwhash.pbkdf2(&key, password, &salt, 100_000, std.crypto.auth.hmac.sha2.HmacSha256) catch unreachable;
    return key;
}

/// Encrypt data with AES-256-GCM
fn encrypt(plaintext: []const u8, password: []const u8, allocator: std.mem.Allocator) ![]u8 {
    // Generate random salt and nonce
    var salt: [16]u8 = undefined;
    std.crypto.random.bytes(&salt);
    var nonce: [12]u8 = undefined;
    std.crypto.random.bytes(&nonce);

    // Derive key from password
    const key = deriveEncryptionKey(password, salt);

    // Encrypt with AES-256-GCM
    const ciphertext = try allocator.alloc(u8, plaintext.len);
    defer allocator.free(ciphertext);
    var tag: [16]u8 = undefined;

    std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(ciphertext, &tag, plaintext, "", nonce, key);

    // Output: [16 salt][12 nonce][ciphertext][16 tag]
    const total = 16 + 12 + ciphertext.len + 16;
    var output = try allocator.alloc(u8, total);
    var offset: usize = 0;

    @memcpy(output[offset..][0..16], &salt);
    offset += 16;
    @memcpy(output[offset..][0..12], &nonce);
    offset += 12;
    @memcpy(output[offset .. offset + ciphertext.len], ciphertext);
    offset += ciphertext.len;
    @memcpy(output[offset..][0..16], &tag);

    return output;
}

/// Decrypt data with AES-256-GCM
fn decrypt(encrypted: []const u8, password: []const u8, allocator: std.mem.Allocator) ![]u8 {
    if (encrypted.len < 44) return error.InvalidEncryptedData; // 16+12+0+16

    var offset: usize = 0;

    var salt: [16]u8 = undefined;
    @memcpy(&salt, encrypted[offset..][0..16]);
    offset += 16;

    var nonce: [12]u8 = undefined;
    @memcpy(&nonce, encrypted[offset..][0..12]);
    offset += 12;

    const ciphertext_len = encrypted.len - 44;
    const ciphertext = encrypted[offset .. offset + ciphertext_len];
    offset += ciphertext_len;

    var tag: [16]u8 = undefined;
    @memcpy(&tag, encrypted[offset..][0..16]);

    // Derive key
    const key = deriveEncryptionKey(password, salt);

    // Decrypt
    const plaintext = try allocator.alloc(u8, ciphertext_len);
    std.crypto.aead.aes_gcm.Aes256Gcm.decrypt(plaintext, ciphertext, tag, "", nonce, key) catch {
        allocator.free(plaintext);
        return error.WrongPassword;
    };

    return plaintext;
}

/// Save encrypted data to wallet file
fn saveToFile(name: []const u8, data: []const u8, allocator: std.mem.Allocator) !void {
    const dir_path = try EncryptedWallet.getWalletDir(allocator);
    defer allocator.free(dir_path);

    // Create directory recursively
    std.fs.makeDirAbsolute(dir_path) catch |err| {
        if (err != error.PathAlreadyExists) {
            // Try creating parent first
            const home = std.process.getEnvVarOwned(allocator, "USERPROFILE") catch
                try std.process.getEnvVarOwned(allocator, "HOME");
            defer allocator.free(home);
            const parent = try std.fmt.allocPrint(allocator, "{s}/.bsv-pay", .{home});
            defer allocator.free(parent);
            std.fs.makeDirAbsolute(parent) catch |e| {
                if (e != error.PathAlreadyExists) return e;
            };
            std.fs.makeDirAbsolute(dir_path) catch |e2| {
                if (e2 != error.PathAlreadyExists) return e2;
            };
        }
    };

    const path = try EncryptedWallet.getWalletPath(name, allocator);
    defer allocator.free(path);

    const file = try std.fs.createFileAbsolute(path, .{});
    defer file.close();
    try file.writeAll(data);
}

test "encrypt decrypt roundtrip" {
    const allocator = std.testing.allocator;
    const plaintext = "hello BSV wallet secret data";
    const password = "mypassword123";

    const encrypted = try encrypt(plaintext, password, allocator);
    defer allocator.free(encrypted);

    const decrypted = try decrypt(encrypted, password, allocator);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "wrong password fails" {
    const allocator = std.testing.allocator;
    const plaintext = "secret";
    const encrypted = try encrypt(plaintext, "correct", allocator);
    defer allocator.free(encrypted);

    const result = decrypt(encrypted, "wrong", allocator);
    try std.testing.expectError(error.WrongPassword, result);
}
