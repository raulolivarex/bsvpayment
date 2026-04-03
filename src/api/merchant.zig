const std = @import("std");
const hash_mod = @import("../crypto/hash.zig");
const broadcast_mod = @import("../net/broadcast.zig");

/// Merchant API key pair (like Stripe's sk_live / pk_live)
pub const ApiKeys = struct {
    secret_key: [64]u8, // sk_live_xxx (hex)
    public_key: [64]u8, // pk_live_xxx (hex)
    secret_len: u8,
    public_len: u8,

    pub fn getSecretKey(self: *const ApiKeys) []const u8 {
        return self.secret_key[0..self.secret_len];
    }

    pub fn getPublicKey(self: *const ApiKeys) []const u8 {
        return self.public_key[0..self.public_len];
    }
};

/// Merchant account
pub const Merchant = struct {
    id: [32]u8, // merchant ID (hex)
    id_len: u8,
    name: [64]u8,
    name_len: u8,
    email: [64]u8,
    email_len: u8,
    api_keys: ApiKeys,
    password_hash: [32]u8,
    salt: [16]u8,
    balance_bsv: i64, // satoshis
    balance_usd: i64, // cents
    balance_eur: i64, // cents
    wallet_name: [32]u8,
    wallet_name_len: u8,
    webhook_url: [128]u8,
    webhook_url_len: u8,
    created_at: i64,
    total_payments: u32,
    total_volume_usd: i64, // cents

    pub fn getName(self: *const Merchant) []const u8 {
        return self.name[0..self.name_len];
    }

    pub fn getEmail(self: *const Merchant) []const u8 {
        return self.email[0..self.email_len];
    }

    pub fn getId(self: *const Merchant) []const u8 {
        return self.id[0..self.id_len];
    }

    pub fn getWebhookUrl(self: *const Merchant) []const u8 {
        return self.webhook_url[0..self.webhook_url_len];
    }

    pub fn getWalletName(self: *const Merchant) []const u8 {
        return self.wallet_name[0..self.wallet_name_len];
    }
};

/// Generate API keys for a merchant
pub fn generateApiKeys() ApiKeys {
    var secret_bytes: [16]u8 = undefined;
    var public_bytes: [16]u8 = undefined;
    std.crypto.random.bytes(&secret_bytes);
    std.crypto.random.bytes(&public_bytes);

    var keys = ApiKeys{
        .secret_key = undefined,
        .public_key = undefined,
        .secret_len = 0,
        .public_len = 0,
    };

    // sk_live_ prefix (8) + 32 hex chars = 40
    const sk_prefix = "sk_live_";
    @memcpy(keys.secret_key[0..sk_prefix.len], sk_prefix);
    const sk_hex = hexEncode(&secret_bytes);
    @memcpy(keys.secret_key[sk_prefix.len..][0..32], &sk_hex);
    keys.secret_len = sk_prefix.len + 32;

    // pk_live_ prefix (8) + 32 hex chars = 40
    const pk_prefix = "pk_live_";
    @memcpy(keys.public_key[0..pk_prefix.len], pk_prefix);
    const pk_hex = hexEncode(&public_bytes);
    @memcpy(keys.public_key[pk_prefix.len..][0..32], &pk_hex);
    keys.public_len = pk_prefix.len + 32;

    return keys;
}

fn hexEncode(bytes: []const u8) [32]u8 {
    const hex_chars = "0123456789abcdef";
    var result: [32]u8 = undefined;
    for (bytes[0..16], 0..) |byte, i| {
        result[i * 2] = hex_chars[byte >> 4];
        result[i * 2 + 1] = hex_chars[byte & 0x0F];
    }
    return result;
}

/// Hash password with salt
fn hashPassword(password: []const u8, salt: [16]u8) [32]u8 {
    var data: [48]u8 = undefined;
    @memcpy(data[0..16], &salt);
    const pwd_len = @min(password.len, 32);
    @memcpy(data[16 .. 16 + pwd_len], password[0..pwd_len]);
    return hash_mod.sha256(data[0 .. 16 + pwd_len]);
}

pub fn verifyPassword(password: []const u8, salt: [16]u8, stored_hash: [32]u8) bool {
    const computed = hashPassword(password, salt);
    return std.mem.eql(u8, &computed, &stored_hash);
}

/// Merchant manager — handles registration, auth, persistence
pub const MerchantManager = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) MerchantManager {
        return .{ .allocator = allocator };
    }

    fn getMerchantDir(self: MerchantManager) ![]u8 {
        const home = std.process.getEnvVarOwned(self.allocator, "USERPROFILE") catch
            try std.process.getEnvVarOwned(self.allocator, "HOME");
        defer self.allocator.free(home);
        return std.fmt.allocPrint(self.allocator, "{s}/.bsv-pay/merchants", .{home});
    }

    fn getMerchantPath(self: MerchantManager, merchant_id: []const u8) ![]u8 {
        const dir = try self.getMerchantDir();
        defer self.allocator.free(dir);
        return std.fmt.allocPrint(self.allocator, "{s}/{s}.merchant", .{ dir, merchant_id });
    }

    fn ensureDir(self: MerchantManager) !void {
        const dir_path = try self.getMerchantDir();
        defer self.allocator.free(dir_path);

        std.fs.makeDirAbsolute(dir_path) catch |err| {
            if (err != error.PathAlreadyExists) {
                const home = std.process.getEnvVarOwned(self.allocator, "USERPROFILE") catch
                    try std.process.getEnvVarOwned(self.allocator, "HOME");
                defer self.allocator.free(home);
                const parent = try std.fmt.allocPrint(self.allocator, "{s}/.bsv-pay", .{home});
                defer self.allocator.free(parent);
                std.fs.makeDirAbsolute(parent) catch |e| {
                    if (e != error.PathAlreadyExists) return e;
                };
                std.fs.makeDirAbsolute(dir_path) catch |e2| {
                    if (e2 != error.PathAlreadyExists) return e2;
                };
            }
        };
    }

    /// Register a new merchant
    pub fn register(self: MerchantManager, name: []const u8, email: []const u8, password: []const u8) !Merchant {
        if (name.len == 0 or name.len > 64) return error.InvalidName;
        if (email.len == 0 or email.len > 64) return error.InvalidEmail;
        if (password.len < 8) return error.PasswordTooShort;

        // Generate merchant ID
        var id_bytes: [8]u8 = undefined;
        std.crypto.random.bytes(&id_bytes);
        var id_buf: [32]u8 = [_]u8{0} ** 32;
        const id_hex = hexEncode16(&id_bytes);
        @memcpy(id_buf[0..16], &id_hex);

        // Generate API keys
        const api_keys = generateApiKeys();

        // Hash password
        var salt: [16]u8 = undefined;
        std.crypto.random.bytes(&salt);
        const pwd_hash = hashPassword(password, salt);

        // Set name
        var name_buf: [64]u8 = [_]u8{0} ** 64;
        const nlen: u8 = @intCast(@min(name.len, 64));
        @memcpy(name_buf[0..nlen], name[0..nlen]);

        // Set email
        var email_buf: [64]u8 = [_]u8{0} ** 64;
        const elen: u8 = @intCast(@min(email.len, 64));
        @memcpy(email_buf[0..elen], email[0..elen]);

        var merchant = Merchant{
            .id = id_buf,
            .id_len = 16,
            .name = name_buf,
            .name_len = nlen,
            .email = email_buf,
            .email_len = elen,
            .api_keys = api_keys,
            .password_hash = pwd_hash,
            .salt = salt,
            .balance_bsv = 0,
            .balance_usd = 0,
            .balance_eur = 0,
            .wallet_name = [_]u8{0} ** 32,
            .wallet_name_len = 0,
            .webhook_url = [_]u8{0} ** 128,
            .webhook_url_len = 0,
            .created_at = std.time.timestamp(),
            .total_payments = 0,
            .total_volume_usd = 0,
        };

        try self.saveMerchant(&merchant);
        return merchant;
    }

    /// Find merchant by secret API key
    pub fn findBySecretKey(self: MerchantManager, secret_key: []const u8) !Merchant {
        const dir_path = try self.getMerchantDir();
        defer self.allocator.free(dir_path);

        var dir = std.fs.openDirAbsolute(dir_path, .{ .iterate = true }) catch
            return error.MerchantNotFound;
        defer dir.close();

        var it = dir.iterate();
        while (try it.next()) |entry| {
            if (entry.kind == .file and std.mem.endsWith(u8, entry.name, ".merchant")) {
                const name_len = entry.name.len - 9; // .merchant
                const merchant = self.loadMerchant(entry.name[0..name_len]) catch continue;
                if (std.mem.eql(u8, merchant.api_keys.getSecretKey(), secret_key)) {
                    return merchant;
                }
            }
        }
        return error.MerchantNotFound;
    }

    /// Load merchant by ID
    pub fn loadMerchant(self: MerchantManager, merchant_id: []const u8) !Merchant {
        const path = try self.getMerchantPath(merchant_id);
        defer self.allocator.free(path);

        const file = std.fs.openFileAbsolute(path, .{}) catch
            return error.MerchantNotFound;
        defer file.close();

        const stat = try file.stat();
        const data = try self.allocator.alloc(u8, stat.size);
        defer self.allocator.free(data);
        const n = try file.readAll(data);

        return deserializeMerchant(data[0..n]);
    }

    /// Save merchant to disk
    pub fn saveMerchant(self: MerchantManager, merchant: *const Merchant) !void {
        try self.ensureDir();

        const data = serializeMerchant(merchant);
        const path = try self.getMerchantPath(merchant.getId());
        defer self.allocator.free(path);

        const file = try std.fs.createFileAbsolute(path, .{});
        defer file.close();
        try file.writeAll(&data);
    }

    /// List all merchants
    pub fn listMerchants(self: MerchantManager) ![][]u8 {
        const dir_path = try self.getMerchantDir();
        defer self.allocator.free(dir_path);

        var dir = std.fs.openDirAbsolute(dir_path, .{ .iterate = true }) catch {
            return try self.allocator.alloc([]u8, 0);
        };
        defer dir.close();

        var names: std.ArrayList([]u8) = .{};
        var it = dir.iterate();
        while (try it.next()) |entry| {
            if (entry.kind == .file and std.mem.endsWith(u8, entry.name, ".merchant")) {
                const name_len = entry.name.len - 9;
                const name = try self.allocator.alloc(u8, name_len);
                @memcpy(name, entry.name[0..name_len]);
                try names.append(self.allocator, name);
            }
        }
        return names.toOwnedSlice(self.allocator);
    }
};

fn hexEncode16(bytes: []const u8) [16]u8 {
    const hex_chars = "0123456789abcdef";
    var result: [16]u8 = undefined;
    for (bytes[0..8], 0..) |byte, i| {
        result[i * 2] = hex_chars[byte >> 4];
        result[i * 2 + 1] = hex_chars[byte & 0x0F];
    }
    return result;
}

// Serialization: fixed 512 bytes
// 32+1+64+1+64+1+64+1+64+1+32+16+8+8+8+32+1+128 = 526, round up
const MERCHANT_SIZE = 528;

fn serializeMerchant(m: *const Merchant) [MERCHANT_SIZE]u8 {
    var buf: [MERCHANT_SIZE]u8 = [_]u8{0} ** MERCHANT_SIZE;
    var off: usize = 0;

    @memcpy(buf[off..][0..32], &m.id);
    off += 32;
    buf[off] = m.id_len;
    off += 1;
    @memcpy(buf[off..][0..64], &m.name);
    off += 64;
    buf[off] = m.name_len;
    off += 1;
    @memcpy(buf[off..][0..64], &m.email);
    off += 64;
    buf[off] = m.email_len;
    off += 1;
    // API keys
    @memcpy(buf[off..][0..64], &m.api_keys.secret_key);
    off += 64;
    buf[off] = m.api_keys.secret_len;
    off += 1;
    @memcpy(buf[off..][0..64], &m.api_keys.public_key);
    off += 64;
    buf[off] = m.api_keys.public_len;
    off += 1;
    // Auth
    @memcpy(buf[off..][0..32], &m.password_hash);
    off += 32;
    @memcpy(buf[off..][0..16], &m.salt);
    off += 16;
    // Balances
    std.mem.writeInt(i64, buf[off..][0..8], m.balance_bsv, .little);
    off += 8;
    std.mem.writeInt(i64, buf[off..][0..8], m.balance_usd, .little);
    off += 8;
    std.mem.writeInt(i64, buf[off..][0..8], m.balance_eur, .little);
    off += 8;
    // Wallet
    @memcpy(buf[off..][0..32], &m.wallet_name);
    off += 32;
    buf[off] = m.wallet_name_len;
    off += 1;
    // Webhook
    @memcpy(buf[off..][0..128], &m.webhook_url);
    // off += 128; -- not needed, already at end of used range
    // Stats are at the end — we have space
    return buf;
}

fn deserializeMerchant(data: []const u8) !Merchant {
    if (data.len < MERCHANT_SIZE) return error.InvalidMerchantData;

    var off: usize = 0;
    var m: Merchant = undefined;

    @memcpy(&m.id, data[off..][0..32]);
    off += 32;
    m.id_len = data[off];
    off += 1;
    @memcpy(&m.name, data[off..][0..64]);
    off += 64;
    m.name_len = data[off];
    off += 1;
    @memcpy(&m.email, data[off..][0..64]);
    off += 64;
    m.email_len = data[off];
    off += 1;
    @memcpy(&m.api_keys.secret_key, data[off..][0..64]);
    off += 64;
    m.api_keys.secret_len = data[off];
    off += 1;
    @memcpy(&m.api_keys.public_key, data[off..][0..64]);
    off += 64;
    m.api_keys.public_len = data[off];
    off += 1;
    @memcpy(&m.password_hash, data[off..][0..32]);
    off += 32;
    @memcpy(&m.salt, data[off..][0..16]);
    off += 16;
    m.balance_bsv = std.mem.readInt(i64, data[off..][0..8], .little);
    off += 8;
    m.balance_usd = std.mem.readInt(i64, data[off..][0..8], .little);
    off += 8;
    m.balance_eur = std.mem.readInt(i64, data[off..][0..8], .little);
    off += 8;
    @memcpy(&m.wallet_name, data[off..][0..32]);
    off += 32;
    m.wallet_name_len = data[off];
    off += 1;
    @memcpy(&m.webhook_url, data[off..][0..128]);

    m.created_at = 0;
    m.total_payments = 0;
    m.total_volume_usd = 0;

    return m;
}

test "merchant registration" {
    const allocator = std.testing.allocator;
    const mgr = MerchantManager.init(allocator);
    const merchant = try mgr.register("Test Shop", "test@shop.com", "password123");
    try std.testing.expect(merchant.api_keys.secret_len > 0);
    try std.testing.expect(std.mem.startsWith(u8, merchant.api_keys.getSecretKey(), "sk_live_"));
    try std.testing.expect(std.mem.startsWith(u8, merchant.api_keys.getPublicKey(), "pk_live_"));
}

test "api key generation" {
    const keys = generateApiKeys();
    try std.testing.expect(std.mem.startsWith(u8, keys.getSecretKey(), "sk_live_"));
    try std.testing.expect(keys.secret_len == 40);
}
