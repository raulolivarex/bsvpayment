const std = @import("std");
const hash_mod = @import("../crypto/hash.zig");

pub const Currency = enum {
    BSV, // satoshis
    USD, // cents
    EUR, // cents

    pub fn symbol(self: Currency) []const u8 {
        return switch (self) {
            .BSV => "BSV",
            .USD => "USD",
            .EUR => "EUR",
        };
    }

    pub fn decimals(self: Currency) u8 {
        return switch (self) {
            .BSV => 8, // satoshis
            .USD, .EUR => 2, // cents
        };
    }

    pub fn toByte(self: Currency) u8 {
        return switch (self) {
            .BSV => 0,
            .USD => 1,
            .EUR => 2,
        };
    }

    pub fn fromByte(b: u8) !Currency {
        return switch (b) {
            0 => .BSV,
            1 => .USD,
            2 => .EUR,
            else => error.InvalidCurrency,
        };
    }
};

pub const Transaction = struct {
    currency: Currency,
    amount: i64, // positive = deposit, negative = withdrawal
    timestamp: i64,
    description: [64]u8,
    desc_len: u8,

    pub fn getDescription(self: *const Transaction) []const u8 {
        return self.description[0..self.desc_len];
    }
};

pub const Account = struct {
    username: [32]u8,
    username_len: u8,
    password_hash: [32]u8, // SHA256(salt + password)
    salt: [16]u8,
    balance_bsv: i64, // in satoshis
    balance_usd: i64, // in cents
    balance_eur: i64, // in cents
    wallet_name: [32]u8, // linked wallet name
    wallet_name_len: u8,
    transactions: std.ArrayList(Transaction),
    allocator: std.mem.Allocator,

    pub fn getUsername(self: *const Account) []const u8 {
        return self.username[0..self.username_len];
    }

    pub fn getWalletName(self: *const Account) []const u8 {
        return self.wallet_name[0..self.wallet_name_len];
    }

    pub fn getBalance(self: *const Account, currency: Currency) i64 {
        return switch (currency) {
            .BSV => self.balance_bsv,
            .USD => self.balance_usd,
            .EUR => self.balance_eur,
        };
    }

    pub fn formatBalance(self: *const Account, currency: Currency, buf: []u8) []const u8 {
        const raw = self.getBalance(currency);
        const abs_val: u64 = if (raw < 0) @intCast(-raw) else @intCast(raw);
        const sign: []const u8 = if (raw < 0) "-" else "";

        return switch (currency) {
            .BSV => std.fmt.bufPrint(buf, "{s}{d}.{d:0>8} BSV", .{
                sign,
                abs_val / 100_000_000,
                abs_val % 100_000_000,
            }) catch "?",
            .USD => std.fmt.bufPrint(buf, "{s}${d}.{d:0>2}", .{
                sign,
                abs_val / 100,
                abs_val % 100,
            }) catch "?",
            .EUR => std.fmt.bufPrint(buf, "{s}€{d}.{d:0>2}", .{
                sign,
                abs_val / 100,
                abs_val % 100,
            }) catch "?",
        };
    }

    pub fn deposit(self: *Account, currency: Currency, amount: u64, description: []const u8) !void {
        switch (currency) {
            .BSV => self.balance_bsv += @intCast(amount),
            .USD => self.balance_usd += @intCast(amount),
            .EUR => self.balance_eur += @intCast(amount),
        }

        var desc_buf: [64]u8 = [_]u8{0} ** 64;
        const desc_len: u8 = @intCast(@min(description.len, 64));
        @memcpy(desc_buf[0..desc_len], description[0..desc_len]);

        try self.transactions.append(self.allocator, Transaction{
            .currency = currency,
            .amount = @intCast(amount),
            .timestamp = std.time.timestamp(),
            .description = desc_buf,
            .desc_len = desc_len,
        });
    }

    pub fn withdraw(self: *Account, currency: Currency, amount: u64, description: []const u8) !void {
        const current = self.getBalance(currency);
        if (current < @as(i64, @intCast(amount))) return error.InsufficientFunds;

        const neg_amount: i64 = -@as(i64, @intCast(amount));
        switch (currency) {
            .BSV => self.balance_bsv += neg_amount,
            .USD => self.balance_usd += neg_amount,
            .EUR => self.balance_eur += neg_amount,
        }

        var desc_buf: [64]u8 = [_]u8{0} ** 64;
        const desc_len: u8 = @intCast(@min(description.len, 64));
        @memcpy(desc_buf[0..desc_len], description[0..desc_len]);

        try self.transactions.append(self.allocator, Transaction{
            .currency = currency,
            .amount = neg_amount,
            .timestamp = std.time.timestamp(),
            .description = desc_buf,
            .desc_len = desc_len,
        });
    }

    pub fn deinit(self: *Account) void {
        self.transactions.deinit(self.allocator);
    }
};

/// Hash password with salt using SHA256
fn hashPassword(password: []const u8, salt: [16]u8) [32]u8 {
    var data: [48]u8 = undefined; // 16 salt + up to 32 password
    @memcpy(data[0..16], &salt);
    const pwd_len = @min(password.len, 32);
    @memcpy(data[16 .. 16 + pwd_len], password[0..pwd_len]);
    return hash_mod.sha256(data[0 .. 16 + pwd_len]);
}

/// Verify password against stored hash
fn verifyPassword(password: []const u8, salt: [16]u8, stored_hash: [32]u8) bool {
    const computed = hashPassword(password, salt);
    return std.mem.eql(u8, &computed, &stored_hash);
}

pub const AccountManager = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) AccountManager {
        return .{ .allocator = allocator };
    }

    fn getAccountDir(self: AccountManager) ![]u8 {
        const home = std.process.getEnvVarOwned(self.allocator, "USERPROFILE") catch
            try std.process.getEnvVarOwned(self.allocator, "HOME");
        defer self.allocator.free(home);
        return std.fmt.allocPrint(self.allocator, "{s}/.bsv-pay/accounts", .{home});
    }

    fn getAccountPath(self: AccountManager, username: []const u8) ![]u8 {
        const dir = try self.getAccountDir();
        defer self.allocator.free(dir);
        return std.fmt.allocPrint(self.allocator, "{s}/{s}.acc", .{ dir, username });
    }

    fn ensureDir(self: AccountManager) !void {
        const dir_path = try self.getAccountDir();
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

    /// Register a new account
    pub fn register(self: AccountManager, username: []const u8, password: []const u8, wallet_name: []const u8) !Account {
        if (username.len == 0 or username.len > 32) return error.InvalidUsername;
        if (password.len < 8) return error.PasswordTooShort;

        // Check if account exists
        const path = try self.getAccountPath(username);
        defer self.allocator.free(path);
        if (std.fs.openFileAbsolute(path, .{})) |f| {
            f.close();
            return error.AccountExists;
        } else |_| {}

        // Create account
        var salt: [16]u8 = undefined;
        std.crypto.random.bytes(&salt);
        const pwd_hash = hashPassword(password, salt);

        var uname_buf: [32]u8 = [_]u8{0} ** 32;
        @memcpy(uname_buf[0..username.len], username);

        var wname_buf: [32]u8 = [_]u8{0} ** 32;
        const wname_len: u8 = @intCast(@min(wallet_name.len, 32));
        @memcpy(wname_buf[0..wname_len], wallet_name[0..wname_len]);

        var account = Account{
            .username = uname_buf,
            .username_len = @intCast(username.len),
            .password_hash = pwd_hash,
            .salt = salt,
            .balance_bsv = 0,
            .balance_usd = 0,
            .balance_eur = 0,
            .wallet_name = wname_buf,
            .wallet_name_len = wname_len,
            .transactions = .{},
            .allocator = self.allocator,
        };

        try self.saveAccount(&account);
        return account;
    }

    /// Login to an existing account
    pub fn login(self: AccountManager, username: []const u8, password: []const u8) !Account {
        const path = try self.getAccountPath(username);
        defer self.allocator.free(path);

        const file = std.fs.openFileAbsolute(path, .{}) catch
            return error.AccountNotFound;
        defer file.close();

        const stat = try file.stat();
        const data = try self.allocator.alloc(u8, stat.size);
        defer self.allocator.free(data);
        const n = try file.readAll(data);

        return self.deserializeAccount(data[0..n], password);
    }

    /// Save account to disk (encrypted with AES-256-GCM)
    pub fn saveAccount(self: AccountManager, account: *const Account) !void {
        try self.ensureDir();

        const serialized = try self.serializeAccount(account);
        defer self.allocator.free(serialized);

        // Encrypt with account's password hash as key
        var nonce: [12]u8 = undefined;
        std.crypto.random.bytes(&nonce);
        const ciphertext = try self.allocator.alloc(u8, serialized.len);
        defer self.allocator.free(ciphertext);
        var tag: [16]u8 = undefined;

        std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(ciphertext, &tag, serialized, "", nonce, account.password_hash);

        // File format: [16 salt][12 nonce][ciphertext][16 tag]
        const total = 16 + 12 + ciphertext.len + 16;
        const output = try self.allocator.alloc(u8, total);
        defer self.allocator.free(output);

        var offset: usize = 0;
        @memcpy(output[offset..][0..16], &account.salt);
        offset += 16;
        @memcpy(output[offset..][0..12], &nonce);
        offset += 12;
        @memcpy(output[offset .. offset + ciphertext.len], ciphertext);
        offset += ciphertext.len;
        @memcpy(output[offset..][0..16], &tag);

        const path = try self.getAccountPath(account.getUsername());
        defer self.allocator.free(path);

        const file = try std.fs.createFileAbsolute(path, .{});
        defer file.close();
        try file.writeAll(output);
    }

    fn serializeAccount(self: AccountManager, account: *const Account) ![]u8 {
        // Fixed header: username(32) + username_len(1) + balance_bsv(8) + balance_usd(8) + balance_eur(8)
        //             + wallet_name(32) + wallet_name_len(1) + tx_count(4) + transactions(N*81)
        const tx_count: u32 = @intCast(account.transactions.items.len);
        const tx_size: usize = @as(usize, tx_count) * 81; // each tx: currency(1) + amount(8) + timestamp(8) + desc(64)
        const header_size: usize = 32 + 1 + 8 + 8 + 8 + 32 + 1 + 4;
        const total = header_size + tx_size;

        const buf = try self.allocator.alloc(u8, total);
        var offset: usize = 0;

        @memcpy(buf[offset..][0..32], &account.username);
        offset += 32;
        buf[offset] = account.username_len;
        offset += 1;
        std.mem.writeInt(i64, buf[offset..][0..8], account.balance_bsv, .little);
        offset += 8;
        std.mem.writeInt(i64, buf[offset..][0..8], account.balance_usd, .little);
        offset += 8;
        std.mem.writeInt(i64, buf[offset..][0..8], account.balance_eur, .little);
        offset += 8;
        @memcpy(buf[offset..][0..32], &account.wallet_name);
        offset += 32;
        buf[offset] = account.wallet_name_len;
        offset += 1;
        std.mem.writeInt(u32, buf[offset..][0..4], tx_count, .little);
        offset += 4;

        for (account.transactions.items) |tx| {
            buf[offset] = tx.currency.toByte();
            offset += 1;
            std.mem.writeInt(i64, buf[offset..][0..8], tx.amount, .little);
            offset += 8;
            std.mem.writeInt(i64, buf[offset..][0..8], tx.timestamp, .little);
            offset += 8;
            @memcpy(buf[offset..][0..64], &tx.description);
            offset += 64;
        }

        return buf;
    }

    fn deserializeAccount(self: AccountManager, data: []const u8, password: []const u8) !Account {
        if (data.len < 44) return error.InvalidAccountData; // 16 salt + 12 nonce + 0 + 16 tag

        // Extract salt, nonce, ciphertext, tag
        var offset: usize = 0;
        var salt: [16]u8 = undefined;
        @memcpy(&salt, data[offset..][0..16]);
        offset += 16;

        var nonce: [12]u8 = undefined;
        @memcpy(&nonce, data[offset..][0..12]);
        offset += 12;

        const ct_len = data.len - 44;
        const ciphertext = data[offset .. offset + ct_len];
        offset += ct_len;

        var tag: [16]u8 = undefined;
        @memcpy(&tag, data[offset..][0..16]);

        // Derive key and decrypt
        const pwd_hash = hashPassword(password, salt);
        const plaintext = try self.allocator.alloc(u8, ct_len);
        defer self.allocator.free(plaintext);

        std.crypto.aead.aes_gcm.Aes256Gcm.decrypt(plaintext, ciphertext, tag, "", nonce, pwd_hash) catch
            return error.WrongPassword;

        // Parse plaintext
        if (plaintext.len < 94) return error.InvalidAccountData;
        var poff: usize = 0;

        var username: [32]u8 = undefined;
        @memcpy(&username, plaintext[poff..][0..32]);
        poff += 32;
        const username_len = plaintext[poff];
        poff += 1;
        const balance_bsv = std.mem.readInt(i64, plaintext[poff..][0..8], .little);
        poff += 8;
        const balance_usd = std.mem.readInt(i64, plaintext[poff..][0..8], .little);
        poff += 8;
        const balance_eur = std.mem.readInt(i64, plaintext[poff..][0..8], .little);
        poff += 8;
        var wallet_name: [32]u8 = undefined;
        @memcpy(&wallet_name, plaintext[poff..][0..32]);
        poff += 32;
        const wallet_name_len = plaintext[poff];
        poff += 1;
        const tx_count = std.mem.readInt(u32, plaintext[poff..][0..4], .little);
        poff += 4;

        var transactions: std.ArrayList(Transaction) = .{};
        for (0..tx_count) |_| {
            const currency = try Currency.fromByte(plaintext[poff]);
            poff += 1;
            const amount = std.mem.readInt(i64, plaintext[poff..][0..8], .little);
            poff += 8;
            const timestamp = std.mem.readInt(i64, plaintext[poff..][0..8], .little);
            poff += 8;
            var desc: [64]u8 = undefined;
            @memcpy(&desc, plaintext[poff..][0..64]);
            poff += 64;

            var desc_len: u8 = 0;
            while (desc_len < 64 and desc[desc_len] != 0) : (desc_len += 1) {}

            try transactions.append(self.allocator, Transaction{
                .currency = currency,
                .amount = amount,
                .timestamp = timestamp,
                .description = desc,
                .desc_len = desc_len,
            });
        }

        return Account{
            .username = username,
            .username_len = username_len,
            .password_hash = pwd_hash,
            .salt = salt,
            .balance_bsv = balance_bsv,
            .balance_usd = balance_usd,
            .balance_eur = balance_eur,
            .wallet_name = wallet_name,
            .wallet_name_len = wallet_name_len,
            .transactions = transactions,
            .allocator = self.allocator,
        };
    }

    /// List all accounts
    pub fn listAccounts(self: AccountManager) ![][]u8 {
        const dir_path = try self.getAccountDir();
        defer self.allocator.free(dir_path);

        var dir = std.fs.openDirAbsolute(dir_path, .{ .iterate = true }) catch {
            return try self.allocator.alloc([]u8, 0);
        };
        defer dir.close();

        var names: std.ArrayList([]u8) = .{};
        var it = dir.iterate();
        while (try it.next()) |entry| {
            if (entry.kind == .file and std.mem.endsWith(u8, entry.name, ".acc")) {
                const name_len = entry.name.len - 4;
                const name = try self.allocator.alloc(u8, name_len);
                @memcpy(name, entry.name[0..name_len]);
                try names.append(self.allocator, name);
            }
        }

        return names.toOwnedSlice(self.allocator);
    }
};

test "account creation and balance" {
    const allocator = std.testing.allocator;
    var account = Account{
        .username = [_]u8{0} ** 32,
        .username_len = 4,
        .password_hash = [_]u8{0} ** 32,
        .salt = [_]u8{0} ** 16,
        .balance_bsv = 0,
        .balance_usd = 0,
        .balance_eur = 0,
        .wallet_name = [_]u8{0} ** 32,
        .wallet_name_len = 0,
        .transactions = .{},
        .allocator = allocator,
    };
    defer account.deinit();

    try account.deposit(.USD, 10000, "Initial deposit"); // $100.00
    try std.testing.expectEqual(@as(i64, 10000), account.getBalance(.USD));

    try account.deposit(.EUR, 5000, "EUR deposit"); // €50.00
    try std.testing.expectEqual(@as(i64, 5000), account.getBalance(.EUR));

    try account.withdraw(.USD, 2500, "Withdrawal"); // -$25.00
    try std.testing.expectEqual(@as(i64, 7500), account.getBalance(.USD));
}

test "insufficient funds" {
    const allocator = std.testing.allocator;
    var account = Account{
        .username = [_]u8{0} ** 32,
        .username_len = 4,
        .password_hash = [_]u8{0} ** 32,
        .salt = [_]u8{0} ** 16,
        .balance_bsv = 0,
        .balance_usd = 0,
        .balance_eur = 0,
        .wallet_name = [_]u8{0} ** 32,
        .wallet_name_len = 0,
        .transactions = .{},
        .allocator = allocator,
    };
    defer account.deinit();

    try std.testing.expectError(error.InsufficientFunds, account.withdraw(.USD, 100, "test"));
}
