const std = @import("std");
const wallet_mod = @import("wallet/wallet.zig");
const encrypted_mod = @import("wallet/encrypted.zig");
const keypair_mod = @import("keys/keypair.zig");
const broadcast_mod = @import("net/broadcast.zig");
const hash_mod = @import("crypto/hash.zig");
const account_mod = @import("account/account.zig");
const exchange_mod = @import("exchange/rates.zig");
const transfer_mod = @import("pay/transfer.zig");
const merchant_mod = @import("api/merchant.zig");
const payments_mod = @import("api/payments.zig");
const server_mod = @import("api/server.zig");
const checkout_mod = @import("api/checkout.zig");

// Re-export modules for tests
comptime {
    _ = @import("crypto/hash.zig");
    _ = @import("crypto/secp256k1.zig");
    _ = @import("keys/keypair.zig");
    _ = @import("tx/script.zig");
    _ = @import("tx/sighash.zig");
    _ = @import("tx/transaction.zig");
    _ = @import("net/broadcast.zig");
    _ = @import("wallet/wallet.zig");
    _ = @import("wallet/encrypted.zig");
    _ = @import("bip39/mnemonic.zig");
    _ = @import("bip32/hd.zig");
    _ = @import("account/account.zig");
    _ = @import("exchange/rates.zig");
    _ = @import("pay/transfer.zig");
    _ = @import("api/merchant.zig");
    _ = @import("api/payments.zig");
    _ = @import("api/server.zig");
    _ = @import("api/checkout.zig");
}

const VERSION = "0.4.0";

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        printUsage();
        return;
    }

    const command = args[1];

    if (std.mem.eql(u8, command, "account")) {
        if (args.len < 3) {
            printAccountUsage();
            return;
        }
        const sub = args[2];

        if (std.mem.eql(u8, sub, "register")) {
            try cmdAccountRegister(allocator);
        } else if (std.mem.eql(u8, sub, "login")) {
            try cmdAccountLogin(allocator);
        } else if (std.mem.eql(u8, sub, "deposit")) {
            if (args.len < 5) {
                std.debug.print("Usage: bsv-pay account deposit <currency> <amount>\n", .{});
                std.debug.print("  currency: BSV, USD, EUR\n", .{});
                std.debug.print("  amount: in smallest unit (satoshis/cents)\n", .{});
                return;
            }
            try cmdAccountDeposit(allocator, args[3], args[4]);
        } else if (std.mem.eql(u8, sub, "withdraw")) {
            if (args.len < 5) {
                std.debug.print("Usage: bsv-pay account withdraw <currency> <amount>\n", .{});
                return;
            }
            try cmdAccountWithdraw(allocator, args[3], args[4]);
        } else if (std.mem.eql(u8, sub, "history")) {
            try cmdAccountHistory(allocator);
        } else if (std.mem.eql(u8, sub, "list")) {
            try cmdAccountList(allocator);
        } else {
            std.debug.print("Unknown account command: {s}\n", .{sub});
            printAccountUsage();
        }
    } else if (std.mem.eql(u8, command, "send")) {
        try cmdSend(allocator);
    } else if (std.mem.eql(u8, command, "rates")) {
        try cmdRates(allocator);
    } else if (std.mem.eql(u8, command, "api")) {
        if (args.len < 3) {
            printApiUsage();
            return;
        }
        const sub = args[2];
        if (std.mem.eql(u8, sub, "start")) {
            const port: u16 = if (args.len >= 4) std.fmt.parseInt(u16, args[3], 10) catch 3000 else 3000;
            try cmdApiStart(allocator, port);
        } else {
            printApiUsage();
        }
    } else if (std.mem.eql(u8, command, "merchant")) {
        if (args.len < 3) {
            printMerchantUsage();
            return;
        }
        const sub = args[2];
        if (std.mem.eql(u8, sub, "register")) {
            try cmdMerchantRegister(allocator);
        } else if (std.mem.eql(u8, sub, "keys")) {
            try cmdMerchantKeys(allocator);
        } else if (std.mem.eql(u8, sub, "balance")) {
            try cmdMerchantBalance(allocator);
        } else if (std.mem.eql(u8, sub, "dashboard")) {
            try cmdMerchantDashboard(allocator);
        } else if (std.mem.eql(u8, sub, "list")) {
            try cmdMerchantList(allocator);
        } else {
            printMerchantUsage();
        }
    } else if (std.mem.eql(u8, command, "wallet")) {
        if (args.len < 3) {
            printWalletUsage();
            return;
        }
        const sub = args[2];

        if (std.mem.eql(u8, sub, "create")) {
            if (args.len < 4) {
                std.debug.print("Usage: bsv-pay wallet create <name>\n", .{});
                return;
            }
            try cmdWalletCreate(allocator, args[3]);
        } else if (std.mem.eql(u8, sub, "restore")) {
            if (args.len < 4) {
                std.debug.print("Usage: bsv-pay wallet restore <name>\n", .{});
                return;
            }
            try cmdWalletRestore(allocator, args[3]);
        } else if (std.mem.eql(u8, sub, "open")) {
            if (args.len < 4) {
                std.debug.print("Usage: bsv-pay wallet open <name>\n", .{});
                return;
            }
            try cmdWalletOpen(allocator, args[3]);
        } else if (std.mem.eql(u8, sub, "list")) {
            try cmdWalletList(allocator);
        } else if (std.mem.eql(u8, sub, "delete")) {
            if (args.len < 4) {
                std.debug.print("Usage: bsv-pay wallet delete <name>\n", .{});
                return;
            }
            try cmdWalletDelete(allocator, args[3]);
        } else {
            std.debug.print("Unknown wallet command: {s}\n", .{sub});
            printWalletUsage();
        }
    } else if (std.mem.eql(u8, command, "generate")) {
        try cmdGenerate(allocator);
    } else if (std.mem.eql(u8, command, "balance")) {
        if (args.len < 3) {
            std.debug.print("Usage: bsv-pay balance <address>\n", .{});
            return;
        }
        try cmdBalance(allocator, args[2]);
    } else if (std.mem.eql(u8, command, "version")) {
        std.debug.print("bsv-pay v{s} — Ultra-fast BSV payments in Zig\n", .{VERSION});
    } else {
        std.debug.print("Unknown command: {s}\n", .{command});
        printUsage();
    }
}

fn printUsage() void {
    std.debug.print(
        \\
        \\  ╔══════════════════════════════════════╗
        \\  ║         bsv-pay v{s}              ║
        \\  ║   Ultra-fast BSV payments in Zig     ║
        \\  ╚══════════════════════════════════════╝
        \\
        \\  PAYMENT API (Stripe-style):
        \\
        \\    api start [port]          Start REST API server (default 3000)
        \\    merchant register         Register as merchant (get API keys)
        \\    merchant keys             View your API keys
        \\    merchant balance          View merchant balance
        \\    merchant dashboard        View payment history
        \\    merchant list             List all merchants
        \\
        \\  SEND MONEY (Bizum-style):
        \\
        \\    send                      Send money to another user
        \\                              (EUR/USD auto-converts via BSV)
        \\    rates                     Show live BSV exchange rates
        \\
        \\  ACCOUNT COMMANDS:
        \\
        \\    account register          Create account (user/pass + wallet)
        \\    account login             Login and view balances
        \\    account deposit <cur> <n> Deposit funds (BSV/USD/EUR)
        \\    account withdraw <cur> <n> Withdraw funds
        \\    account history           View transaction history
        \\    account list              List all accounts
        \\
        \\  WALLET COMMANDS:
        \\
        \\    wallet create <name>      Create encrypted wallet with seed
        \\    wallet restore <name>     Restore from seed phrase
        \\    wallet open <name>        Open wallet details
        \\    wallet list               List all wallets
        \\    wallet delete <name>      Delete a wallet
        \\
        \\  OTHER COMMANDS:
        \\
        \\    generate                  Generate a keypair (no save)
        \\    balance <address>         Check BSV balance on-chain
        \\    version                   Show version
        \\
    , .{VERSION});
}

fn printAccountUsage() void {
    std.debug.print(
        \\
        \\  ACCOUNT COMMANDS:
        \\
        \\    account register             Create new account
        \\    account login                Login to account
        \\    account deposit <cur> <amt>  Deposit (BSV/USD/EUR, amount in cents/sats)
        \\    account withdraw <cur> <amt> Withdraw funds
        \\    account history              Transaction history
        \\    account list                 List accounts
        \\
        \\  Examples:
        \\    bsv-pay account deposit USD 10000     # Deposit $100.00
        \\    bsv-pay account deposit EUR 5000      # Deposit €50.00
        \\    bsv-pay account deposit BSV 100000    # Deposit 0.00100000 BSV
        \\    bsv-pay account withdraw USD 2500     # Withdraw $25.00
        \\
    , .{});
}

fn printWalletUsage() void {
    std.debug.print(
        \\
        \\  WALLET COMMANDS:
        \\
        \\    wallet create <name>      Create new encrypted wallet
        \\    wallet restore <name>     Restore from seed phrase
        \\    wallet open <name>        Open wallet (requires password)
        \\    wallet list               List all wallets
        \\    wallet delete <name>      Delete a wallet
        \\
    , .{});
}

fn readLine(buf: []u8) []const u8 {
    const file = std.fs.File.stdin();
    var idx: usize = 0;
    while (idx < buf.len) {
        var byte: [1]u8 = undefined;
        const n = file.read(&byte) catch break;
        if (n == 0) break;
        if (byte[0] == '\n') break;
        buf[idx] = byte[0];
        idx += 1;
    }
    if (idx > 0 and buf[idx - 1] == '\r') idx -= 1;
    return buf[0..idx];
}

fn readPassword(prompt: []const u8) ![128]u8 {
    std.debug.print("{s}", .{prompt});
    var buf: [128]u8 = undefined;
    @memset(&buf, 0);
    const line = readLine(&buf);
    var result: [128]u8 = undefined;
    @memset(&result, 0);
    @memcpy(result[0..line.len], line);
    return result;
}

fn getPasswordSlice(buf: *const [128]u8) []const u8 {
    var len: usize = 0;
    while (len < 128 and buf[len] != 0) : (len += 1) {}
    return buf[0..len];
}

fn parseCurrency(str: []const u8) ?account_mod.Currency {
    if (std.ascii.eqlIgnoreCase(str, "BSV") or std.ascii.eqlIgnoreCase(str, "bsv")) return .BSV;
    if (std.ascii.eqlIgnoreCase(str, "USD") or std.ascii.eqlIgnoreCase(str, "usd")) return .USD;
    if (std.ascii.eqlIgnoreCase(str, "EUR") or std.ascii.eqlIgnoreCase(str, "eur")) return .EUR;
    return null;
}

// ═══════════════════════════════════════════
// ACCOUNT COMMANDS
// ═══════════════════════════════════════════

fn cmdAccountRegister(allocator: std.mem.Allocator) !void {
    std.debug.print("\n  ╔══════════════════════════════════════╗\n", .{});
    std.debug.print("  ║         Create New Account            ║\n", .{});
    std.debug.print("  ╚══════════════════════════════════════╝\n\n", .{});

    std.debug.print("  Username: ", .{});
    var uname_buf: [32]u8 = undefined;
    const username = readLine(&uname_buf);

    if (username.len == 0) {
        std.debug.print("  ✗ Username cannot be empty.\n", .{});
        return;
    }

    const pw1 = try readPassword("  Password (min 8 chars): ");
    const pw2 = try readPassword("  Confirm password: ");
    const pass1 = getPasswordSlice(&pw1);
    const pass2 = getPasswordSlice(&pw2);

    if (!std.mem.eql(u8, pass1, pass2)) {
        std.debug.print("\n  ✗ Passwords don't match!\n", .{});
        return;
    }
    if (pass1.len < 8) {
        std.debug.print("\n  ✗ Password must be at least 8 characters!\n", .{});
        return;
    }

    // Create wallet automatically
    std.debug.print("\n  Creating BSV wallet...\n", .{});
    const wallet_name = username; // wallet name = username

    var wallet_data = encrypted_mod.EncryptedWallet.create(wallet_name, pass1, allocator) catch |err| {
        std.debug.print("  ✗ Error creating wallet: {}\n", .{err});
        return;
    };
    defer wallet_data.deinit();

    // Create account linked to wallet
    const mgr = account_mod.AccountManager.init(allocator);
    var account = mgr.register(username, pass1, wallet_name) catch |err| {
        if (err == error.AccountExists) {
            std.debug.print("  ✗ Account '{s}' already exists.\n", .{username});
        } else {
            std.debug.print("  ✗ Error creating account: {}\n", .{err});
        }
        return;
    };
    defer account.deinit();

    std.debug.print(
        \\
        \\  ╔══════════════════════════════════════════════════════╗
        \\  ║         ✦ Account Created Successfully               ║
        \\  ╚══════════════════════════════════════════════════════╝
        \\
        \\  Username   : {s}
        \\  BSV Address: {s}
        \\  Network    : BSV Mainnet
        \\
        \\  Balances:
        \\    BSV: 0.00000000 BSV
        \\    USD: $0.00
        \\    EUR: €0.00
        \\
        \\  ┌──────────────────────────────────────────────────────┐
        \\  │  SEED PHRASE (write this down!)                      │
        \\  │  {s}
        \\  │                                                      │
        \\  │  ⚠ Keep this safe! It restores your BSV wallet.      │
        \\  └──────────────────────────────────────────────────────┘
        \\
        \\  Encrypted with AES-256-GCM. Saved to disk.
        \\
    , .{ username, wallet_data.address, wallet_data.mnemonic });
}

fn cmdAccountLogin(allocator: std.mem.Allocator) !void {
    std.debug.print("\n  ── Login ──\n\n", .{});

    std.debug.print("  Username: ", .{});
    var uname_buf: [32]u8 = undefined;
    const username = readLine(&uname_buf);

    const pw = try readPassword("  Password: ");
    const pass = getPasswordSlice(&pw);

    const mgr = account_mod.AccountManager.init(allocator);
    var account = mgr.login(username, pass) catch |err| {
        if (err == error.WrongPassword) {
            std.debug.print("\n  ✗ Wrong password!\n", .{});
        } else if (err == error.AccountNotFound) {
            std.debug.print("\n  ✗ Account '{s}' not found.\n", .{username});
        } else {
            std.debug.print("\n  ✗ Login error: {}\n", .{err});
        }
        return;
    };
    defer account.deinit();

    // Get BSV address from linked wallet
    const wname = account.getWalletName();
    var bsv_address: []const u8 = "N/A";
    var wallet_data_opt: ?encrypted_mod.WalletData = null;
    if (wname.len > 0) {
        if (encrypted_mod.EncryptedWallet.open(wname, pass, allocator)) |wd| {
            wallet_data_opt = wd;
            bsv_address = wd.address;
        } else |_| {}
    }
    defer if (wallet_data_opt) |*wd| wd.deinit();

    var bsv_buf: [64]u8 = undefined;
    var usd_buf: [64]u8 = undefined;
    var eur_buf: [64]u8 = undefined;
    const bsv_str = account.formatBalance(.BSV, &bsv_buf);
    const usd_str = account.formatBalance(.USD, &usd_buf);
    const eur_str = account.formatBalance(.EUR, &eur_buf);

    std.debug.print(
        \\
        \\  ✦ Welcome back, {s}!
        \\  ────────────────────────────────────────
        \\  BSV Address : {s}
        \\  Wallet      : {s}
        \\
        \\  Balances:
        \\  ┌──────────────────────────────────┐
        \\  │  BSV : {s}
        \\  │  USD : {s}
        \\  │  EUR : {s}
        \\  └──────────────────────────────────┘
        \\
        \\  Transactions: {d}
        \\  ────────────────────────────────────────
        \\
    , .{
        account.getUsername(),
        bsv_address,
        wname,
        bsv_str,
        usd_str,
        eur_str,
        account.transactions.items.len,
    });
}

fn cmdAccountDeposit(allocator: std.mem.Allocator, currency_str: []const u8, amount_str: []const u8) !void {
    const currency = parseCurrency(currency_str) orelse {
        std.debug.print("  ✗ Invalid currency. Use: BSV, USD, EUR\n", .{});
        return;
    };

    const amount = std.fmt.parseInt(u64, amount_str, 10) catch {
        std.debug.print("  ✗ Invalid amount.\n", .{});
        return;
    };

    std.debug.print("  Username: ", .{});
    var uname_buf: [32]u8 = undefined;
    const username = readLine(&uname_buf);
    const pw = try readPassword("  Password: ");
    const pass = getPasswordSlice(&pw);

    const mgr = account_mod.AccountManager.init(allocator);
    var account = mgr.login(username, pass) catch |err| {
        if (err == error.WrongPassword) {
            std.debug.print("\n  ✗ Wrong password!\n", .{});
        } else {
            std.debug.print("\n  ✗ Login failed: {}\n", .{err});
        }
        return;
    };
    defer account.deinit();

    account.deposit(currency, amount, "Deposit") catch |err| {
        std.debug.print("  ✗ Deposit error: {}\n", .{err});
        return;
    };

    // Save updated account
    mgr.saveAccount(&account) catch |err| {
        std.debug.print("  ✗ Error saving: {}\n", .{err});
        return;
    };

    var bal_buf: [64]u8 = undefined;
    const bal_str = account.formatBalance(currency, &bal_buf);

    std.debug.print("\n  ✓ Deposited {s} {s}\n", .{ amount_str, currency.symbol() });
    std.debug.print("  New {s} balance: {s}\n\n", .{ currency.symbol(), bal_str });
}

fn cmdAccountWithdraw(allocator: std.mem.Allocator, currency_str: []const u8, amount_str: []const u8) !void {
    const currency = parseCurrency(currency_str) orelse {
        std.debug.print("  ✗ Invalid currency. Use: BSV, USD, EUR\n", .{});
        return;
    };

    const amount = std.fmt.parseInt(u64, amount_str, 10) catch {
        std.debug.print("  ✗ Invalid amount.\n", .{});
        return;
    };

    std.debug.print("  Username: ", .{});
    var uname_buf: [32]u8 = undefined;
    const username = readLine(&uname_buf);
    const pw = try readPassword("  Password: ");
    const pass = getPasswordSlice(&pw);

    const mgr = account_mod.AccountManager.init(allocator);
    var account = mgr.login(username, pass) catch |err| {
        if (err == error.WrongPassword) {
            std.debug.print("\n  ✗ Wrong password!\n", .{});
        } else {
            std.debug.print("\n  ✗ Login failed: {}\n", .{err});
        }
        return;
    };
    defer account.deinit();

    account.withdraw(currency, amount, "Withdrawal") catch |err| {
        if (err == error.InsufficientFunds) {
            std.debug.print("\n  ✗ Insufficient funds!\n", .{});
        } else {
            std.debug.print("  ✗ Withdrawal error: {}\n", .{err});
        }
        return;
    };

    mgr.saveAccount(&account) catch |err| {
        std.debug.print("  ✗ Error saving: {}\n", .{err});
        return;
    };

    var bal_buf: [64]u8 = undefined;
    const bal_str = account.formatBalance(currency, &bal_buf);

    std.debug.print("\n  ✓ Withdrew {s} {s}\n", .{ amount_str, currency.symbol() });
    std.debug.print("  New {s} balance: {s}\n\n", .{ currency.symbol(), bal_str });
}

fn cmdAccountHistory(allocator: std.mem.Allocator) !void {
    std.debug.print("  Username: ", .{});
    var uname_buf: [32]u8 = undefined;
    const username = readLine(&uname_buf);
    const pw = try readPassword("  Password: ");
    const pass = getPasswordSlice(&pw);

    const mgr = account_mod.AccountManager.init(allocator);
    var account = mgr.login(username, pass) catch |err| {
        if (err == error.WrongPassword) {
            std.debug.print("\n  ✗ Wrong password!\n", .{});
        } else {
            std.debug.print("\n  ✗ Login failed: {}\n", .{err});
        }
        return;
    };
    defer account.deinit();

    std.debug.print("\n  Transaction History for '{s}':\n", .{account.getUsername()});
    std.debug.print("  ────────────────────────────────────────\n", .{});

    if (account.transactions.items.len == 0) {
        std.debug.print("  No transactions yet.\n\n", .{});
        return;
    }

    for (account.transactions.items, 1..) |tx, i| {
        const sign: []const u8 = if (tx.amount >= 0) "+" else "";
        const abs_val: u64 = if (tx.amount < 0) @intCast(-tx.amount) else @intCast(tx.amount);

        switch (tx.currency) {
            .BSV => std.debug.print("  {d}. {s}{d} sats BSV — {s}\n", .{ i, sign, abs_val, tx.getDescription() }),
            .USD => std.debug.print("  {d}. {s}${d}.{d:0>2} — {s}\n", .{ i, sign, abs_val / 100, abs_val % 100, tx.getDescription() }),
            .EUR => std.debug.print("  {d}. {s}€{d}.{d:0>2} — {s}\n", .{ i, sign, abs_val / 100, abs_val % 100, tx.getDescription() }),
        }
    }
    std.debug.print("  ────────────────────────────────────────\n\n", .{});
}

fn cmdAccountList(allocator: std.mem.Allocator) !void {
    const mgr = account_mod.AccountManager.init(allocator);
    const names = mgr.listAccounts() catch {
        std.debug.print("\n  No accounts found.\n", .{});
        return;
    };
    defer {
        for (names) |name| allocator.free(name);
        allocator.free(names);
    }

    if (names.len == 0) {
        std.debug.print("\n  No accounts found. Create one with: bsv-pay account register\n", .{});
        return;
    }

    std.debug.print("\n  Registered Accounts:\n  ────────────────────────────────────────\n", .{});
    for (names, 1..) |name, i| {
        std.debug.print("  {d}. {s}\n", .{ i, name });
    }
    std.debug.print("  ────────────────────────────────────────\n\n", .{});
}

// ═══════════════════════════════════════════
// WALLET COMMANDS
// ═══════════════════════════════════════════

fn cmdWalletCreate(allocator: std.mem.Allocator, name: []const u8) !void {
    std.debug.print("\n  Creating wallet '{s}'...\n\n", .{name});

    const pw1 = try readPassword("  Enter password: ");
    const pw2 = try readPassword("  Confirm password: ");
    const pass1 = getPasswordSlice(&pw1);
    const pass2 = getPasswordSlice(&pw2);

    if (!std.mem.eql(u8, pass1, pass2)) {
        std.debug.print("\n  ✗ Passwords don't match!\n", .{});
        return;
    }
    if (pass1.len < 8) {
        std.debug.print("\n  ✗ Password must be at least 8 characters!\n", .{});
        return;
    }

    var wallet_data = encrypted_mod.EncryptedWallet.create(name, pass1, allocator) catch |err| {
        std.debug.print("\n  ✗ Error creating wallet: {}\n", .{err});
        return;
    };
    defer wallet_data.deinit();

    std.debug.print(
        \\
        \\  ╔══════════════════════════════════════════════════════╗
        \\  ║              ✦ Wallet Created Successfully           ║
        \\  ╚══════════════════════════════════════════════════════╝
        \\
        \\  Name     : {s}
        \\  Address  : {s}
        \\  Network  : BSV Mainnet
        \\
        \\  ┌──────────────────────────────────────────────────────┐
        \\  │  SEED PHRASE (write this down and keep it safe!)     │
        \\  │                                                      │
        \\  │  {s}
        \\  │                                                      │
        \\  │  ⚠ Anyone with these words can access your funds!    │
        \\  │  ⚠ Never share them. Never store them digitally.     │
        \\  └──────────────────────────────────────────────────────┘
        \\
        \\  Wallet encrypted with AES-256-GCM and saved to disk.
        \\
    , .{ name, wallet_data.address, wallet_data.mnemonic });
}

fn cmdWalletRestore(allocator: std.mem.Allocator, name: []const u8) !void {
    std.debug.print("\n  Restoring wallet '{s}'...\n\n", .{name});
    std.debug.print("  Enter 12-word seed phrase: ", .{});
    var mnemonic_buf: [256]u8 = undefined;
    const mnemonic = readLine(&mnemonic_buf);

    const pw1 = try readPassword("  Enter password: ");
    const pw2 = try readPassword("  Confirm password: ");
    const pass1 = getPasswordSlice(&pw1);
    const pass2 = getPasswordSlice(&pw2);

    if (!std.mem.eql(u8, pass1, pass2)) {
        std.debug.print("\n  ✗ Passwords don't match!\n", .{});
        return;
    }

    var wallet_data = encrypted_mod.EncryptedWallet.restore(name, mnemonic, pass1, allocator) catch |err| {
        std.debug.print("\n  ✗ Error restoring wallet: {}\n", .{err});
        return;
    };
    defer wallet_data.deinit();

    std.debug.print(
        \\
        \\  ✦ Wallet Restored Successfully
        \\  ────────────────────────────────────────
        \\  Name     : {s}
        \\  Address  : {s}
        \\  Network  : BSV Mainnet
        \\  ────────────────────────────────────────
        \\
    , .{ name, wallet_data.address });
}

fn cmdWalletOpen(allocator: std.mem.Allocator, name: []const u8) !void {
    const pw = try readPassword("  Enter password: ");
    const pass = getPasswordSlice(&pw);

    var wallet_data = encrypted_mod.EncryptedWallet.open(name, pass, allocator) catch |err| {
        if (err == error.WrongPassword) {
            std.debug.print("\n  ✗ Wrong password!\n", .{});
        } else if (err == error.WalletNotFound) {
            std.debug.print("\n  ✗ Wallet '{s}' not found.\n", .{name});
        } else {
            std.debug.print("\n  ✗ Error: {}\n", .{err});
        }
        return;
    };
    defer wallet_data.deinit();

    const pub_hex = try broadcast_mod.bytesToHex(&wallet_data.public_key, allocator);
    defer allocator.free(pub_hex);

    std.debug.print(
        \\
        \\  ✦ Wallet: {s}
        \\  ────────────────────────────────────────
        \\  Address    : {s}
        \\  Public Key : {s}
        \\  Mnemonic   : {s}
        \\  Network    : BSV Mainnet
        \\  Derivation : m/44'/236'/0'/0/0
        \\  Encryption : AES-256-GCM
        \\  ────────────────────────────────────────
        \\
    , .{ name, wallet_data.address, pub_hex, wallet_data.mnemonic });
}

fn cmdWalletList(allocator: std.mem.Allocator) !void {
    const names = encrypted_mod.EncryptedWallet.listWallets(allocator) catch {
        std.debug.print("\n  No wallets found.\n", .{});
        return;
    };
    defer {
        for (names) |name| allocator.free(name);
        allocator.free(names);
    }

    if (names.len == 0) {
        std.debug.print("\n  No wallets found.\n", .{});
        return;
    }

    std.debug.print("\n  Saved Wallets:\n  ────────────────────────────────────────\n", .{});
    for (names, 1..) |name, i| {
        std.debug.print("  {d}. {s}\n", .{ i, name });
    }
    std.debug.print("  ────────────────────────────────────────\n\n", .{});
}

fn cmdWalletDelete(allocator: std.mem.Allocator, name: []const u8) !void {
    std.debug.print("  ⚠ Delete wallet '{s}'? (yes/no): ", .{name});
    var buf: [16]u8 = undefined;
    const line = readLine(&buf);
    if (std.mem.eql(u8, line, "yes")) {
        encrypted_mod.EncryptedWallet.deleteWallet(name, allocator) catch {
            std.debug.print("  ✗ Wallet '{s}' not found.\n", .{name});
            return;
        };
        std.debug.print("  ✓ Wallet '{s}' deleted.\n", .{name});
    } else {
        std.debug.print("  Cancelled.\n", .{});
    }
}

fn cmdGenerate(allocator: std.mem.Allocator) !void {
    const kp = try keypair_mod.KeyPair.generate();
    const priv_hex = try broadcast_mod.bytesToHex(&kp.private_key, allocator);
    defer allocator.free(priv_hex);
    const pub_hex = try broadcast_mod.bytesToHex(&kp.public_key, allocator);
    defer allocator.free(pub_hex);
    const address = try kp.getAddress(allocator);
    defer allocator.free(address);
    const wif = try kp.toWIF(allocator);
    defer allocator.free(wif);

    std.debug.print(
        \\
        \\  ✦ New BSV Keypair (not saved)
        \\  ────────────────────────────────────────
        \\  Private Key : {s}
        \\  Public Key  : {s}
        \\  Address     : {s}
        \\  WIF         : {s}
        \\  ────────────────────────────────────────
        \\
    , .{ priv_hex, pub_hex, address, wif });
}

fn cmdBalance(allocator: std.mem.Allocator, address: []const u8) !void {
    const client = broadcast_mod.WocClient.init(.mainnet, allocator);
    const result = client.getBalance(address) catch {
        std.debug.print("Error: Could not fetch balance.\n", .{});
        return;
    };
    defer allocator.free(result);
    std.debug.print("Balance: {s}\n", .{result});
}

// ═══════════════════════════════════════════
// SEND / BIZUM COMMANDS
// ═══════════════════════════════════════════

fn cmdSend(allocator: std.mem.Allocator) !void {
    std.debug.print(
        \\
        \\  ╔══════════════════════════════════════╗
        \\  ║           Send Money                  ║
        \\  ║     (powered by BSV, invisible)       ║
        \\  ╚══════════════════════════════════════╝
        \\
    , .{});

    // Sender login
    std.debug.print("  Your username: ", .{});
    var sender_buf: [32]u8 = undefined;
    const sender_name = readLine(&sender_buf);

    const pw = try readPassword("  Your password: ");
    const pass = getPasswordSlice(&pw);

    const mgr = account_mod.AccountManager.init(allocator);
    var sender = mgr.login(sender_name, pass) catch |err| {
        if (err == error.WrongPassword) {
            std.debug.print("\n  ✗ Wrong password!\n", .{});
        } else if (err == error.AccountNotFound) {
            std.debug.print("\n  ✗ Account not found.\n", .{});
        } else {
            std.debug.print("\n  ✗ Error: {}\n", .{err});
        }
        return;
    };
    defer sender.deinit();

    // Recipient
    std.debug.print("  Recipient username: ", .{});
    var recv_buf: [32]u8 = undefined;
    const recv_name = readLine(&recv_buf);

    if (std.mem.eql(u8, sender_name, recv_name)) {
        std.debug.print("\n  ✗ Cannot send to yourself!\n", .{});
        return;
    }

    // Receiver needs to confirm with their password (like Bizum confirmation)
    const recv_pw = try readPassword("  Recipient password (confirmation): ");
    const recv_pass = getPasswordSlice(&recv_pw);

    var receiver2 = mgr.login(recv_name, recv_pass) catch |err| {
        if (err == error.WrongPassword) {
            std.debug.print("\n  ✗ Recipient password incorrect!\n", .{});
        } else if (err == error.AccountNotFound) {
            std.debug.print("\n  ✗ Recipient '{s}' not found.\n", .{recv_name});
        } else {
            std.debug.print("\n  ✗ Error: {}\n", .{err});
        }
        return;
    };
    defer receiver2.deinit();

    // Currency and amount
    std.debug.print("  Currency to send (EUR/USD): ", .{});
    var cur_buf: [8]u8 = undefined;
    const cur_str = readLine(&cur_buf);
    const currency = parseCurrency(cur_str) orelse {
        std.debug.print("\n  ✗ Invalid currency. Use EUR or USD.\n", .{});
        return;
    };

    std.debug.print("  Amount (e.g. 10.50): ", .{});
    var amt_buf: [32]u8 = undefined;
    const amt_str = readLine(&amt_buf);
    const amount_cents = parseAmount(amt_str, currency) orelse {
        std.debug.print("\n  ✗ Invalid amount.\n", .{});
        return;
    };

    if (amount_cents == 0) {
        std.debug.print("\n  ✗ Amount must be greater than 0.\n", .{});
        return;
    }

    // Fetch exchange rate
    std.debug.print("\n  Fetching BSV exchange rate...\n", .{});
    const rates = exchange_mod.ExchangeRates.fetchLive(allocator) catch {
        std.debug.print("  ✗ Could not fetch exchange rate. Using fallback.\n", .{});
        // Fallback rates for offline/testing
        return cmdSendWithRates(
            &sender,
            &receiver2,
            pass,
            amount_cents,
            currency,
            currency,
            exchange_mod.ExchangeRates{ .bsv_usd = 50.0, .bsv_eur = 46.0, .timestamp = std.time.timestamp() },
            mgr,
            allocator,
        );
    };

    return cmdSendWithRates(&sender, &receiver2, pass, amount_cents, currency, currency, rates, mgr, allocator);
}

fn cmdSendWithRates(
    sender: *account_mod.Account,
    receiver: *account_mod.Account,
    sender_password: []const u8,
    amount_cents: u64,
    send_currency: account_mod.Currency,
    recv_currency: account_mod.Currency,
    rates: exchange_mod.ExchangeRates,
    mgr: account_mod.AccountManager,
    allocator: std.mem.Allocator,
) !void {
    // Show confirmation
    var rate_buf: [64]u8 = undefined;
    const rate_str = rates.formatRate(send_currency, &rate_buf);
    const satoshis = rates.fiatToSatoshis(send_currency, amount_cents);

    const whole = amount_cents / 100;
    const frac = amount_cents % 100;
    const sym = send_currency.symbol();

    std.debug.print(
        \\
        \\  ┌──────────────────────────────────────────┐
        \\  │  Transfer Summary                         │
        \\  ├──────────────────────────────────────────┤
        \\  │  From    : {s}
        \\  │  To      : {s}
        \\  │  Amount  : {s}{d}.{d:0>2}
        \\  │  Rate    : {s}
        \\  │  BSV     : {d} satoshis (invisible)
        \\  └──────────────────────────────────────────┘
        \\
    , .{
        sender.getUsername(),
        receiver.getUsername(),
        sym,
        whole,
        frac,
        rate_str,
        satoshis,
    });

    std.debug.print("  Confirm? (yes/no): ", .{});
    var confirm_buf: [8]u8 = undefined;
    const confirm = readLine(&confirm_buf);
    if (!std.mem.eql(u8, confirm, "yes")) {
        std.debug.print("  Cancelled.\n", .{});
        return;
    }

    // Execute transfer
    var result = transfer_mod.executeTransfer(
        sender,
        receiver,
        sender_password,
        amount_cents,
        send_currency,
        recv_currency,
        rates,
        allocator,
    ) catch |err| {
        if (err == error.InsufficientFunds) {
            std.debug.print("\n  ✗ Insufficient funds!\n", .{});
        } else if (err == error.AmountTooSmall) {
            std.debug.print("\n  ✗ Amount too small to convert to BSV.\n", .{});
        } else if (err == error.AmountBelowDust) {
            std.debug.print("\n  ✗ Amount below BSV dust limit (546 sats).\n", .{});
        } else {
            std.debug.print("\n  ✗ Transfer error: {}\n", .{err});
        }
        return;
    };
    defer result.deinit();

    // Save both accounts
    mgr.saveAccount(sender) catch |err| {
        std.debug.print("  ✗ Error saving sender: {}\n", .{err});
    };
    mgr.saveAccount(receiver) catch |err| {
        std.debug.print("  ✗ Error saving receiver: {}\n", .{err});
    };

    // Show success
    std.debug.print(
        \\
        \\  ╔══════════════════════════════════════════╗
        \\  ║         ✦ Transfer Complete!               ║
        \\  ╚══════════════════════════════════════════╝
        \\
        \\  {s}{d}.{d:0>2} sent to {s}
        \\
        \\  Settlement: {d} satoshis via BSV network
        \\  Speed: ~0-conf instant (< 1 second)
        \\  Fee: < 1 sat/byte (~$0.0001)
        \\
    , .{
        sym,
        whole,
        frac,
        receiver.getUsername(),
        result.amount_satoshis,
    });

    if (result.txid) |txid| {
        std.debug.print("  On-chain TXID: {s}\n\n", .{txid});
    } else {
        std.debug.print("  Settlement: account-level (on-chain when UTXOs available)\n\n", .{});
    }
}

fn cmdRates(allocator: std.mem.Allocator) !void {
    std.debug.print("\n  Fetching live BSV exchange rates...\n", .{});

    const rates = exchange_mod.ExchangeRates.fetchLive(allocator) catch {
        std.debug.print("  ✗ Could not fetch rates. Check your internet connection.\n\n", .{});
        return;
    };

    var usd_buf: [64]u8 = undefined;
    var eur_buf: [64]u8 = undefined;
    const usd_str = rates.formatRate(.USD, &usd_buf);
    const eur_str = rates.formatRate(.EUR, &eur_buf);

    std.debug.print(
        \\
        \\  ╔══════════════════════════════════════╗
        \\  ║         BSV Exchange Rates            ║
        \\  ╚══════════════════════════════════════╝
        \\
        \\  {s}
        \\  {s}
        \\
        \\  Source: CoinGecko (live)
        \\
    , .{ usd_str, eur_str });
}

/// Parse "10.50" or "10" into cents (1050 or 1000)
fn parseAmount(str: []const u8, currency: account_mod.Currency) ?u64 {
    if (str.len == 0) return null;

    // For BSV, parse as satoshis directly
    if (currency == .BSV) {
        return std.fmt.parseInt(u64, str, 10) catch null;
    }

    // Find decimal point
    var dot_pos: ?usize = null;
    for (str, 0..) |c, i| {
        if (c == '.' or c == ',') {
            dot_pos = i;
            break;
        }
    }

    if (dot_pos) |dp| {
        const whole = std.fmt.parseInt(u64, str[0..dp], 10) catch return null;
        const frac_str = str[dp + 1 ..];
        var frac: u64 = 0;
        if (frac_str.len >= 1) {
            frac = std.fmt.parseInt(u64, frac_str, 10) catch return null;
            if (frac_str.len == 1) frac *= 10; // "10.5" → 50 cents
        }
        return whole * 100 + frac;
    } else {
        const whole = std.fmt.parseInt(u64, str, 10) catch return null;
        return whole * 100;
    }
}

// ═══════════════════════════════════════════
// API / MERCHANT COMMANDS
// ═══════════════════════════════════════════

fn printApiUsage() void {
    std.debug.print(
        \\
        \\  API COMMANDS:
        \\
        \\    api start [port]    Start REST API server (default: 3000)
        \\
        \\  Example:
        \\    bsv-pay api start 8080
        \\
    , .{});
}

fn printMerchantUsage() void {
    std.debug.print(
        \\
        \\  MERCHANT COMMANDS:
        \\
        \\    merchant register     Register new merchant account
        \\    merchant keys         View API keys (sk_live / pk_live)
        \\    merchant balance      View balance and stats
        \\    merchant dashboard    View payment history
        \\    merchant list         List all merchants
        \\
    , .{});
}

fn cmdApiStart(allocator: std.mem.Allocator, port: u16) !void {
    const server = server_mod.ApiServer.init(allocator, port);
    try server.start();
}

fn cmdMerchantRegister(allocator: std.mem.Allocator) !void {
    std.debug.print(
        \\
        \\  ╔══════════════════════════════════════╗
        \\  ║       Register as Merchant            ║
        \\  ╚══════════════════════════════════════╝
        \\
    , .{});

    std.debug.print("  Business name: ", .{});
    var name_buf: [64]u8 = undefined;
    const name = readLine(&name_buf);

    std.debug.print("  Email: ", .{});
    var email_buf: [64]u8 = undefined;
    const email = readLine(&email_buf);

    const pw1 = try readPassword("  Password (min 8 chars): ");
    const pw2 = try readPassword("  Confirm password: ");
    const pass1 = getPasswordSlice(&pw1);
    const pass2 = getPasswordSlice(&pw2);

    if (!std.mem.eql(u8, pass1, pass2)) {
        std.debug.print("\n  ✗ Passwords don't match!\n", .{});
        return;
    }
    if (pass1.len < 8) {
        std.debug.print("\n  ✗ Password must be at least 8 characters!\n", .{});
        return;
    }

    const mgr = merchant_mod.MerchantManager.init(allocator);
    const merchant = mgr.register(name, email, pass1) catch |err| {
        std.debug.print("\n  ✗ Registration error: {}\n", .{err});
        return;
    };

    std.debug.print(
        \\
        \\  ╔══════════════════════════════════════════════════════╗
        \\  ║       ✦ Merchant Registered Successfully              ║
        \\  ╚══════════════════════════════════════════════════════╝
        \\
        \\  Business    : {s}
        \\  Email       : {s}
        \\  Merchant ID : {s}
        \\
        \\  ┌──────────────────────────────────────────────────────┐
        \\  │  API KEYS (save these!)                               │
        \\  │                                                       │
        \\  │  Secret:  {s}
        \\  │  Public:  {s}
        \\  │                                                       │
        \\  │  Use the secret key in Authorization: Bearer header   │
        \\  │  ⚠ Never share your secret key!                       │
        \\  └──────────────────────────────────────────────────────┘
        \\
        \\  Quick start:
        \\    1. bsv-pay api start
        \\    2. curl -X POST http://localhost:3000/v1/payments \
        \\         -H "Authorization: Bearer {s}" \
        \\         -d '{{"amount":1000,"currency":"USD","description":"Test"}}'
        \\
    , .{
        merchant.getName(),
        merchant.getEmail(),
        merchant.getId(),
        merchant.api_keys.getSecretKey(),
        merchant.api_keys.getPublicKey(),
        merchant.api_keys.getSecretKey(),
    });
}

fn cmdMerchantKeys(allocator: std.mem.Allocator) !void {
    std.debug.print("  Merchant ID: ", .{});
    var id_buf: [32]u8 = undefined;
    const merchant_id = readLine(&id_buf);

    const mgr = merchant_mod.MerchantManager.init(allocator);
    const merchant = mgr.loadMerchant(merchant_id) catch {
        std.debug.print("\n  ✗ Merchant not found.\n", .{});
        return;
    };

    std.debug.print(
        \\
        \\  API Keys for {s}:
        \\  ────────────────────────────────────────
        \\  Secret: {s}
        \\  Public: {s}
        \\  ────────────────────────────────────────
        \\
    , .{
        merchant.getName(),
        merchant.api_keys.getSecretKey(),
        merchant.api_keys.getPublicKey(),
    });
}

fn cmdMerchantBalance(allocator: std.mem.Allocator) !void {
    std.debug.print("  Merchant ID: ", .{});
    var id_buf: [32]u8 = undefined;
    const merchant_id = readLine(&id_buf);

    const mgr = merchant_mod.MerchantManager.init(allocator);
    const merchant = mgr.loadMerchant(merchant_id) catch {
        std.debug.print("\n  ✗ Merchant not found.\n", .{});
        return;
    };

    const usd_whole: u64 = @intCast(@divTrunc(@as(i64, @intCast(@abs(merchant.balance_usd))), 100));
    const usd_frac: u64 = @intCast(@mod(@as(i64, @intCast(@abs(merchant.balance_usd))), 100));
    const eur_whole: u64 = @intCast(@divTrunc(@as(i64, @intCast(@abs(merchant.balance_eur))), 100));
    const eur_frac: u64 = @intCast(@mod(@as(i64, @intCast(@abs(merchant.balance_eur))), 100));

    std.debug.print(
        \\
        \\  ✦ Merchant: {s}
        \\  ────────────────────────────────────────
        \\  Balances:
        \\    BSV : {d} satoshis
        \\    USD : ${d}.{d:0>2}
        \\    EUR : €{d}.{d:0>2}
        \\
        \\  Stats:
        \\    Total payments : {d}
        \\  ────────────────────────────────────────
        \\
    , .{
        merchant.getName(),
        merchant.balance_bsv,
        usd_whole,
        usd_frac,
        eur_whole,
        eur_frac,
        merchant.total_payments,
    });
}

fn cmdMerchantDashboard(allocator: std.mem.Allocator) !void {
    std.debug.print("  Merchant ID: ", .{});
    var id_buf: [32]u8 = undefined;
    const merchant_id = readLine(&id_buf);

    const mgr = merchant_mod.MerchantManager.init(allocator);
    const merchant = mgr.loadMerchant(merchant_id) catch {
        std.debug.print("\n  ✗ Merchant not found.\n", .{});
        return;
    };

    const engine = payments_mod.PaymentEngine.init(allocator);
    const payments = engine.listPayments(merchant_id) catch {
        std.debug.print("\n  No payments found.\n", .{});
        return;
    };
    defer allocator.free(payments);

    std.debug.print(
        \\
        \\  ✦ Dashboard: {s}
        \\  ════════════════════════════════════════════════
        \\
    , .{merchant.getName()});

    if (payments.len == 0) {
        std.debug.print("  No payments yet.\n\n", .{});
        return;
    }

    std.debug.print("  {s:<22} {s:<10} {s:<10} {s:<12} {s}\n", .{ "Payment ID", "Amount", "Currency", "Status", "Description" });
    std.debug.print("  ──────────────────────────────────────────────────────────────\n", .{});

    for (payments) |p| {
        const whole = p.amount / 100;
        const frac = p.amount % 100;
        var amt_buf: [20]u8 = undefined;
        const amt_str = std.fmt.bufPrint(&amt_buf, "{d}.{d:0>2}", .{ whole, frac }) catch "?";

        std.debug.print("  {s:<22} {s:<10} {s:<10} {s:<12} {s}\n", .{
            p.getId(),
            amt_str,
            p.currency.symbol(),
            p.status.toString(),
            p.getDescription(),
        });
    }
    std.debug.print("  ──────────────────────────────────────────────────────────────\n", .{});
    std.debug.print("  Total: {d} payments\n\n", .{payments.len});
}

fn cmdMerchantList(allocator: std.mem.Allocator) !void {
    const mgr = merchant_mod.MerchantManager.init(allocator);
    const ids = mgr.listMerchants() catch {
        std.debug.print("\n  No merchants found.\n", .{});
        return;
    };
    defer {
        for (ids) |id| allocator.free(id);
        allocator.free(ids);
    }

    if (ids.len == 0) {
        std.debug.print("\n  No merchants. Register with: bsv-pay merchant register\n", .{});
        return;
    }

    std.debug.print("\n  Registered Merchants:\n  ────────────────────────────────────────\n", .{});
    for (ids, 1..) |id, i| {
        // Try loading to get name
        if (mgr.loadMerchant(id)) |m| {
            std.debug.print("  {d}. {s} (ID: {s})\n", .{ i, m.getName(), id });
        } else |_| {
            std.debug.print("  {d}. {s}\n", .{ i, id });
        }
    }
    std.debug.print("  ────────────────────────────────────────\n\n", .{});
}

test "main module compiles" {
    try std.testing.expect(true);
}
