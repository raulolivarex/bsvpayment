const std = @import("std");
const keypair_mod = @import("../keys/keypair.zig");
const tx_mod = @import("../tx/transaction.zig");
const hash_mod = @import("../crypto/hash.zig");
const broadcast_mod = @import("../net/broadcast.zig");
const script_mod = @import("../tx/script.zig");

pub const UTXO = struct {
    txid: [32]u8,
    vout: u32,
    value: u64,
    script_pubkey: [25]u8,
};

pub const Wallet = struct {
    key_pair: keypair_mod.KeyPair,
    network: broadcast_mod.Network,
    allocator: std.mem.Allocator,
    utxos: std.ArrayList(UTXO) = .{},

    pub fn init(allocator: std.mem.Allocator, network: broadcast_mod.Network) !Wallet {
        const kp = try keypair_mod.KeyPair.generate();
        return Wallet{
            .key_pair = kp,
            .network = network,
            .allocator = allocator,
        };
    }

    pub fn fromPrivateKey(private_key: [32]u8, allocator: std.mem.Allocator, network: broadcast_mod.Network) !Wallet {
        const kp = try keypair_mod.KeyPair.fromPrivateKey(private_key);
        return Wallet{
            .key_pair = kp,
            .network = network,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Wallet) void {
        self.utxos.deinit(self.allocator);
    }

    pub fn getBalance(self: *const Wallet) u64 {
        var total: u64 = 0;
        for (self.utxos.items) |utxo| {
            total += utxo.value;
        }
        return total;
    }

    pub fn getAddress(self: *const Wallet) ![]u8 {
        return self.key_pair.getAddress(self.allocator);
    }

    pub fn getWIF(self: *const Wallet) ![]u8 {
        return self.key_pair.toWIF(self.allocator);
    }

    pub fn addUtxo(self: *Wallet, txid: [32]u8, vout: u32, value: u64) !void {
        const pub_key_hash = hash_mod.hash160(&self.key_pair.public_key);
        const s = script_mod.p2pkh_locking_script(pub_key_hash);
        try self.utxos.append(self.allocator, UTXO{
            .txid = txid,
            .vout = vout,
            .value = value,
            .script_pubkey = s,
        });
    }

    pub fn createPayment(
        self: *Wallet,
        recipient_pubkey_hash: [20]u8,
        amount: u64,
        fee_rate: u64,
    ) ![]u8 {
        var tx = tx_mod.Transaction.init(self.allocator);

        var total_input: u64 = 0;
        for (self.utxos.items) |utxo| {
            try tx.addInput(utxo.txid, utxo.vout, utxo.value, &utxo.script_pubkey);
            total_input += utxo.value;
        }

        if (total_input < amount) return error.InsufficientFunds;

        try tx.addP2PKHOutput(recipient_pubkey_hash, amount);

        const estimated_fee = tx.calculateFee(fee_rate);

        if (total_input < amount + estimated_fee) return error.InsufficientFunds;

        const change = total_input - amount - estimated_fee;
        if (change > 546) {
            const self_pubkey_hash = hash_mod.hash160(&self.key_pair.public_key);
            try tx.addP2PKHOutput(self_pubkey_hash, change);
        }

        try tx.signAllInputs(self.key_pair.private_key);

        return tx.serialize(self.allocator);
    }

    pub fn send(
        self: *Wallet,
        recipient_pubkey_hash: [20]u8,
        amount: u64,
    ) !broadcast_mod.BroadcastResult {
        const raw_tx = try self.createPayment(recipient_pubkey_hash, amount, 1);
        defer self.allocator.free(raw_tx);

        const hex = try broadcast_mod.bytesToHex(raw_tx, self.allocator);
        defer self.allocator.free(hex);

        var client = broadcast_mod.WocClient.init(self.network, self.allocator);
        _ = &client;
        return client.broadcastTx(hex);
    }
};

test "wallet creation" {
    const allocator = std.testing.allocator;
    var wallet = try Wallet.init(allocator, .mainnet);
    defer wallet.deinit();

    try std.testing.expectEqual(@as(u64, 0), wallet.getBalance());

    const addr = try wallet.getAddress();
    defer allocator.free(addr);
    try std.testing.expect(addr[0] == '1');
}
