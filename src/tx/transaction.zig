const std = @import("std");
const hash_mod = @import("../crypto/hash.zig");
const sighash_mod = @import("sighash.zig");
const script_mod = @import("script.zig");
const secp = @import("../crypto/secp256k1.zig");

pub const TxInput = struct {
    prev_txid: [32]u8,
    prev_vout: u32,
    script_sig: []const u8,
    sequence: u32 = 0xFFFFFFFF,
    prev_value: u64 = 0,
    prev_script_pubkey: []const u8 = &.{},
};

pub const TxOutput = struct {
    value: u64,
    script_pubkey: []const u8,
};

pub const Transaction = struct {
    version: u32 = 1,
    inputs: std.ArrayList(TxInput) = .{},
    outputs: std.ArrayList(TxOutput) = .{},
    locktime: u32 = 0,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Transaction {
        return Transaction{
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Transaction) void {
        for (self.inputs.items) |input| {
            if (input.script_sig.len > 0) {
                self.allocator.free(input.script_sig);
            }
        }
        self.inputs.deinit(self.allocator);
        self.outputs.deinit(self.allocator);
    }

    pub fn addInput(self: *Transaction, prev_txid: [32]u8, prev_vout: u32, prev_value: u64, prev_script_pubkey: []const u8) !void {
        try self.inputs.append(self.allocator, TxInput{
            .prev_txid = prev_txid,
            .prev_vout = prev_vout,
            .script_sig = &.{},
            .prev_value = prev_value,
            .prev_script_pubkey = prev_script_pubkey,
        });
    }

    pub fn addP2PKHOutput(self: *Transaction, pub_key_hash: [20]u8, value: u64) !void {
        const script = script_mod.p2pkh_locking_script(pub_key_hash);
        const script_copy = try self.allocator.alloc(u8, 25);
        @memcpy(script_copy, &script);
        try self.outputs.append(self.allocator, TxOutput{
            .value = value,
            .script_pubkey = script_copy,
        });
    }

    pub fn addDataOutput(self: *Transaction, data: []const u8) !void {
        const script = try script_mod.op_return_script(data, self.allocator);
        try self.outputs.append(self.allocator, TxOutput{
            .value = 0,
            .script_pubkey = script,
        });
    }

    pub fn signAllInputs(self: *Transaction, private_key: secp.PrivateKey) !void {
        const public_key = try secp.derivePublicKey(private_key);

        var outpoints = try self.allocator.alloc(sighash_mod.Outpoint, self.inputs.items.len);
        defer self.allocator.free(outpoints);
        var sequences = try self.allocator.alloc(u32, self.inputs.items.len);
        defer self.allocator.free(sequences);

        for (self.inputs.items, 0..) |input, i| {
            outpoints[i] = sighash_mod.Outpoint{
                .txid = input.prev_txid,
                .vout = input.prev_vout,
            };
            sequences[i] = input.sequence;
        }

        const hp = sighash_mod.hashPrevouts(outpoints);
        const hs = sighash_mod.hashSequences(sequences);

        var output_buf: [4096]u8 = undefined;
        var out_offset: usize = 0;
        for (self.outputs.items) |output| {
            std.mem.writeInt(u64, output_buf[out_offset..][0..8], output.value, .little);
            out_offset += 8;
            out_offset += sighash_mod.writeVarInt(output_buf[out_offset..], output.script_pubkey.len);
            @memcpy(output_buf[out_offset .. out_offset + output.script_pubkey.len], output.script_pubkey);
            out_offset += output.script_pubkey.len;
        }
        const ho = sighash_mod.hashOutputs(output_buf[0..out_offset]);

        for (self.inputs.items) |*input| {
            const sighash = sighash_mod.computeSighash(
                self.version,
                hp,
                hs,
                sighash_mod.Outpoint{ .txid = input.prev_txid, .vout = input.prev_vout },
                input.prev_script_pubkey,
                input.prev_value,
                input.sequence,
                ho,
                self.locktime,
                sighash_mod.SIGHASH_ALL_FORKID,
            );

            const sig = try secp.sign(sighash, private_key);

            var der_sig_buf: [73]u8 = undefined;
            const der_len = derEncode(&sig, &der_sig_buf);
            der_sig_buf[der_len] = @intCast(sighash_mod.SIGHASH_ALL_FORKID);

            const sig_with_hashtype = der_len + 1;
            const unlock_script = try script_mod.p2pkh_unlocking_script(
                der_sig_buf[0..sig_with_hashtype],
                &public_key,
                self.allocator,
            );

            if (input.script_sig.len > 0) {
                self.allocator.free(input.script_sig);
            }
            input.script_sig = unlock_script;
        }
    }

    pub fn serialize(self: *const Transaction, allocator: std.mem.Allocator) ![]u8 {
        var buf: std.ArrayList(u8) = .{};

        try buf.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToLittle(u32, self.version)));

        var varint_buf: [9]u8 = undefined;
        var vlen = sighash_mod.writeVarInt(&varint_buf, self.inputs.items.len);
        try buf.appendSlice(allocator, varint_buf[0..vlen]);

        for (self.inputs.items) |input| {
            try buf.appendSlice(allocator, &input.prev_txid);
            try buf.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToLittle(u32, input.prev_vout)));
            vlen = sighash_mod.writeVarInt(&varint_buf, input.script_sig.len);
            try buf.appendSlice(allocator, varint_buf[0..vlen]);
            try buf.appendSlice(allocator, input.script_sig);
            try buf.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToLittle(u32, input.sequence)));
        }

        vlen = sighash_mod.writeVarInt(&varint_buf, self.outputs.items.len);
        try buf.appendSlice(allocator, varint_buf[0..vlen]);

        for (self.outputs.items) |output| {
            try buf.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToLittle(u64, output.value)));
            vlen = sighash_mod.writeVarInt(&varint_buf, output.script_pubkey.len);
            try buf.appendSlice(allocator, varint_buf[0..vlen]);
            try buf.appendSlice(allocator, output.script_pubkey);
        }

        try buf.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToLittle(u32, self.locktime)));

        return buf.toOwnedSlice(allocator);
    }

    pub fn getTxid(self: *const Transaction, allocator: std.mem.Allocator) ![32]u8 {
        const raw = try self.serialize(allocator);
        defer allocator.free(raw);
        var txid = hash_mod.sha256d(raw);
        std.mem.reverse(u8, &txid);
        return txid;
    }

    pub fn estimateSize(self: *const Transaction) usize {
        var size: usize = 4 + 1 + 1 + 4;
        size += self.inputs.items.len * 148;
        size += self.outputs.items.len * 34;
        return size;
    }

    pub fn calculateFee(self: *const Transaction, sat_per_byte: u64) u64 {
        return @as(u64, @intCast(self.estimateSize())) * sat_per_byte;
    }
};

fn derEncode(sig: *const secp.Signature, out: *[73]u8) usize {
    var offset: usize = 0;
    out[offset] = 0x30;
    offset += 1;
    const len_pos = offset;
    offset += 1;

    out[offset] = 0x02;
    offset += 1;
    const r = sig[0..32];
    const r_pad: u8 = if (r[0] >= 0x80) 1 else 0;
    out[offset] = 32 + r_pad;
    offset += 1;
    if (r_pad == 1) {
        out[offset] = 0x00;
        offset += 1;
    }
    @memcpy(out[offset..][0..32], r);
    offset += 32;

    out[offset] = 0x02;
    offset += 1;
    const s = sig[32..64];
    const s_pad: u8 = if (s[0] >= 0x80) 1 else 0;
    out[offset] = 32 + s_pad;
    offset += 1;
    if (s_pad == 1) {
        out[offset] = 0x00;
        offset += 1;
    }
    @memcpy(out[offset..][0..32], s);
    offset += 32;

    out[len_pos] = @intCast(offset - 2);
    return offset;
}

test "transaction creation" {
    const allocator = std.testing.allocator;
    var tx = Transaction.init(allocator);
    defer tx.deinit();

    try tx.addInput([_]u8{0xAA} ** 32, 0, 100000, &script_mod.p2pkh_locking_script([_]u8{0} ** 20));
    try tx.addP2PKHOutput([_]u8{0xBB} ** 20, 90000);

    try std.testing.expectEqual(@as(usize, 1), tx.inputs.items.len);
    try std.testing.expectEqual(@as(usize, 1), tx.outputs.items.len);

    allocator.free(tx.outputs.items[0].script_pubkey);
    tx.outputs.items[0].script_pubkey = &.{};
}
