const std = @import("std");
const hash_mod = @import("../crypto/hash.zig");

// BSV Sighash flags
pub const SIGHASH_ALL: u32 = 0x01;
pub const SIGHASH_NONE: u32 = 0x02;
pub const SIGHASH_SINGLE: u32 = 0x03;
pub const SIGHASH_FORKID: u32 = 0x40;
pub const SIGHASH_ANYONECANPAY: u32 = 0x80;

// BSV uses SIGHASH_FORKID for replay protection (BIP143-like)
pub const SIGHASH_ALL_FORKID: u32 = SIGHASH_ALL | SIGHASH_FORKID;

pub const Outpoint = struct {
    txid: [32]u8,
    vout: u32,
};

/// Compute BIP143 sighash for BSV (with FORKID)
/// This is what gets signed for each input
pub fn computeSighash(
    version: u32,
    hash_prevouts: [32]u8,
    hash_sequence: [32]u8,
    outpoint: Outpoint,
    script_code: []const u8,
    value: u64,
    sequence: u32,
    hash_outputs: [32]u8,
    locktime: u32,
    sighash_type: u32,
) [32]u8 {
    var buf: [512]u8 = undefined;
    var offset: usize = 0;

    // 1. nVersion (4 bytes LE)
    std.mem.writeInt(u32, buf[offset..][0..4], version, .little);
    offset += 4;

    // 2. hashPrevouts (32 bytes)
    @memcpy(buf[offset..][0..32], &hash_prevouts);
    offset += 32;

    // 3. hashSequence (32 bytes)
    @memcpy(buf[offset..][0..32], &hash_sequence);
    offset += 32;

    // 4. outpoint (32+4 bytes)
    @memcpy(buf[offset..][0..32], &outpoint.txid);
    offset += 32;
    std.mem.writeInt(u32, buf[offset..][0..4], outpoint.vout, .little);
    offset += 4;

    // 5. scriptCode (varint + script)
    offset += writeVarInt(buf[offset..], script_code.len);
    @memcpy(buf[offset .. offset + script_code.len], script_code);
    offset += script_code.len;

    // 6. value (8 bytes LE)
    std.mem.writeInt(u64, buf[offset..][0..8], value, .little);
    offset += 8;

    // 7. nSequence (4 bytes LE)
    std.mem.writeInt(u32, buf[offset..][0..4], sequence, .little);
    offset += 4;

    // 8. hashOutputs (32 bytes)
    @memcpy(buf[offset..][0..32], &hash_outputs);
    offset += 32;

    // 9. nLocktime (4 bytes LE)
    std.mem.writeInt(u32, buf[offset..][0..4], locktime, .little);
    offset += 4;

    // 10. sighashType (4 bytes LE) — includes FORKID
    std.mem.writeInt(u32, buf[offset..][0..4], sighash_type, .little);
    offset += 4;

    return hash_mod.sha256d(buf[0..offset]);
}

/// Hash all prevouts for BIP143
pub fn hashPrevouts(outpoints: []const Outpoint) [32]u8 {
    var buf: [4096]u8 = undefined;
    var offset: usize = 0;

    for (outpoints) |op| {
        @memcpy(buf[offset..][0..32], &op.txid);
        offset += 32;
        std.mem.writeInt(u32, buf[offset..][0..4], op.vout, .little);
        offset += 4;
    }

    return hash_mod.sha256d(buf[0..offset]);
}

/// Hash all sequences for BIP143
pub fn hashSequences(sequences: []const u32) [32]u8 {
    var buf: [1024]u8 = undefined;
    var offset: usize = 0;

    for (sequences) |seq| {
        std.mem.writeInt(u32, buf[offset..][0..4], seq, .little);
        offset += 4;
    }

    return hash_mod.sha256d(buf[0..offset]);
}

/// Hash all outputs for BIP143
pub fn hashOutputs(output_data: []const u8) [32]u8 {
    return hash_mod.sha256d(output_data);
}

pub fn writeVarInt(buf: []u8, value: usize) usize {
    if (value < 0xFD) {
        buf[0] = @intCast(value);
        return 1;
    } else if (value <= 0xFFFF) {
        buf[0] = 0xFD;
        std.mem.writeInt(u16, buf[1..3], @intCast(value), .little);
        return 3;
    } else if (value <= 0xFFFFFFFF) {
        buf[0] = 0xFE;
        std.mem.writeInt(u32, buf[1..5], @intCast(value), .little);
        return 5;
    } else {
        buf[0] = 0xFF;
        std.mem.writeInt(u64, buf[1..9], @intCast(value), .little);
        return 9;
    }
}

test "sighash type constants" {
    try std.testing.expectEqual(@as(u32, 0x41), SIGHASH_ALL_FORKID);
}
