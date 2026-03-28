const std = @import("std");
const hash = @import("../crypto/hash.zig");

// Bitcoin Script Opcodes
pub const OP_DUP: u8 = 0x76;
pub const OP_HASH160: u8 = 0xA9;
pub const OP_EQUALVERIFY: u8 = 0x88;
pub const OP_CHECKSIG: u8 = 0xAC;
pub const OP_RETURN: u8 = 0x6A;
pub const OP_FALSE: u8 = 0x00;
pub const OP_PUSH20: u8 = 0x14; // Push 20 bytes

/// Create P2PKH locking script: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
pub fn p2pkh_locking_script(pub_key_hash: [20]u8) [25]u8 {
    var script: [25]u8 = undefined;
    script[0] = OP_DUP;
    script[1] = OP_HASH160;
    script[2] = OP_PUSH20;
    @memcpy(script[3..23], &pub_key_hash);
    script[23] = OP_EQUALVERIFY;
    script[24] = OP_CHECKSIG;
    return script;
}

/// Create P2PKH locking script from an address's public key
pub fn p2pkh_from_pubkey(pub_key: []const u8) [25]u8 {
    const pub_key_hash = hash.hash160(pub_key);
    return p2pkh_locking_script(pub_key_hash);
}

/// Create P2PKH unlocking script: <sig> <pubkey>
pub fn p2pkh_unlocking_script(signature: []const u8, pub_key: []const u8, allocator: std.mem.Allocator) ![]u8 {
    // [siglen][sig][pubkeylen][pubkey]
    const total_len = 1 + signature.len + 1 + pub_key.len;
    var script = try allocator.alloc(u8, total_len);

    var offset: usize = 0;
    script[offset] = @intCast(signature.len);
    offset += 1;
    @memcpy(script[offset .. offset + signature.len], signature);
    offset += signature.len;
    script[offset] = @intCast(pub_key.len);
    offset += 1;
    @memcpy(script[offset .. offset + pub_key.len], pub_key);

    return script;
}

/// Create OP_RETURN data output script (for embedding data on-chain)
pub fn op_return_script(data: []const u8, allocator: std.mem.Allocator) ![]u8 {
    if (data.len <= 75) {
        var script = try allocator.alloc(u8, 2 + data.len);
        script[0] = OP_FALSE;
        script[1] = OP_RETURN;
        @memcpy(script[2..], data);
        return script;
    }

    // OP_PUSHDATA1 for data > 75 bytes
    var script = try allocator.alloc(u8, 4 + data.len);
    script[0] = OP_FALSE;
    script[1] = OP_RETURN;
    script[2] = 0x4C; // OP_PUSHDATA1
    script[3] = @intCast(data.len);
    @memcpy(script[4..], data);
    return script;
}

test "p2pkh locking script" {
    const pub_key_hash = [_]u8{0} ** 20;
    const script = p2pkh_locking_script(pub_key_hash);
    try std.testing.expectEqual(@as(u8, OP_DUP), script[0]);
    try std.testing.expectEqual(@as(u8, OP_HASH160), script[1]);
    try std.testing.expectEqual(@as(u8, OP_PUSH20), script[2]);
    try std.testing.expectEqual(@as(u8, OP_EQUALVERIFY), script[23]);
    try std.testing.expectEqual(@as(u8, OP_CHECKSIG), script[24]);
}
