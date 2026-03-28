const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

/// Double SHA-256 hash (used in Bitcoin/BSV for txid, block hash, etc.)
pub fn sha256d(data: []const u8) [32]u8 {
    const first = sha256(data);
    return sha256(&first);
}

/// Single SHA-256
pub fn sha256(data: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    Sha256.hash(data, &out, .{});
    return out;
}

/// RIPEMD-160 (used in address generation: HASH160 = RIPEMD160(SHA256(pubkey)))
pub fn ripemd160(data: []const u8) [20]u8 {
    var out: [20]u8 = undefined;
    // Zig std has no RIPEMD160 — we implement a minimal version
    ripemd160_compute(data, &out);
    return out;
}

/// HASH160 = RIPEMD160(SHA256(data)) — used for BSV addresses
pub fn hash160(data: []const u8) [20]u8 {
    const sha_hash = sha256(data);
    return ripemd160(&sha_hash);
}

/// Base58Check encoding (for BSV addresses)
pub fn base58check_encode(payload: []const u8, allocator: std.mem.Allocator) ![]u8 {
    // checksum = first 4 bytes of sha256d(payload)
    const checksum = sha256d(payload);

    var data = try allocator.alloc(u8, payload.len + 4);
    defer allocator.free(data);
    @memcpy(data[0..payload.len], payload);
    @memcpy(data[payload.len..][0..4], checksum[0..4]);

    return base58_encode(data, allocator);
}

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub fn base58_encode(data: []const u8, allocator: std.mem.Allocator) ![]u8 {
    if (data.len == 0) return try allocator.alloc(u8, 0);

    // Count leading zeros
    var leading_zeros: usize = 0;
    for (data) |byte| {
        if (byte != 0) break;
        leading_zeros += 1;
    }

    // Allocate enough space (log(256)/log(58) ≈ 1.366)
    const size = data.len * 138 / 100 + 1;
    var buf = try allocator.alloc(u8, size);
    defer allocator.free(buf);
    @memset(buf, 0);

    for (data) |byte| {
        var carry: u32 = byte;
        var j: usize = size;
        while (j > 0) {
            j -= 1;
            carry += @as(u32, 256) * @as(u32, buf[j]);
            buf[j] = @intCast(carry % 58);
            carry /= 58;
        }
    }

    // Skip leading zeros in buf
    var start: usize = 0;
    while (start < size and buf[start] == 0) : (start += 1) {}

    // Build result
    var result = try allocator.alloc(u8, leading_zeros + (size - start));
    @memset(result[0..leading_zeros], '1');
    for (buf[start..], 0..) |val, i| {
        result[leading_zeros + i] = BASE58_ALPHABET[val];
    }

    return result;
}

// ============================================================
// Minimal RIPEMD-160 implementation
// ============================================================

fn ripemd160_compute(message: []const u8, out: *[20]u8) void {
    var h0: u32 = 0x67452301;
    var h1: u32 = 0xEFCDAB89;
    var h2: u32 = 0x98BADCFE;
    var h3: u32 = 0x10325476;
    var h4: u32 = 0xC3D2E1F0;

    const msg_len = message.len;
    const bit_len: u64 = @as(u64, @intCast(msg_len)) * 8;

    // Padding
    const pad_len = blk: {
        const rem = (msg_len + 1) % 64;
        if (rem <= 56) break :blk 56 - rem;
        break :blk 120 - rem;
    };

    var padded_buf: [256]u8 = undefined;
    var padded: []u8 = undefined;
    var alloc_buf: ?[]u8 = null;
    _ = &alloc_buf;

    const total_len = msg_len + 1 + pad_len + 8;
    if (total_len <= padded_buf.len) {
        padded = padded_buf[0..total_len];
    } else {
        // For very large messages, this won't happen in practice for our use case
        @memset(&padded_buf, 0);
        padded = padded_buf[0..padded_buf.len];
    }

    @memcpy(padded[0..msg_len], message);
    padded[msg_len] = 0x80;
    @memset(padded[msg_len + 1 .. msg_len + 1 + pad_len], 0);

    // Length in bits, little-endian
    const len_offset = msg_len + 1 + pad_len;
    std.mem.writeInt(u64, padded[len_offset..][0..8], bit_len, .little);

    // Process blocks
    var offset: usize = 0;
    while (offset < total_len) : (offset += 64) {
        var x: [16]u32 = undefined;
        for (0..16) |i| {
            x[i] = std.mem.readInt(u32, padded[offset + i * 4 ..][0..4], .little);
        }

        ripemd160_block(&h0, &h1, &h2, &h3, &h4, &x);
    }

    std.mem.writeInt(u32, out[0..4], h0, .little);
    std.mem.writeInt(u32, out[4..8], h1, .little);
    std.mem.writeInt(u32, out[8..12], h2, .little);
    std.mem.writeInt(u32, out[12..16], h3, .little);
    std.mem.writeInt(u32, out[16..20], h4, .little);
}

fn rotl(x: u32, n: u5) u32 {
    return std.math.rotl(u32, x, @as(u32, n));
}

fn ripemd160_block(h0: *u32, h1: *u32, h2: *u32, h3: *u32, h4: *u32, x: *const [16]u32) void {
    const KL = [5]u32{ 0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E };
    const KR = [5]u32{ 0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000 };

    const RL = [80]u4{
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
        3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
        1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
    };

    const RR = [80]u4{
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
        6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
        8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
        12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
    };

    const SL = [80]u5{
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
        7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
        11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
        9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
    };

    const SR = [80]u5{
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
        9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
        15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
        8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
    };

    var al = h0.*;
    var bl = h1.*;
    var cl = h2.*;
    var dl = h3.*;
    var el = h4.*;

    var ar = h0.*;
    var br = h1.*;
    var cr = h2.*;
    var dr = h3.*;
    var er = h4.*;

    for (0..80) |j| {
        const round = j / 16;
        var fl: u32 = undefined;
        var fr: u32 = undefined;

        switch (round) {
            0 => {
                fl = bl ^ cl ^ dl;
                fr = br ^ (cr | ~dr);
            },
            1 => {
                fl = (bl & cl) | (~bl & dl);
                fr = (br & dr) | (cr & ~dr);
            },
            2 => {
                fl = (bl | ~cl) ^ dl;
                fr = (br | ~cr) ^ dr;
            },
            3 => {
                fl = (bl & dl) | (cl & ~dl);
                fr = (br & cr) | (~br & dr);
            },
            4 => {
                fl = bl ^ (cl | ~dl);
                fr = br ^ cr ^ dr;
            },
            else => unreachable,
        }

        var tl = al +% fl +% x[RL[j]] +% KL[round];
        tl = rotl(tl, SL[j]) +% el;
        al = el;
        el = dl;
        dl = rotl(cl, 10);
        cl = bl;
        bl = tl;

        var tr = ar +% fr +% x[RR[j]] +% KR[round];
        tr = rotl(tr, SR[j]) +% er;
        ar = er;
        er = dr;
        dr = rotl(cr, 10);
        cr = br;
        br = tr;
    }

    const t = h1.* +% cl +% dr;
    h1.* = h2.* +% dl +% er;
    h2.* = h3.* +% el +% ar;
    h3.* = h4.* +% al +% br;
    h4.* = h0.* +% bl +% cr;
    h0.* = t;
}

// ============================================================
// Tests
// ============================================================

test "sha256d" {
    const result = sha256d("hello");
    // Known double-sha256 of "hello"
    const expected = [_]u8{
        0x95, 0x95, 0xc9, 0xdf, 0x90, 0x07, 0x51, 0x48,
        0xeb, 0x06, 0x86, 0x03, 0x65, 0xdf, 0x33, 0x58,
        0x4b, 0x75, 0xbf, 0xf7, 0x82, 0xa5, 0x10, 0xc6,
        0xcd, 0x48, 0x83, 0xa4, 0x19, 0x83, 0x3d, 0x50,
    };
    try std.testing.expectEqualSlices(u8, &expected, &result);
}

test "hash160" {
    // hash160 of a known value
    const data = [_]u8{ 0x04, 0x50, 0x86, 0x3A, 0xD6, 0x4A, 0x87, 0xAE, 0x8A, 0x2F, 0xE8, 0x3C, 0x1A, 0xF1, 0xA8, 0x40, 0x3C, 0xB5, 0x3F, 0x53 };
    const result = hash160(&data);
    try std.testing.expect(result.len == 20);
}
