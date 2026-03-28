const std = @import("std");
const wordlist = @import("wordlist.zig");
const hash_mod = @import("../crypto/hash.zig");

/// Generate a 12-word BIP39 mnemonic phrase
pub fn generateMnemonic() [12][]const u8 {
    // 128 bits of entropy → 12 words
    var entropy: [16]u8 = undefined;
    std.crypto.random.bytes(&entropy);
    return entropyToMnemonic(&entropy);
}

/// Convert 128-bit entropy to 12-word mnemonic
pub fn entropyToMnemonic(entropy: *const [16]u8) [12][]const u8 {
    // Checksum: first 4 bits of SHA256(entropy)
    const checksum = hash_mod.sha256(entropy);
    const checksum_bits: u4 = @intCast(checksum[0] >> 4);

    // Convert entropy (128 bits) + checksum (4 bits) = 132 bits → 12 words (11 bits each)
    var words: [12][]const u8 = undefined;

    // Build a bit stream from entropy + checksum
    var bit_buffer: u32 = 0;
    var bits_in_buffer: u5 = 0;
    var byte_idx: usize = 0;
    var word_idx: usize = 0;

    while (word_idx < 12) {
        // Fill buffer with bits from entropy
        while (bits_in_buffer < 11) {
            if (byte_idx < 16) {
                bit_buffer = (bit_buffer << 8) | @as(u32, entropy[byte_idx]);
                bits_in_buffer += 8;
                byte_idx += 1;
            } else {
                // Append checksum bits
                bit_buffer = (bit_buffer << 4) | @as(u32, checksum_bits);
                bits_in_buffer += 4;
            }
        }

        // Extract 11 bits for word index
        const shift: u5 = @intCast(bits_in_buffer - 11);
        const index: u11 = @intCast((bit_buffer >> shift) & 0x7FF);
        words[word_idx] = wordlist.WORDLIST[index];
        word_idx += 1;

        // Remove used bits
        bits_in_buffer -= 11;
        bit_buffer &= (@as(u32, 1) << shift) - 1;
    }

    return words;
}

/// Convert mnemonic words to a string (space-separated)
pub fn mnemonicToString(words: [12][]const u8, allocator: std.mem.Allocator) ![]u8 {
    var total_len: usize = 0;
    for (words, 0..) |word, i| {
        total_len += word.len;
        if (i < 11) total_len += 1; // space
    }

    var result = try allocator.alloc(u8, total_len);
    var offset: usize = 0;
    for (words, 0..) |word, i| {
        @memcpy(result[offset .. offset + word.len], word);
        offset += word.len;
        if (i < 11) {
            result[offset] = ' ';
            offset += 1;
        }
    }

    return result;
}

/// Parse a mnemonic string back to 12 words
pub fn parseMnemonic(mnemonic_str: []const u8) ![12][]const u8 {
    var words: [12][]const u8 = undefined;
    var word_idx: usize = 0;
    var start: usize = 0;

    for (mnemonic_str, 0..) |c, i| {
        if (c == ' ' or i == mnemonic_str.len - 1) {
            const end = if (c == ' ') i else i + 1;
            if (word_idx >= 12) return error.TooManyWords;
            words[word_idx] = mnemonic_str[start..end];
            word_idx += 1;
            start = i + 1;
        }
    }

    if (word_idx != 12) return error.InvalidMnemonicLength;

    // Validate each word exists in wordlist
    for (words) |word| {
        if (!isValidWord(word)) return error.InvalidWord;
    }

    return words;
}

/// Check if a word is in the BIP39 wordlist
fn isValidWord(word: []const u8) bool {
    for (wordlist.WORDLIST) |w| {
        if (std.mem.eql(u8, word, w)) return true;
    }
    return false;
}

/// Derive seed from mnemonic using PBKDF2-HMAC-SHA512 (BIP39)
/// passphrase is optional (for extra protection)
pub fn mnemonicToSeed(words: [12][]const u8, passphrase: []const u8, allocator: std.mem.Allocator) ![64]u8 {
    // Construct mnemonic string
    const mnemonic_str = try mnemonicToString(words, allocator);
    defer allocator.free(mnemonic_str);

    // Salt = "mnemonic" + passphrase
    const prefix = "mnemonic";
    var salt = try allocator.alloc(u8, prefix.len + passphrase.len);
    defer allocator.free(salt);
    @memcpy(salt[0..prefix.len], prefix);
    @memcpy(salt[prefix.len..], passphrase);

    // PBKDF2-HMAC-SHA512 with 2048 iterations
    var seed: [64]u8 = undefined;
    try std.crypto.pwhash.pbkdf2(&seed, mnemonic_str, salt, 2048, std.crypto.auth.hmac.sha2.HmacSha512);
    return seed;
}

test "mnemonic generation" {
    const words = generateMnemonic();
    // Should have 12 words
    try std.testing.expectEqual(@as(usize, 12), words.len);
    // Each word should be in the wordlist
    for (words) |word| {
        try std.testing.expect(word.len > 0);
    }
}

test "mnemonic to string" {
    const words = generateMnemonic();
    const str = try mnemonicToString(words, std.testing.allocator);
    defer std.testing.allocator.free(str);
    // Count spaces
    var spaces: usize = 0;
    for (str) |c| {
        if (c == ' ') spaces += 1;
    }
    try std.testing.expectEqual(@as(usize, 11), spaces);
}
