const std = @import("std");

pub const Network = enum {
    mainnet,
    testnet,
};

pub const BroadcastResult = struct {
    success: bool,
    txid: ?[]const u8 = null,
    error_message: ?[]const u8 = null,
};

pub const WocClient = struct {
    network: Network,
    allocator: std.mem.Allocator,

    pub fn init(network: Network, allocator: std.mem.Allocator) WocClient {
        return WocClient{
            .network = network,
            .allocator = allocator,
        };
    }

    fn getBaseUrl(self: WocClient) []const u8 {
        return switch (self.network) {
            .mainnet => "https://api.whatsonchain.com/v1/bsv/main",
            .testnet => "https://api.whatsonchain.com/v1/bsv/test",
        };
    }

    pub fn broadcastTx(self: WocClient, raw_tx_hex: []const u8) !BroadcastResult {
        const base_url = self.getBaseUrl();
        const url = try std.fmt.allocPrint(self.allocator, "{s}/tx/raw", .{base_url});
        defer self.allocator.free(url);

        const body = try std.fmt.allocPrint(self.allocator, "{{\"txhex\":\"{s}\"}}", .{raw_tx_hex});
        defer self.allocator.free(body);

        var client: std.http.Client = .{ .allocator = self.allocator };
        defer client.deinit();

        var aw: std.Io.Writer.Allocating = .init(self.allocator);
        defer aw.deinit();

        const result = try client.fetch(.{
            .location = .{ .url = url },
            .method = .POST,
            .payload = body,
            .extra_headers = &.{
                .{ .name = "Content-Type", .value = "application/json" },
            },
            .response_writer = &aw.writer,
        });

        if (result.status == .ok) {
            const data = aw.writer.buffer[0..aw.writer.end];
            const txid = try self.allocator.alloc(u8, data.len);
            @memcpy(txid, data);
            return BroadcastResult{
                .success = true,
                .txid = txid,
            };
        }

        return BroadcastResult{
            .success = false,
            .error_message = "Broadcast failed",
        };
    }

    pub fn getUtxos(self: WocClient, address: []const u8) ![]const u8 {
        const base_url = self.getBaseUrl();
        const url = try std.fmt.allocPrint(self.allocator, "{s}/address/{s}/unspent", .{ base_url, address });
        defer self.allocator.free(url);
        return self.httpGet(url);
    }

    pub fn getBalance(self: WocClient, address: []const u8) ![]const u8 {
        const base_url = self.getBaseUrl();
        const url = try std.fmt.allocPrint(self.allocator, "{s}/address/{s}/balance", .{ base_url, address });
        defer self.allocator.free(url);
        return self.httpGet(url);
    }

    fn httpGet(self: WocClient, url: []const u8) ![]const u8 {
        var client: std.http.Client = .{ .allocator = self.allocator };
        defer client.deinit();

        var aw: std.Io.Writer.Allocating = .init(self.allocator);
        defer aw.deinit();

        const result = try client.fetch(.{
            .location = .{ .url = url },
            .method = .GET,
            .response_writer = &aw.writer,
        });

        if (result.status == .ok) {
            const data = aw.writer.buffer[0..aw.writer.end];
            const out = try self.allocator.alloc(u8, data.len);
            @memcpy(out, data);
            return out;
        }

        return error.FetchFailed;
    }
};

pub fn bytesToHex(bytes: []const u8, allocator: std.mem.Allocator) ![]u8 {
    const hex_chars = "0123456789abcdef";
    var hex = try allocator.alloc(u8, bytes.len * 2);
    for (bytes, 0..) |byte, i| {
        hex[i * 2] = hex_chars[byte >> 4];
        hex[i * 2 + 1] = hex_chars[byte & 0x0F];
    }
    return hex;
}

test "bytes to hex" {
    const allocator = std.testing.allocator;
    const bytes = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const hex = try bytesToHex(&bytes, allocator);
    defer allocator.free(hex);
    try std.testing.expectEqualStrings("deadbeef", hex);
}
