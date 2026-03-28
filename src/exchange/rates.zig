const std = @import("std");

/// BSV exchange rates against fiat currencies
pub const ExchangeRates = struct {
    bsv_usd: f64, // 1 BSV = X USD
    bsv_eur: f64, // 1 BSV = X EUR
    timestamp: i64,

    /// Fetch live BSV prices from CoinGecko API (no API key needed)
    pub fn fetchLive(allocator: std.mem.Allocator) !ExchangeRates {
        var client: std.http.Client = .{ .allocator = allocator };
        defer client.deinit();

        var aw: std.Io.Writer.Allocating = .init(allocator);
        defer aw.deinit();

        const url = "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin-cash-sv&vs_currencies=usd,eur";
        const result = try client.fetch(.{
            .location = .{ .url = url },
            .method = .GET,
            .response_writer = &aw.writer,
        });

        if (result.status != .ok) return error.RateFetchFailed;

        const body = aw.writer.buffer[0..aw.writer.end];
        // Response: {"bitcoin-cash-sv":{"usd":XX.XX,"eur":YY.YY}}
        const rates = try parseRatesJson(body);

        return ExchangeRates{
            .bsv_usd = rates.usd,
            .bsv_eur = rates.eur,
            .timestamp = std.time.timestamp(),
        };
    }

    /// Convert fiat cents to satoshis
    /// e.g., 1000 USD cents ($10.00) at BSV=$50 = 20_000_000 satoshis (0.2 BSV)
    pub fn fiatToSatoshis(self: ExchangeRates, currency: Currency, cents: u64) u64 {
        const fiat_amount: f64 = @as(f64, @floatFromInt(cents)) / 100.0;
        const bsv_price = switch (currency) {
            .USD => self.bsv_usd,
            .EUR => self.bsv_eur,
            .BSV => return cents, // already satoshis
        };
        if (bsv_price <= 0) return 0;
        const bsv_amount = fiat_amount / bsv_price;
        return @intFromFloat(bsv_amount * 100_000_000.0);
    }

    /// Convert satoshis to fiat cents
    /// e.g., 20_000_000 satoshis (0.2 BSV) at BSV=$50 = 1000 cents ($10.00)
    pub fn satoshisToFiat(self: ExchangeRates, currency: Currency, satoshis: u64) u64 {
        const bsv_amount: f64 = @as(f64, @floatFromInt(satoshis)) / 100_000_000.0;
        const bsv_price = switch (currency) {
            .USD => self.bsv_usd,
            .EUR => self.bsv_eur,
            .BSV => return satoshis,
        };
        const fiat_amount = bsv_amount * bsv_price;
        return @intFromFloat(fiat_amount * 100.0);
    }

    /// Format rate for display
    pub fn formatRate(self: ExchangeRates, currency: Currency, buf: []u8) []const u8 {
        const price = switch (currency) {
            .USD => self.bsv_usd,
            .EUR => self.bsv_eur,
            .BSV => return "1 BSV",
        };
        const whole: u64 = @intFromFloat(price);
        const frac: u64 = @intFromFloat((price - @as(f64, @floatFromInt(whole))) * 100.0);
        const sym = currency.symbol();
        return std.fmt.bufPrint(buf, "1 BSV = {s}{d}.{d:0>2}", .{ sym, whole, frac }) catch "?";
    }
};

const Currency = @import("../account/account.zig").Currency;

/// Parse CoinGecko JSON response
/// {"bitcoin-cash-sv":{"usd":XX.XX,"eur":YY.YY}}
fn parseRatesJson(json: []const u8) !struct { usd: f64, eur: f64 } {
    var usd: f64 = 0;
    var eur: f64 = 0;

    // Find "usd": and "eur": values
    if (findJsonNumber(json, "\"usd\":")) |v| {
        usd = v;
    } else return error.InvalidRateResponse;

    if (findJsonNumber(json, "\"eur\":")) |v| {
        eur = v;
    } else return error.InvalidRateResponse;

    return .{ .usd = usd, .eur = eur };
}

/// Find a number value after a key in JSON
fn findJsonNumber(json: []const u8, key: []const u8) ?f64 {
    const idx = std.mem.indexOf(u8, json, key) orelse return null;
    const start = idx + key.len;

    // Skip whitespace
    var pos = start;
    while (pos < json.len and (json[pos] == ' ' or json[pos] == '\t')) : (pos += 1) {}

    // Parse number
    var end = pos;
    var has_dot = false;
    while (end < json.len) : (end += 1) {
        const c = json[end];
        if (c == '.') {
            if (has_dot) break;
            has_dot = true;
        } else if (c < '0' or c > '9') {
            break;
        }
    }

    if (end == pos) return null;

    return parseFloat(json[pos..end]);
}

/// Simple float parser (no std.fmt.parseFloat in Zig 0.15 for runtime slices)
fn parseFloat(s: []const u8) ?f64 {
    var result: f64 = 0;
    var decimal_place: f64 = 0;
    var after_dot = false;

    for (s) |c| {
        if (c == '.') {
            after_dot = true;
            decimal_place = 10.0;
            continue;
        }
        if (c < '0' or c > '9') return null;
        const digit: f64 = @floatFromInt(c - '0');
        if (after_dot) {
            result += digit / decimal_place;
            decimal_place *= 10.0;
        } else {
            result = result * 10.0 + digit;
        }
    }

    return result;
}

test "fiat to satoshis conversion" {
    const rates = ExchangeRates{
        .bsv_usd = 50.0,
        .bsv_eur = 45.0,
        .timestamp = 0,
    };

    // $10.00 (1000 cents) at $50/BSV = 0.2 BSV = 20_000_000 sats
    const sats = rates.fiatToSatoshis(.USD, 1000);
    try std.testing.expectEqual(@as(u64, 20_000_000), sats);

    // €10.00 (1000 cents) at €45/BSV ≈ 0.2222 BSV ≈ 22_222_222 sats
    const eur_sats = rates.fiatToSatoshis(.EUR, 1000);
    try std.testing.expect(eur_sats > 22_000_000 and eur_sats < 22_500_000);
}

test "satoshis to fiat conversion" {
    const rates = ExchangeRates{
        .bsv_usd = 50.0,
        .bsv_eur = 45.0,
        .timestamp = 0,
    };

    // 20_000_000 sats = 0.2 BSV at $50 = $10.00 = 1000 cents
    const cents = rates.satoshisToFiat(.USD, 20_000_000);
    try std.testing.expectEqual(@as(u64, 1000), cents);
}

test "parse json rates" {
    const json = "{\"bitcoin-cash-sv\":{\"usd\":51.23,\"eur\":46.78}}";
    const rates = try parseRatesJson(json);
    try std.testing.expect(rates.usd > 51.0 and rates.usd < 52.0);
    try std.testing.expect(rates.eur > 46.0 and rates.eur < 47.0);
}

test "parse float" {
    const v = parseFloat("51.23") orelse unreachable;
    try std.testing.expect(v > 51.22 and v < 51.24);
}
