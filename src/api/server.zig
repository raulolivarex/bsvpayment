const std = @import("std");
const merchant_mod = @import("merchant.zig");
const payments_mod = @import("payments.zig");
const checkout_mod = @import("checkout.zig");
const exchange_mod = @import("../exchange/rates.zig");
const account_mod = @import("../account/account.zig");

/// HTTP API Server — Stripe-compatible REST API over BSV
pub const ApiServer = struct {
    allocator: std.mem.Allocator,
    port: u16,

    pub fn init(allocator: std.mem.Allocator, port: u16) ApiServer {
        return .{ .allocator = allocator, .port = port };
    }

    pub fn start(self: ApiServer) !void {
        const address = std.net.Address.parseIp("0.0.0.0", self.port) catch unreachable;
        var server = try address.listen(.{ .reuse_address = true });

        std.debug.print(
            \\
            \\  ╔══════════════════════════════════════╗
            \\  ║         BSVPay API Server             ║
            \\  ║    Stripe-compatible REST API         ║
            \\  ╚══════════════════════════════════════╝
            \\
            \\  Listening on http://localhost:{d}
            \\
            \\  Endpoints:
            \\    POST /v1/payments             Create payment
            \\    GET  /v1/payments/:id          Get payment
            \\    POST /v1/payments/:id/confirm  Confirm payment
            \\    POST /v1/refunds               Refund payment
            \\    GET  /v1/balance               Merchant balance
            \\    GET  /v1/checkout/:id           Checkout page
            \\
            \\  Auth: Bearer sk_live_xxx
            \\  Press Ctrl+C to stop.
            \\
        , .{self.port});

        while (true) {
            const conn = server.accept() catch continue;
            self.handleConnection(conn) catch |err| {
                std.debug.print("  Request error: {}\n", .{err});
            };
        }
    }

    fn handleConnection(self: ApiServer, conn: std.net.Server.Connection) !void {
        defer conn.stream.close();

        // Read request
        var buf: [8192]u8 = undefined;
        const n = conn.stream.read(&buf) catch return;
        if (n == 0) return;
        const request = buf[0..n];

        // Parse method and path
        const method_end = std.mem.indexOf(u8, request, " ") orelse return;
        const method = request[0..method_end];

        const path_start = method_end + 1;
        const path_end = std.mem.indexOfPos(u8, request, path_start, " ") orelse return;
        const path = request[path_start..path_end];

        // Extract Authorization header
        const auth_key = extractHeader(request, "Authorization: Bearer ");

        // Find request body (after \r\n\r\n)
        const body = if (std.mem.indexOf(u8, request, "\r\n\r\n")) |pos| request[pos + 4 ..] else "";

        // Log request
        std.debug.print("  {s} {s}\n", .{ method, path });

        // Route request
        if (std.mem.eql(u8, method, "POST") and std.mem.eql(u8, path, "/v1/payments")) {
            try self.handleCreatePayment(conn.stream, auth_key, body);
        } else if (std.mem.eql(u8, method, "GET") and std.mem.startsWith(u8, path, "/v1/payments/")) {
            const id = path[13..];
            if (std.mem.endsWith(u8, id, "/confirm")) {
                // GET confirm shouldn't happen, but handle gracefully
                try sendJsonResponse(conn.stream, 405, "{\"error\":\"Use POST to confirm\"}");
            } else {
                try self.handleGetPayment(conn.stream, auth_key, id);
            }
        } else if (std.mem.eql(u8, method, "POST") and std.mem.startsWith(u8, path, "/v1/payments/") and std.mem.endsWith(u8, path, "/confirm")) {
            const id = path[13 .. path.len - 8]; // strip /confirm
            try self.handleConfirmPayment(conn.stream, id);
        } else if (std.mem.eql(u8, method, "POST") and std.mem.eql(u8, path, "/v1/refunds")) {
            try self.handleRefund(conn.stream, auth_key, body);
        } else if (std.mem.eql(u8, method, "GET") and std.mem.eql(u8, path, "/v1/balance")) {
            try self.handleGetBalance(conn.stream, auth_key);
        } else if (std.mem.eql(u8, method, "GET") and std.mem.startsWith(u8, path, "/v1/checkout/")) {
            const id = path[13..];
            try self.handleCheckout(conn.stream, id);
        } else if (std.mem.eql(u8, method, "GET") and std.mem.eql(u8, path, "/")) {
            try sendJsonResponse(conn.stream, 200,
                \\{"name":"BSVPay API","version":"0.4.0","description":"Stripe-compatible payment API powered by BSV"}
            );
        } else {
            try sendJsonResponse(conn.stream, 404, "{\"error\":\"Not found\"}");
        }
    }

    /// POST /v1/payments — Create a new payment
    fn handleCreatePayment(self: ApiServer, stream: std.net.Stream, auth_key: ?[]const u8, body: []const u8) !void {
        const key = auth_key orelse {
            try sendJsonResponse(stream, 401, "{\"error\":\"Missing API key. Use Authorization: Bearer sk_live_xxx\"}");
            return;
        };

        const mmgr = merchant_mod.MerchantManager.init(self.allocator);
        const merchant = mmgr.findBySecretKey(key) catch {
            try sendJsonResponse(stream, 401, "{\"error\":\"Invalid API key\"}");
            return;
        };

        // Parse body: {"amount":1000,"currency":"USD","description":"..."}
        const amount = findJsonInt(body, "\"amount\":") orelse {
            try sendJsonResponse(stream, 400, "{\"error\":\"Missing amount\"}");
            return;
        };

        const currency_str = findJsonString(body, "\"currency\":\"") orelse "USD";
        const currency: account_mod.Currency = if (std.ascii.eqlIgnoreCase(currency_str, "EUR"))
            .EUR
        else if (std.ascii.eqlIgnoreCase(currency_str, "BSV"))
            .BSV
        else
            .USD;

        const description = findJsonString(body, "\"description\":\"") orelse "";
        const metadata = findJsonString(body, "\"metadata\":\"") orelse "";

        // Fetch exchange rates
        const rates = exchange_mod.ExchangeRates.fetchLive(self.allocator) catch
            exchange_mod.ExchangeRates{ .bsv_usd = 50.0, .bsv_eur = 46.0, .timestamp = std.time.timestamp() };

        const engine = payments_mod.PaymentEngine.init(self.allocator);
        const payment = engine.createPayment(&merchant, .{
            .amount = amount,
            .currency = currency,
            .description = description,
            .customer_email = "",
            .metadata = metadata,
        }, rates) catch {
            try sendJsonResponse(stream, 500, "{\"error\":\"Failed to create payment\"}");
            return;
        };

        // Build JSON response
        const json = std.fmt.allocPrint(self.allocator,
            \\{{"id":"{s}","amount":{d},"currency":"{s}","status":"{s}","bsv_satoshis":{d},"checkout_url":"http://localhost:{d}/v1/checkout/{s}"}}
        , .{
            payment.getId(),
            payment.amount,
            payment.currency.symbol(),
            payment.status.toString(),
            payment.bsv_satoshis,
            self.port,
            payment.getId(),
        }) catch {
            try sendJsonResponse(stream, 500, "{\"error\":\"Internal error\"}");
            return;
        };
        defer self.allocator.free(json);

        try sendJsonResponse(stream, 200, json);
    }

    /// GET /v1/payments/:id
    fn handleGetPayment(self: ApiServer, stream: std.net.Stream, auth_key: ?[]const u8, payment_id: []const u8) !void {
        _ = auth_key;
        const engine = payments_mod.PaymentEngine.init(self.allocator);
        const payment = engine.loadPayment(payment_id) catch {
            try sendJsonResponse(stream, 404, "{\"error\":\"Payment not found\"}");
            return;
        };

        const fee = payments_mod.calculateFee(payment.amount);
        const net = payments_mod.netAmount(payment.amount);

        const json = std.fmt.allocPrint(self.allocator,
            \\{{"id":"{s}","amount":{d},"currency":"{s}","status":"{s}","bsv_satoshis":{d},"fee":{d},"net_amount":{d},"refunded_amount":{d},"description":"{s}"}}
        , .{
            payment.getId(),
            payment.amount,
            payment.currency.symbol(),
            payment.status.toString(),
            payment.bsv_satoshis,
            fee,
            net,
            payment.refunded_amount,
            payment.getDescription(),
        }) catch {
            try sendJsonResponse(stream, 500, "{\"error\":\"Internal error\"}");
            return;
        };
        defer self.allocator.free(json);

        try sendJsonResponse(stream, 200, json);
    }

    /// POST /v1/payments/:id/confirm
    fn handleConfirmPayment(self: ApiServer, stream: std.net.Stream, payment_id: []const u8) !void {
        const engine = payments_mod.PaymentEngine.init(self.allocator);
        const payment = engine.confirmPayment(payment_id) catch |err| {
            if (err == error.PaymentNotPending) {
                try sendJsonResponse(stream, 400, "{\"error\":\"Payment already processed\"}");
            } else if (err == error.PaymentNotFound) {
                try sendJsonResponse(stream, 404, "{\"error\":\"Payment not found\"}");
            } else {
                try sendJsonResponse(stream, 500, "{\"error\":\"Confirmation failed\"}");
            }
            return;
        };

        const json = std.fmt.allocPrint(self.allocator,
            \\{{"id":"{s}","status":"{s}","amount":{d},"currency":"{s}","bsv_satoshis":{d},"confirmed":true}}
        , .{
            payment.getId(),
            payment.status.toString(),
            payment.amount,
            payment.currency.symbol(),
            payment.bsv_satoshis,
        }) catch {
            try sendJsonResponse(stream, 500, "{\"error\":\"Internal error\"}");
            return;
        };
        defer self.allocator.free(json);

        std.debug.print("    Payment {s} confirmed: {d} {s}\n", .{
            payment.getId(),
            payment.amount,
            payment.currency.symbol(),
        });

        try sendJsonResponse(stream, 200, json);
    }

    /// POST /v1/refunds
    fn handleRefund(self: ApiServer, stream: std.net.Stream, auth_key: ?[]const u8, body: []const u8) !void {
        const key = auth_key orelse {
            try sendJsonResponse(stream, 401, "{\"error\":\"Missing API key\"}");
            return;
        };

        const mmgr = merchant_mod.MerchantManager.init(self.allocator);
        _ = mmgr.findBySecretKey(key) catch {
            try sendJsonResponse(stream, 401, "{\"error\":\"Invalid API key\"}");
            return;
        };

        const payment_id = findJsonString(body, "\"payment_id\":\"") orelse {
            try sendJsonResponse(stream, 400, "{\"error\":\"Missing payment_id\"}");
            return;
        };
        const refund_amount = findJsonInt(body, "\"amount\":");

        const engine = payments_mod.PaymentEngine.init(self.allocator);
        const payment = engine.refundPayment(payment_id, refund_amount) catch |err| {
            if (err == error.PaymentNotRefundable) {
                try sendJsonResponse(stream, 400, "{\"error\":\"Payment not refundable\"}");
            } else if (err == error.RefundExceedsPayment) {
                try sendJsonResponse(stream, 400, "{\"error\":\"Refund exceeds payment amount\"}");
            } else {
                try sendJsonResponse(stream, 500, "{\"error\":\"Refund failed\"}");
            }
            return;
        };

        const json = std.fmt.allocPrint(self.allocator,
            \\{{"id":"{s}","status":"{s}","refunded_amount":{d},"amount":{d}}}
        , .{
            payment.getId(),
            payment.status.toString(),
            payment.refunded_amount,
            payment.amount,
        }) catch {
            try sendJsonResponse(stream, 500, "{\"error\":\"Internal error\"}");
            return;
        };
        defer self.allocator.free(json);

        try sendJsonResponse(stream, 200, json);
    }

    /// GET /v1/balance
    fn handleGetBalance(self: ApiServer, stream: std.net.Stream, auth_key: ?[]const u8) !void {
        const key = auth_key orelse {
            try sendJsonResponse(stream, 401, "{\"error\":\"Missing API key\"}");
            return;
        };

        const mmgr = merchant_mod.MerchantManager.init(self.allocator);
        const merchant = mmgr.findBySecretKey(key) catch {
            try sendJsonResponse(stream, 401, "{\"error\":\"Invalid API key\"}");
            return;
        };

        const json = std.fmt.allocPrint(self.allocator,
            \\{{"balance":{{"bsv":{d},"usd":{d},"eur":{d}}},"merchant":"{s}","total_payments":{d}}}
        , .{
            merchant.balance_bsv,
            merchant.balance_usd,
            merchant.balance_eur,
            merchant.getName(),
            merchant.total_payments,
        }) catch {
            try sendJsonResponse(stream, 500, "{\"error\":\"Internal error\"}");
            return;
        };
        defer self.allocator.free(json);

        try sendJsonResponse(stream, 200, json);
    }

    /// GET /v1/checkout/:id — Serve checkout HTML page
    fn handleCheckout(self: ApiServer, stream: std.net.Stream, payment_id: []const u8) !void {
        const engine = payments_mod.PaymentEngine.init(self.allocator);
        const payment = engine.loadPayment(payment_id) catch {
            try sendHtmlResponse(stream, 404, "<h1>Payment not found</h1>");
            return;
        };

        const html = checkout_mod.generateCheckoutPage(&payment, self.allocator) catch {
            try sendHtmlResponse(stream, 500, "<h1>Error generating checkout</h1>");
            return;
        };
        defer self.allocator.free(html);

        try sendHtmlResponse(stream, 200, html);
    }
};

fn sendJsonResponse(stream: std.net.Stream, status_code: u16, body: []const u8) !void {
    const status_text = switch (status_code) {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        else => "Unknown",
    };

    var hdr_buf: [512]u8 = undefined;
    const header = std.fmt.bufPrint(&hdr_buf,
        "HTTP/1.1 {d} {s}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n",
        .{ status_code, status_text, body.len },
    ) catch return;

    _ = stream.write(header) catch return;
    _ = stream.write(body) catch return;
}

fn sendHtmlResponse(stream: std.net.Stream, status_code: u16, body: []const u8) !void {
    const status_text = switch (status_code) {
        200 => "OK",
        404 => "Not Found",
        500 => "Internal Server Error",
        else => "Unknown",
    };

    var hdr_buf: [512]u8 = undefined;
    const header = std.fmt.bufPrint(&hdr_buf,
        "HTTP/1.1 {d} {s}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n",
        .{ status_code, status_text, body.len },
    ) catch return;

    _ = stream.write(header) catch return;
    _ = stream.write(body) catch return;
}

fn extractHeader(request: []const u8, header_name: []const u8) ?[]const u8 {
    const idx = std.mem.indexOf(u8, request, header_name) orelse return null;
    const start = idx + header_name.len;
    const end = std.mem.indexOfPos(u8, request, start, "\r\n") orelse request.len;
    const value = request[start..end];
    if (value.len == 0) return null;
    return value;
}

fn findJsonInt(json: []const u8, key: []const u8) ?u64 {
    const idx = std.mem.indexOf(u8, json, key) orelse return null;
    const start = idx + key.len;
    var end = start;
    while (end < json.len and json[end] >= '0' and json[end] <= '9') : (end += 1) {}
    if (end == start) return null;
    return std.fmt.parseInt(u64, json[start..end], 10) catch null;
}

fn findJsonString(json: []const u8, key: []const u8) ?[]const u8 {
    const idx = std.mem.indexOf(u8, json, key) orelse return null;
    const start = idx + key.len;
    const end = std.mem.indexOfPos(u8, json, start, "\"") orelse return null;
    return json[start..end];
}

test "extract header" {
    const req = "GET / HTTP/1.1\r\nAuthorization: Bearer sk_live_abc123\r\nHost: localhost\r\n\r\n";
    const val = extractHeader(req, "Authorization: Bearer ");
    try std.testing.expect(val != null);
    try std.testing.expectEqualStrings("sk_live_abc123", val.?);
}

test "find json int" {
    const json = "{\"amount\":1000,\"currency\":\"USD\"}";
    try std.testing.expectEqual(@as(?u64, 1000), findJsonInt(json, "\"amount\":"));
}

test "find json string" {
    const json = "{\"currency\":\"EUR\",\"desc\":\"test\"}";
    const val = findJsonString(json, "\"currency\":\"");
    try std.testing.expect(val != null);
    try std.testing.expectEqualStrings("EUR", val.?);
}
