const std = @import("std");
const account_mod = @import("../account/account.zig");
const exchange_mod = @import("../exchange/rates.zig");
const merchant_mod = @import("merchant.zig");

/// Payment status (like Stripe's payment intent states)
pub const PaymentStatus = enum {
    pending, // Created, awaiting confirmation
    processing, // Being processed on BSV
    succeeded, // Payment complete
    failed, // Payment failed
    refunded, // Fully refunded
    partially_refunded, // Partially refunded

    pub fn toString(self: PaymentStatus) []const u8 {
        return switch (self) {
            .pending => "pending",
            .processing => "processing",
            .succeeded => "succeeded",
            .failed => "failed",
            .refunded => "refunded",
            .partially_refunded => "partially_refunded",
        };
    }

    pub fn fromByte(b: u8) PaymentStatus {
        return switch (b) {
            0 => .pending,
            1 => .processing,
            2 => .succeeded,
            3 => .failed,
            4 => .refunded,
            5 => .partially_refunded,
            else => .failed,
        };
    }

    pub fn toByte(self: PaymentStatus) u8 {
        return switch (self) {
            .pending => 0,
            .processing => 1,
            .succeeded => 2,
            .failed => 3,
            .refunded => 4,
            .partially_refunded => 5,
        };
    }
};

/// Payment object (like Stripe's PaymentIntent)
pub const Payment = struct {
    id: [32]u8, // pay_xxx
    id_len: u8,
    merchant_id: [32]u8,
    merchant_id_len: u8,
    amount: u64, // in smallest currency unit (cents/satoshis)
    currency: account_mod.Currency,
    status: PaymentStatus,
    description: [128]u8,
    description_len: u8,
    customer_email: [64]u8,
    customer_email_len: u8,
    bsv_satoshis: u64, // BSV equivalent at time of creation
    bsv_txid: [64]u8, // on-chain txid (hex)
    bsv_txid_len: u8,
    exchange_rate: f64, // BSV price at creation
    refunded_amount: u64,
    created_at: i64,
    confirmed_at: i64,
    metadata: [128]u8, // merchant-defined metadata
    metadata_len: u8,

    pub fn getId(self: *const Payment) []const u8 {
        return self.id[0..self.id_len];
    }

    pub fn getMerchantId(self: *const Payment) []const u8 {
        return self.merchant_id[0..self.merchant_id_len];
    }

    pub fn getDescription(self: *const Payment) []const u8 {
        return self.description[0..self.description_len];
    }

    pub fn getCustomerEmail(self: *const Payment) []const u8 {
        return self.customer_email[0..self.customer_email_len];
    }

    pub fn getTxid(self: *const Payment) []const u8 {
        return self.bsv_txid[0..self.bsv_txid_len];
    }

    pub fn getMetadata(self: *const Payment) []const u8 {
        return self.metadata[0..self.metadata_len];
    }
};

/// Create payment request (like Stripe's POST /v1/payment_intents)
pub const CreatePaymentRequest = struct {
    amount: u64,
    currency: account_mod.Currency,
    description: []const u8,
    customer_email: []const u8,
    metadata: []const u8,
};

/// Payment engine — manages payment lifecycle
pub const PaymentEngine = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) PaymentEngine {
        return .{ .allocator = allocator };
    }

    fn getPaymentDir(self: PaymentEngine) ![]u8 {
        const home = std.process.getEnvVarOwned(self.allocator, "USERPROFILE") catch
            try std.process.getEnvVarOwned(self.allocator, "HOME");
        defer self.allocator.free(home);
        return std.fmt.allocPrint(self.allocator, "{s}/.bsv-pay/payments", .{home});
    }

    fn getPaymentPath(self: PaymentEngine, payment_id: []const u8) ![]u8 {
        const dir = try self.getPaymentDir();
        defer self.allocator.free(dir);
        return std.fmt.allocPrint(self.allocator, "{s}/{s}.pay", .{ dir, payment_id });
    }

    fn ensureDir(self: PaymentEngine) !void {
        const dir_path = try self.getPaymentDir();
        defer self.allocator.free(dir_path);

        std.fs.makeDirAbsolute(dir_path) catch |err| {
            if (err != error.PathAlreadyExists) {
                const home = std.process.getEnvVarOwned(self.allocator, "USERPROFILE") catch
                    try std.process.getEnvVarOwned(self.allocator, "HOME");
                defer self.allocator.free(home);
                const parent = try std.fmt.allocPrint(self.allocator, "{s}/.bsv-pay", .{home});
                defer self.allocator.free(parent);
                std.fs.makeDirAbsolute(parent) catch |e| {
                    if (e != error.PathAlreadyExists) return e;
                };
                std.fs.makeDirAbsolute(dir_path) catch |e2| {
                    if (e2 != error.PathAlreadyExists) return e2;
                };
            }
        };
    }

    /// Create a new payment (like Stripe's create PaymentIntent)
    pub fn createPayment(
        self: PaymentEngine,
        merchant: *const merchant_mod.Merchant,
        req: CreatePaymentRequest,
        rates: exchange_mod.ExchangeRates,
    ) !Payment {
        // Generate payment ID
        var id_bytes: [8]u8 = undefined;
        std.crypto.random.bytes(&id_bytes);
        var id_buf: [32]u8 = [_]u8{0} ** 32;
        const prefix = "pay_";
        @memcpy(id_buf[0..prefix.len], prefix);
        const id_hex = hexEncode16(&id_bytes);
        @memcpy(id_buf[prefix.len..][0..16], &id_hex);
        const total_len: u8 = prefix.len + 16;

        // Calculate BSV equivalent
        const satoshis = rates.fiatToSatoshis(req.currency, req.amount);
        const rate_price: f64 = switch (req.currency) {
            .USD => rates.bsv_usd,
            .EUR => rates.bsv_eur,
            .BSV => 1.0,
        };

        // Build payment
        var payment = Payment{
            .id = id_buf,
            .id_len = total_len,
            .merchant_id = merchant.id,
            .merchant_id_len = merchant.id_len,
            .amount = req.amount,
            .currency = req.currency,
            .status = .pending,
            .description = [_]u8{0} ** 128,
            .description_len = 0,
            .customer_email = [_]u8{0} ** 64,
            .customer_email_len = 0,
            .bsv_satoshis = satoshis,
            .bsv_txid = [_]u8{0} ** 64,
            .bsv_txid_len = 0,
            .exchange_rate = rate_price,
            .refunded_amount = 0,
            .created_at = std.time.timestamp(),
            .confirmed_at = 0,
            .metadata = [_]u8{0} ** 128,
            .metadata_len = 0,
        };

        // Copy description
        const dlen: u8 = @intCast(@min(req.description.len, 128));
        @memcpy(payment.description[0..dlen], req.description[0..dlen]);
        payment.description_len = dlen;

        // Copy customer email
        const elen: u8 = @intCast(@min(req.customer_email.len, 64));
        @memcpy(payment.customer_email[0..elen], req.customer_email[0..elen]);
        payment.customer_email_len = elen;

        // Copy metadata
        const mlen: u8 = @intCast(@min(req.metadata.len, 128));
        @memcpy(payment.metadata[0..mlen], req.metadata[0..mlen]);
        payment.metadata_len = mlen;

        try self.savePayment(&payment);
        return payment;
    }

    /// Confirm a payment (simulate customer completing payment)
    pub fn confirmPayment(self: PaymentEngine, payment_id: []const u8) !Payment {
        var payment = try self.loadPayment(payment_id);

        if (payment.status != .pending) return error.PaymentNotPending;

        payment.status = .succeeded;
        payment.confirmed_at = std.time.timestamp();

        // Credit merchant balance
        const mmgr = merchant_mod.MerchantManager.init(self.allocator);
        var merchant = try mmgr.loadMerchant(payment.getMerchantId());

        // Apply 2.9% + 30c fee (like Stripe), rest goes to merchant
        const fee = calculateFee(payment.amount);
        const net_amount = payment.amount - fee;

        switch (payment.currency) {
            .BSV => merchant.balance_bsv += @intCast(net_amount),
            .USD => merchant.balance_usd += @intCast(net_amount),
            .EUR => merchant.balance_eur += @intCast(net_amount),
        }
        merchant.total_payments += 1;
        merchant.total_volume_usd += @intCast(payment.amount);

        try mmgr.saveMerchant(&merchant);
        try self.savePayment(&payment);

        return payment;
    }

    /// Refund a payment
    pub fn refundPayment(self: PaymentEngine, payment_id: []const u8, amount: ?u64) !Payment {
        var payment = try self.loadPayment(payment_id);

        if (payment.status != .succeeded and payment.status != .partially_refunded) {
            return error.PaymentNotRefundable;
        }

        const refund_amount = amount orelse payment.amount - payment.refunded_amount;
        if (refund_amount > payment.amount - payment.refunded_amount) {
            return error.RefundExceedsPayment;
        }

        payment.refunded_amount += refund_amount;
        if (payment.refunded_amount >= payment.amount) {
            payment.status = .refunded;
        } else {
            payment.status = .partially_refunded;
        }

        // Debit merchant balance
        const mmgr = merchant_mod.MerchantManager.init(self.allocator);
        var merchant = mmgr.loadMerchant(payment.getMerchantId()) catch return error.MerchantNotFound;

        const neg: i64 = -@as(i64, @intCast(refund_amount));
        switch (payment.currency) {
            .BSV => merchant.balance_bsv += neg,
            .USD => merchant.balance_usd += neg,
            .EUR => merchant.balance_eur += neg,
        }

        try mmgr.saveMerchant(&merchant);
        try self.savePayment(&payment);

        return payment;
    }

    /// Load payment from disk
    pub fn loadPayment(self: PaymentEngine, payment_id: []const u8) !Payment {
        const path = try self.getPaymentPath(payment_id);
        defer self.allocator.free(path);

        const file = std.fs.openFileAbsolute(path, .{}) catch
            return error.PaymentNotFound;
        defer file.close();

        var data: [PAYMENT_SIZE]u8 = undefined;
        const n = try file.readAll(&data);
        if (n < PAYMENT_SIZE) return error.InvalidPaymentData;

        return deserializePayment(&data);
    }

    /// List payments for a merchant
    pub fn listPayments(self: PaymentEngine, merchant_id: []const u8) ![]Payment {
        const dir_path = try self.getPaymentDir();
        defer self.allocator.free(dir_path);

        var dir = std.fs.openDirAbsolute(dir_path, .{ .iterate = true }) catch {
            return try self.allocator.alloc(Payment, 0);
        };
        defer dir.close();

        var payments: std.ArrayList(Payment) = .{};
        var it = dir.iterate();
        while (try it.next()) |entry| {
            if (entry.kind == .file and std.mem.endsWith(u8, entry.name, ".pay")) {
                const name_len = entry.name.len - 4;
                const payment = self.loadPayment(entry.name[0..name_len]) catch continue;
                if (std.mem.eql(u8, payment.getMerchantId(), merchant_id)) {
                    try payments.append(self.allocator, payment);
                }
            }
        }
        return payments.toOwnedSlice(self.allocator);
    }

    fn savePayment(self: PaymentEngine, payment: *const Payment) !void {
        try self.ensureDir();
        const data = serializePayment(payment);
        const path = try self.getPaymentPath(payment.getId());
        defer self.allocator.free(path);

        const file = try std.fs.createFileAbsolute(path, .{});
        defer file.close();
        try file.writeAll(&data);
    }
};

/// Fee structure (transparent breakdown):
///
///   Total fee to merchant: 1.0% flat
///   ├── Exchange cost:     0.5%  (EUR→BSV + BSV→EUR conversion spread)
///   ├── ROXEX margin:      0.5%  (platform revenue)
///   └── BSV network:       ~$0.001 (absorbed by ROXEX, not charged)
///
///   Stripe charges 2.9% + 30c = 3.2% on $100.
///   BSVPay charges 1.0% flat  = 1.0% on $100.
///   Merchant saves 2.2% on every transaction.
///
///   Minimum fee: 1 cent (enables micropayments from $0.01)

/// ROXEX platform margin: 0.5%
pub const ROXEX_MARGIN_BPS: u64 = 50; // basis points (50 = 0.5%)
/// Exchange conversion cost: 0.5% round-trip (0.25% each way)
pub const EXCHANGE_COST_BPS: u64 = 50; // basis points
/// Total fee: 1.0%
pub const TOTAL_FEE_BPS: u64 = ROXEX_MARGIN_BPS + EXCHANGE_COST_BPS;

/// Total fee charged to merchant (1.0% flat, min 1 cent)
pub fn calculateFee(amount: u64) u64 {
    const fee = (amount * TOTAL_FEE_BPS) / 10000;
    return if (fee < 1) 1 else fee;
}

/// ROXEX revenue portion of the fee (0.5%)
pub fn roxexMargin(amount: u64) u64 {
    const margin = (amount * ROXEX_MARGIN_BPS) / 10000;
    return if (margin < 1) 1 else margin;
}

/// Exchange conversion cost portion (0.5%)
pub fn exchangeCost(amount: u64) u64 {
    return (amount * EXCHANGE_COST_BPS) / 10000;
}

/// Net amount merchant receives after all fees
pub fn netAmount(amount: u64) u64 {
    const fee = calculateFee(amount);
    return if (fee >= amount) 0 else amount - fee;
}

/// What Stripe would charge for comparison
pub fn stripeFee(amount: u64) u64 {
    return (amount * 29) / 1000 + 30; // 2.9% + 30c
}

/// How much the merchant saves vs Stripe
pub fn savingsVsStripe(amount: u64) u64 {
    const our_fee = calculateFee(amount);
    const their_fee = stripeFee(amount);
    return if (their_fee > our_fee) their_fee - our_fee else 0;
}

fn hexEncode16(bytes: []const u8) [16]u8 {
    const hex_chars = "0123456789abcdef";
    var result: [16]u8 = undefined;
    for (bytes[0..8], 0..) |byte, i| {
        result[i * 2] = hex_chars[byte >> 4];
        result[i * 2 + 1] = hex_chars[byte & 0x0F];
    }
    return result;
}

const PAYMENT_SIZE = 512;

fn serializePayment(p: *const Payment) [PAYMENT_SIZE]u8 {
    var buf: [PAYMENT_SIZE]u8 = [_]u8{0} ** PAYMENT_SIZE;
    var off: usize = 0;

    @memcpy(buf[off..][0..32], &p.id);
    off += 32;
    buf[off] = p.id_len;
    off += 1;
    @memcpy(buf[off..][0..32], &p.merchant_id);
    off += 32;
    buf[off] = p.merchant_id_len;
    off += 1;
    std.mem.writeInt(u64, buf[off..][0..8], p.amount, .little);
    off += 8;
    buf[off] = p.currency.toByte();
    off += 1;
    buf[off] = p.status.toByte();
    off += 1;
    @memcpy(buf[off..][0..128], &p.description);
    off += 128;
    buf[off] = p.description_len;
    off += 1;
    @memcpy(buf[off..][0..64], &p.customer_email);
    off += 64;
    buf[off] = p.customer_email_len;
    off += 1;
    std.mem.writeInt(u64, buf[off..][0..8], p.bsv_satoshis, .little);
    off += 8;
    @memcpy(buf[off..][0..64], &p.bsv_txid);
    off += 64;
    buf[off] = p.bsv_txid_len;
    off += 1;
    std.mem.writeInt(u64, buf[off..][0..8], @bitCast(p.exchange_rate), .little);
    off += 8;
    std.mem.writeInt(u64, buf[off..][0..8], p.refunded_amount, .little);
    off += 8;
    std.mem.writeInt(i64, buf[off..][0..8], p.created_at, .little);
    off += 8;
    std.mem.writeInt(i64, buf[off..][0..8], p.confirmed_at, .little);
    off += 8;
    @memcpy(buf[off..][0..128], &p.metadata);

    return buf;
}

fn deserializePayment(data: *const [PAYMENT_SIZE]u8) Payment {
    var off: usize = 0;
    var p: Payment = undefined;

    @memcpy(&p.id, data[off..][0..32]);
    off += 32;
    p.id_len = data[off];
    off += 1;
    @memcpy(&p.merchant_id, data[off..][0..32]);
    off += 32;
    p.merchant_id_len = data[off];
    off += 1;
    p.amount = std.mem.readInt(u64, data[off..][0..8], .little);
    off += 8;
    p.currency = account_mod.Currency.fromByte(data[off]) catch .USD;
    off += 1;
    p.status = PaymentStatus.fromByte(data[off]);
    off += 1;
    @memcpy(&p.description, data[off..][0..128]);
    off += 128;
    p.description_len = data[off];
    off += 1;
    @memcpy(&p.customer_email, data[off..][0..64]);
    off += 64;
    p.customer_email_len = data[off];
    off += 1;
    p.bsv_satoshis = std.mem.readInt(u64, data[off..][0..8], .little);
    off += 8;
    @memcpy(&p.bsv_txid, data[off..][0..64]);
    off += 64;
    p.bsv_txid_len = data[off];
    off += 1;
    p.exchange_rate = @bitCast(std.mem.readInt(u64, data[off..][0..8], .little));
    off += 8;
    p.refunded_amount = std.mem.readInt(u64, data[off..][0..8], .little);
    off += 8;
    p.created_at = std.mem.readInt(i64, data[off..][0..8], .little);
    off += 8;
    p.confirmed_at = std.mem.readInt(i64, data[off..][0..8], .little);
    off += 8;
    @memcpy(&p.metadata, data[off..][0..128]);
    p.metadata_len = 0;
    // Find metadata length
    while (p.metadata_len < 128 and p.metadata[p.metadata_len] != 0) : (p.metadata_len += 1) {}

    return p;
}

test "fee calculation" {
    // $10.00 = 1000 cents → 1.0% = 10 cents total (vs Stripe's 59 cents)
    try std.testing.expectEqual(@as(u64, 10), calculateFee(1000));
    // ROXEX keeps 5 cents, exchange costs 5 cents
    try std.testing.expectEqual(@as(u64, 5), roxexMargin(1000));
    try std.testing.expectEqual(@as(u64, 5), exchangeCost(1000));

    // $100.00 = 10000 cents → 1.0% = 100 cents = $1.00 (vs Stripe's $3.20)
    try std.testing.expectEqual(@as(u64, 100), calculateFee(10000));
    // ROXEX keeps $0.50, exchange costs $0.50
    try std.testing.expectEqual(@as(u64, 50), roxexMargin(10000));
    // Merchant nets $99.00
    try std.testing.expectEqual(@as(u64, 9900), netAmount(10000));

    // $0.10 = 10 cents → 1.0% = 0, min 1 cent
    try std.testing.expectEqual(@as(u64, 1), calculateFee(10));

    // Savings vs Stripe on $100: Stripe $3.20 - BSVPay $1.00 = $2.20
    try std.testing.expectEqual(@as(u64, 220), savingsVsStripe(10000));
}

test "payment status roundtrip" {
    const statuses = [_]PaymentStatus{ .pending, .processing, .succeeded, .failed, .refunded, .partially_refunded };
    for (statuses) |s| {
        try std.testing.expectEqual(s, PaymentStatus.fromByte(s.toByte()));
    }
}
