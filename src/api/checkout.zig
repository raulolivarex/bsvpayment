const std = @import("std");
const payments_mod = @import("payments.zig");
const account_mod = @import("../account/account.zig");

/// Generate an HTML checkout page for a payment
pub fn generateCheckoutPage(payment: *const payments_mod.Payment, allocator: std.mem.Allocator) ![]u8 {
    const sym = payment.currency.symbol();
    const whole = payment.amount / 100;
    const frac = payment.amount % 100;
    const desc = payment.getDescription();
    const payment_id = payment.getId();

    return std.fmt.allocPrint(allocator,
        \\<!DOCTYPE html>
        \\<html lang="en">
        \\<head>
        \\<meta charset="UTF-8">
        \\<meta name="viewport" content="width=device-width, initial-scale=1.0">
        \\<title>ROXEXPay — Checkout</title>
        \\<style>
        \\* {{ margin: 0; padding: 0; box-sizing: border-box; }}
        \\body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f6f9fc; display: flex; justify-content: center; align-items: center; min-height: 100vh; }}
        \\.checkout {{ background: white; border-radius: 12px; box-shadow: 0 4px 24px rgba(0,0,0,0.1); padding: 40px; width: 420px; }}
        \\.logo {{ text-align: center; margin-bottom: 24px; }}
        \\.logo h1 {{ font-size: 24px; color: #1a1a2e; }}
        \\.logo span {{ color: #6c5ce7; }}
        \\.amount {{ text-align: center; font-size: 48px; font-weight: 700; color: #1a1a2e; margin: 24px 0; }}
        \\.amount small {{ font-size: 20px; color: #888; }}
        \\.desc {{ text-align: center; color: #666; margin-bottom: 32px; font-size: 14px; }}
        \\.form-group {{ margin-bottom: 16px; }}
        \\.form-group label {{ display: block; font-size: 13px; font-weight: 600; color: #555; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.5px; }}
        \\.form-group input {{ width: 100%; padding: 12px; border: 2px solid #e0e0e0; border-radius: 8px; font-size: 16px; transition: border-color 0.2s; }}
        \\.form-group input:focus {{ outline: none; border-color: #6c5ce7; }}
        \\.pay-btn {{ width: 100%; padding: 16px; background: #6c5ce7; color: white; border: none; border-radius: 8px; font-size: 18px; font-weight: 600; cursor: pointer; margin-top: 16px; transition: background 0.2s; }}
        \\.pay-btn:hover {{ background: #5b4cdb; }}
        \\.secure {{ text-align: center; margin-top: 16px; font-size: 12px; color: #999; }}
        \\.badge {{ display: inline-block; background: #f0f0f0; border-radius: 20px; padding: 4px 12px; font-size: 11px; color: #666; margin-top: 8px; }}
        \\.success {{ display: none; text-align: center; padding: 40px; }}
        \\.success h2 {{ color: #27ae60; margin-bottom: 8px; }}
        \\</style>
        \\</head>
        \\<body>
        \\<div class="checkout" id="checkout-form">
        \\  <div class="logo"><h1>ROXEXPay</h1></div>
        \\  <div class="amount">{s}{d}.{d:0>2} <small>{s}</small></div>
        \\  <div class="desc">{s}</div>
        \\  <form onsubmit="handlePay(event)">
        \\    <div class="form-group">
        \\      <label>Email</label>
        \\      <input type="email" id="email" placeholder="you@email.com" required>
        \\    </div>
        \\    <div class="form-group">
        \\      <label>Card number</label>
        \\      <input type="text" id="card" placeholder="4242 4242 4242 4242" maxlength="19" required>
        \\    </div>
        \\    <div style="display:flex;gap:12px">
        \\      <div class="form-group" style="flex:1">
        \\        <label>Expiry</label>
        \\        <input type="text" id="expiry" placeholder="MM/YY" maxlength="5" required>
        \\      </div>
        \\      <div class="form-group" style="flex:1">
        \\        <label>CVC</label>
        \\        <input type="text" id="cvc" placeholder="123" maxlength="4" required>
        \\      </div>
        \\    </div>
        \\    <button type="submit" class="pay-btn">Pay {s}{d}.{d:0>2}</button>
        \\  </form>
        \\  <div class="secure">Secured by ROXEXPay instant settlement</div>
        \\  <div style="text-align:center"><span class="badge">0.5% fee &middot; Instant &middot; No middlemen</span></div>
        \\</div>
        \\<div class="checkout success" id="success-msg">
        \\  <div class="logo"><h1>ROXEXPay</h1></div>
        \\  <div style="font-size:64px;margin:20px">&#10003;</div>
        \\  <h2>Payment Successful!</h2>
        \\  <p style="color:#666;margin-top:8px">Your payment of {s}{d}.{d:0>2} has been processed.</p>
        \\  <p style="color:#999;margin-top:16px;font-size:12px">Settled instantly via ROXEXPay</p>
        \\</div>
        \\<script>
        \\async function handlePay(e) {{
        \\  e.preventDefault();
        \\  const email = document.getElementById('email').value;
        \\  const btn = document.querySelector('.pay-btn');
        \\  btn.textContent = 'Processing...';
        \\  btn.disabled = true;
        \\  try {{
        \\    const res = await fetch('/v1/payments/{s}/confirm', {{
        \\      method: 'POST',
        \\      headers: {{'Content-Type': 'application/json'}},
        \\      body: JSON.stringify({{email: email}})
        \\    }});
        \\    if (res.ok) {{
        \\      document.getElementById('checkout-form').style.display = 'none';
        \\      document.getElementById('success-msg').style.display = 'block';
        \\    }} else {{
        \\      btn.textContent = 'Payment failed. Retry';
        \\      btn.disabled = false;
        \\    }}
        \\  }} catch(err) {{
        \\    btn.textContent = 'Error. Retry';
        \\    btn.disabled = false;
        \\  }}
        \\}}
        \\</script>
        \\</body>
        \\</html>
    , .{
        sym, whole, frac, sym,
        desc,
        sym, whole, frac,
        sym, whole, frac,
        payment_id,
    });
}

test "checkout page generation" {
    const allocator = std.testing.allocator;
    var payment = payments_mod.Payment{
        .id = [_]u8{0} ** 32,
        .id_len = 4,
        .merchant_id = [_]u8{0} ** 32,
        .merchant_id_len = 0,
        .amount = 1050,
        .currency = .EUR,
        .status = .pending,
        .description = [_]u8{0} ** 128,
        .description_len = 4,
        .customer_email = [_]u8{0} ** 64,
        .customer_email_len = 0,
        .bsv_satoshis = 2_000_000,
        .bsv_txid = [_]u8{0} ** 64,
        .bsv_txid_len = 0,
        .exchange_rate = 50.0,
        .refunded_amount = 0,
        .created_at = 0,
        .confirmed_at = 0,
        .metadata = [_]u8{0} ** 128,
        .metadata_len = 0,
    };
    @memcpy(payment.description[0..4], "Test");
    const html = try generateCheckoutPage(&payment, allocator);
    defer allocator.free(html);
    try std.testing.expect(std.mem.indexOf(u8, html, "ROXEX") != null);
}
