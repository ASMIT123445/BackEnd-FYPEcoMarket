"""
Ecomarket — Order & Payment HTML Email Templates
All transactional emails sent to customers for order/payment events.
"""
from django.core.mail import EmailMultiAlternatives
from django.conf import settings


# ── Shared layout helpers ─────────────────────────────────────────────────────

def _header():
    return """
    <tr>
      <td style="background:linear-gradient(135deg,#2e7d32,#66bb6a);padding:32px 40px;text-align:center;">
        <h1 style="margin:0;color:#fff;font-size:24px;font-weight:700;letter-spacing:1px;">🌿 Ecomarket</h1>
        <p style="margin:6px 0 0;color:#c8e6c9;font-size:13px;">Nepal's Trusted Eco-Friendly Marketplace</p>
      </td>
    </tr>"""


def _footer():
    return """
    <tr>
      <td style="background:#f9fbe7;padding:18px 40px;text-align:center;border-top:1px solid #e8f5e9;">
        <p style="margin:0;color:#aaa;font-size:12px;">
          © 2025 Ecomarket · Sustainable Shopping Platform<br/>
          This is an automated message — please do not reply.
        </p>
      </td>
    </tr>"""


def _wrap(body_rows: str) -> str:
    """Wrap header + body rows + footer in the outer table shell."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
</head>
<body style="margin:0;padding:0;background:#f0f4f0;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f0f4f0;padding:36px 0;">
    <tr><td align="center">
      <table width="580" cellpadding="0" cellspacing="0"
             style="background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,0.08);">
        {_header()}
        {body_rows}
        {_footer()}
      </table>
    </td></tr>
  </table>
</body>
</html>"""


def _notice(icon: str, text: str, color: str = "#795548", bg: str = "#fff8e1", border: str = "#ffc107") -> str:
    return f"""
    <tr>
      <td style="padding:0 40px 20px;">
        <table width="100%" cellpadding="0" cellspacing="0">
          <tr>
            <td style="background:{bg};border-left:4px solid {border};border-radius:4px;padding:12px 16px;">
              <p style="margin:0;color:{color};font-size:13px;">{icon} {text}</p>
            </td>
          </tr>
        </table>
      </td>
    </tr>"""


def _order_items_table(order) -> str:
    rows = ""
    for item in order.items.all():
        rows += f"""
        <tr>
          <td style="padding:10px 0;border-bottom:1px solid #f5f5f5;font-size:14px;color:#333;">
            {item.product.name}
          </td>
          <td style="padding:10px 0;border-bottom:1px solid #f5f5f5;font-size:14px;color:#555;text-align:center;">
            × {item.quantity}
          </td>
          <td style="padding:10px 0;border-bottom:1px solid #f5f5f5;font-size:14px;color:#2e7d32;text-align:right;font-weight:600;">
            Rs {float(item.price) * item.quantity:,.0f}
          </td>
        </tr>"""
    return f"""
    <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">
      <thead>
        <tr>
          <th style="text-align:left;font-size:12px;color:#999;font-weight:600;text-transform:uppercase;padding-bottom:8px;border-bottom:2px solid #e8f5e9;">Product</th>
          <th style="text-align:center;font-size:12px;color:#999;font-weight:600;text-transform:uppercase;padding-bottom:8px;border-bottom:2px solid #e8f5e9;">Qty</th>
          <th style="text-align:right;font-size:12px;color:#999;font-weight:600;text-transform:uppercase;padding-bottom:8px;border-bottom:2px solid #e8f5e9;">Amount</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
      <tfoot>
        <tr>
          <td colspan="2" style="padding-top:12px;font-size:15px;font-weight:700;color:#1b5e20;">Total</td>
          <td style="padding-top:12px;font-size:15px;font-weight:700;color:#1b5e20;text-align:right;">
            Rs {float(order.total_amount):,.0f}
          </td>
        </tr>
      </tfoot>
    </table>"""


def _status_badge(status: str) -> str:
    colors = {
        'pending':    ('#f59e0b', '#fffbeb'),
        'confirmed':  ('#2e7d32', '#f1f8e9'),
        'processing': ('#1565c0', '#e3f2fd'),
        'shipped':    ('#6a1b9a', '#f3e5f5'),
        'delivered':  ('#2e7d32', '#e8f5e9'),
        'cancelled':  ('#c62828', '#ffebee'),
    }
    fg, bg = colors.get(status, ('#555', '#f5f5f5'))
    label = status.capitalize()
    return (f'<span style="display:inline-block;background:{bg};color:{fg};'
            f'border:1px solid {fg};border-radius:20px;padding:4px 14px;'
            f'font-size:13px;font-weight:700;">{label}</span>')


def _send(subject: str, plain: str, html: str, to: str):
    msg = EmailMultiAlternatives(
        subject=subject,
        body=plain,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[to],
    )
    msg.attach_alternative(html, "text/html")
    msg.send(fail_silently=True)


# ── 1. Order Confirmed (COD) ──────────────────────────────────────────────────

def send_order_confirmed_email(order):
    customer = order.user
    name = customer.first_name or customer.username
    email = customer.email
    if not email:
        return

    items_html = _order_items_table(order)
    payment_method = (order.payment_method or 'cod').upper()

    body = f"""
    <tr>
      <td style="padding:36px 40px 8px;">
        <h2 style="margin:0 0 6px;color:#1b5e20;font-size:20px;">Order Confirmed! 🎉</h2>
        <p style="margin:0 0 20px;color:#555;font-size:15px;line-height:1.6;">
          Hi <strong>{name}</strong>, your order has been placed successfully.
          We'll notify you as it progresses.
        </p>

        <!-- Order meta -->
        <table width="100%" cellpadding="0" cellspacing="0"
               style="background:#f9fbe7;border-radius:8px;padding:16px 20px;margin-bottom:24px;">
          <tr>
            <td style="font-size:13px;color:#555;padding:4px 0;">
              <strong style="color:#1b5e20;">Order #</strong> {order.id}
            </td>
            <td style="font-size:13px;color:#555;padding:4px 0;text-align:right;">
              <strong style="color:#1b5e20;">Payment</strong> {payment_method}
            </td>
          </tr>
          <tr>
            <td style="font-size:13px;color:#555;padding:4px 0;">
              <strong style="color:#1b5e20;">Status</strong>&nbsp; {_status_badge('confirmed')}
            </td>
            <td style="font-size:13px;color:#555;padding:4px 0;text-align:right;">
              <strong style="color:#1b5e20;">Date</strong> {order.created_at.strftime('%d %b %Y')}
            </td>
          </tr>
        </table>

        <!-- Items -->
        <h4 style="margin:0 0 12px;color:#333;font-size:14px;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;">
          Order Summary
        </h4>
        {items_html}
      </td>
    </tr>"""

    if order.shipping_address:
        body += f"""
    <tr>
      <td style="padding:20px 40px 0;">
        <h4 style="margin:0 0 8px;color:#333;font-size:14px;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;">
          Delivery Address
        </h4>
        <p style="margin:0;color:#555;font-size:14px;line-height:1.6;">{order.shipping_address}</p>
      </td>
    </tr>"""

    if order.points_earned > 0:
        body += _notice("🌱", f"You'll earn <strong>{order.points_earned} Green Points</strong> once your order is delivered!", "#2e7d32", "#f1f8e9", "#66bb6a")

    body += """
    <tr><td style="padding:28px 40px 36px;">
      <p style="margin:0;color:#777;font-size:13px;line-height:1.6;">
        Thank you for shopping sustainably with Ecomarket. Every purchase helps build a greener Nepal. 🌿
      </p>
    </td></tr>"""

    html = _wrap(body)
    plain = (f"Hi {name},\n\nYour Order #{order.id} has been confirmed.\n"
             f"Total: Rs {order.total_amount}\nPayment: {payment_method}\n\n"
             f"Thank you for shopping with Ecomarket!")
    _send(f"Order #{order.id} Confirmed — Ecomarket 🌿", plain, html, email)


# ── 2. Payment Successful ─────────────────────────────────────────────────────

def send_payment_success_email(order):
    customer = order.user
    name = customer.first_name or customer.username
    email = customer.email
    if not email:
        return

    payment_method = (order.payment_method or '').upper()
    items_html = _order_items_table(order)

    body = f"""
    <tr>
      <td style="padding:36px 40px 8px;">
        <h2 style="margin:0 0 6px;color:#1b5e20;font-size:20px;">Payment Successful ✅</h2>
        <p style="margin:0 0 20px;color:#555;font-size:15px;line-height:1.6;">
          Hi <strong>{name}</strong>, we've received your payment. Your order is now confirmed and being prepared.
        </p>

        <table width="100%" cellpadding="0" cellspacing="0"
               style="background:#f1f8e9;border-radius:8px;padding:16px 20px;margin-bottom:24px;">
          <tr>
            <td style="font-size:13px;color:#555;padding:4px 0;">
              <strong style="color:#1b5e20;">Order #</strong> {order.id}
            </td>
            <td style="font-size:13px;color:#555;padding:4px 0;text-align:right;">
              <strong style="color:#1b5e20;">Method</strong> {payment_method}
            </td>
          </tr>
          <tr>
            <td colspan="2" style="font-size:22px;font-weight:800;color:#1b5e20;padding-top:10px;">
              Rs {float(order.total_amount):,.0f}
              <span style="font-size:13px;font-weight:400;color:#66bb6a;margin-left:8px;">Paid</span>
            </td>
          </tr>
        </table>

        <h4 style="margin:0 0 12px;color:#333;font-size:14px;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;">
          Order Summary
        </h4>
        {items_html}
      </td>
    </tr>"""

    if order.points_earned > 0:
        body += _notice("🌱", f"<strong>{order.points_earned} Green Points</strong> have been added to your account!", "#2e7d32", "#f1f8e9", "#66bb6a")

    body += """
    <tr><td style="padding:20px 40px 36px;">
      <p style="margin:0;color:#777;font-size:13px;">
        Keep this email as your payment receipt. Thank you for choosing Ecomarket! 🌿
      </p>
    </td></tr>"""

    html = _wrap(body)
    plain = (f"Hi {name},\n\nPayment received for Order #{order.id}.\n"
             f"Amount: Rs {order.total_amount}\nMethod: {payment_method}\n\n"
             f"Thank you for shopping with Ecomarket!")
    _send(f"Payment Confirmed — Order #{order.id} | Ecomarket", plain, html, email)


# ── 3. Payment Failed ─────────────────────────────────────────────────────────

def send_payment_failed_email(order):
    customer = order.user
    name = customer.first_name or customer.username
    email = customer.email
    if not email:
        return

    payment_method = (order.payment_method or '').upper()

    body = f"""
    <tr>
      <td style="padding:36px 40px 8px;">
        <h2 style="margin:0 0 6px;color:#c62828;font-size:20px;">Payment Failed ❌</h2>
        <p style="margin:0 0 20px;color:#555;font-size:15px;line-height:1.6;">
          Hi <strong>{name}</strong>, unfortunately your payment for Order #{order.id} could not be processed.
          Your order has been cancelled and no amount has been charged.
        </p>

        <table width="100%" cellpadding="0" cellspacing="0"
               style="background:#ffebee;border-radius:8px;padding:16px 20px;margin-bottom:24px;">
          <tr>
            <td style="font-size:13px;color:#555;padding:4px 0;">
              <strong style="color:#c62828;">Order #</strong> {order.id}
            </td>
            <td style="font-size:13px;color:#555;padding:4px 0;text-align:right;">
              <strong style="color:#c62828;">Method</strong> {payment_method}
            </td>
          </tr>
          <tr>
            <td colspan="2" style="font-size:22px;font-weight:800;color:#c62828;padding-top:10px;">
              Rs {float(order.total_amount):,.0f}
              <span style="font-size:13px;font-weight:400;color:#ef9a9a;margin-left:8px;">Not Charged</span>
            </td>
          </tr>
        </table>
      </td>
    </tr>"""

    body += _notice("💡", "Please try placing your order again. If the issue persists, contact your bank or try a different payment method.", "#795548", "#fff8e1", "#ffc107")

    body += """
    <tr><td style="padding:20px 40px 36px;">
      <p style="margin:0;color:#777;font-size:13px;">
        We're sorry for the inconvenience. Visit <a href="http://localhost:5173/main" style="color:#2e7d32;">Ecomarket</a> to try again.
      </p>
    </td></tr>"""

    html = _wrap(body)
    plain = (f"Hi {name},\n\nYour payment for Order #{order.id} failed.\n"
             f"No amount was charged. Please try again.\n\nEcomarket Team")
    _send(f"Payment Failed — Order #{order.id} | Ecomarket", plain, html, email)


# ── 4. Order Status Update ────────────────────────────────────────────────────

STATUS_ICONS = {
    'pending':    ('⏳', 'Your order is waiting to be confirmed.'),
    'confirmed':  ('✅', 'Your order has been confirmed and is being prepared.'),
    'processing': ('⚙️', 'Your order is currently being processed and packed.'),
    'shipped':    ('🚚', 'Great news! Your order is on its way to you.'),
    'delivered':  ('📦', 'Your order has been delivered. Enjoy your eco-friendly products!'),
    'cancelled':  ('❌', 'Your order has been cancelled.'),
}

STATUS_COLORS = {
    'pending':    '#f59e0b',
    'confirmed':  '#2e7d32',
    'processing': '#1565c0',
    'shipped':    '#6a1b9a',
    'delivered':  '#2e7d32',
    'cancelled':  '#c62828',
}

STATUS_BG = {
    'pending':    '#fffbeb',
    'confirmed':  '#f1f8e9',
    'processing': '#e3f2fd',
    'shipped':    '#f3e5f5',
    'delivered':  '#e8f5e9',
    'cancelled':  '#ffebee',
}


def send_order_status_update_email(order, new_status: str, note: str = ''):
    customer = order.user
    name = customer.first_name or customer.username
    email = customer.email
    if not email:
        return

    icon, description = STATUS_ICONS.get(new_status, ('📋', 'Your order status has been updated.'))
    color = STATUS_COLORS.get(new_status, '#555')
    bg = STATUS_BG.get(new_status, '#f5f5f5')
    label = new_status.capitalize()

    body = f"""
    <tr>
      <td style="padding:36px 40px 8px;">
        <h2 style="margin:0 0 6px;color:{color};font-size:20px;">Order Update {icon}</h2>
        <p style="margin:0 0 24px;color:#555;font-size:15px;line-height:1.6;">
          Hi <strong>{name}</strong>, {description}
        </p>

        <!-- Status card -->
        <table width="100%" cellpadding="0" cellspacing="0"
               style="background:{bg};border-radius:10px;padding:20px 24px;margin-bottom:24px;">
          <tr>
            <td>
              <p style="margin:0 0 4px;font-size:12px;color:#999;text-transform:uppercase;letter-spacing:0.5px;font-weight:600;">
                Order #{order.id}
              </p>
              <p style="margin:0;font-size:28px;font-weight:800;color:{color};">{label}</p>
            </td>
            <td style="text-align:right;vertical-align:middle;">
              <span style="font-size:40px;">{icon}</span>
            </td>
          </tr>
        </table>"""

    if note:
        body += f"""
        <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:20px;">
          <tr>
            <td style="background:#f5f5f5;border-left:4px solid {color};border-radius:4px;padding:12px 16px;">
              <p style="margin:0;color:#555;font-size:13px;">
                <strong>Note from seller:</strong> {note}
              </p>
            </td>
          </tr>
        </table>"""

    # Order summary strip
    body += f"""
        <table width="100%" cellpadding="0" cellspacing="0"
               style="border:1px solid #e8f5e9;border-radius:8px;padding:14px 18px;margin-bottom:8px;">
          <tr>
            <td style="font-size:13px;color:#555;">
              <strong style="color:#1b5e20;">Total</strong>&nbsp; Rs {float(order.total_amount):,.0f}
            </td>
            <td style="font-size:13px;color:#555;text-align:right;">
              <strong style="color:#1b5e20;">Payment</strong>&nbsp; {(order.payment_method or 'N/A').upper()}
            </td>
          </tr>
        </table>
      </td>
    </tr>"""

    if new_status == 'shipped':
        body += _notice("📍", "Your package is on its way! Estimated delivery: 2–5 business days.", "#1565c0", "#e3f2fd", "#1565c0")

    if new_status == 'delivered':
        body += _notice("⭐", "Loved your order? Leave a review on Ecomarket to help other eco-conscious shoppers!", "#2e7d32", "#f1f8e9", "#66bb6a")

    body += """
    <tr><td style="padding:20px 40px 36px;">
      <p style="margin:0;color:#777;font-size:13px;">
        Thank you for shopping sustainably with Ecomarket. 🌿
      </p>
    </td></tr>"""

    html = _wrap(body)
    plain = (f"Hi {name},\n\nYour Order #{order.id} status has been updated to: {label}\n"
             f"{f'Note: {note}' if note else ''}\n\nTotal: Rs {order.total_amount}\n\nEcomarket Team")
    _send(f"Order #{order.id} — {label} {icon} | Ecomarket", plain, html, email)


# ── 5. Order Cancelled (by customer) ─────────────────────────────────────────

def send_order_cancelled_email(order):
    customer = order.user
    name = customer.first_name or customer.username
    email = customer.email
    if not email:
        return

    payment_method = (order.payment_method or 'N/A').upper()
    was_paid = order.payment_status == 'completed'

    body = f"""
    <tr>
      <td style="padding:36px 40px 8px;">
        <h2 style="margin:0 0 6px;color:#c62828;font-size:20px;">Order Cancelled ❌</h2>
        <p style="margin:0 0 20px;color:#555;font-size:15px;line-height:1.6;">
          Hi <strong>{name}</strong>, your Order #{order.id} has been successfully cancelled as requested.
        </p>

        <table width="100%" cellpadding="0" cellspacing="0"
               style="background:#ffebee;border-radius:8px;padding:16px 20px;margin-bottom:24px;">
          <tr>
            <td style="font-size:13px;color:#555;padding:4px 0;">
              <strong style="color:#c62828;">Order #</strong> {order.id}
            </td>
            <td style="font-size:13px;color:#555;padding:4px 0;text-align:right;">
              <strong style="color:#c62828;">Total</strong> Rs {float(order.total_amount):,.0f}
            </td>
          </tr>
          <tr>
            <td style="font-size:13px;color:#555;padding:4px 0;">
              <strong style="color:#c62828;">Payment</strong> {payment_method}
            </td>
            <td style="font-size:13px;color:#555;padding:4px 0;text-align:right;">
              <strong style="color:#c62828;">Status</strong> {_status_badge('cancelled')}
            </td>
          </tr>
        </table>
      </td>
    </tr>"""

    if was_paid:
        body += _notice(
            "💳",
            f"A refund of <strong>Rs {float(order.total_amount):,.0f}</strong> will be processed to your "
            f"{payment_method} account within <strong>5–7 business days</strong>.",
            "#1565c0", "#e3f2fd", "#1565c0"
        )
    else:
        body += _notice("ℹ️", "No payment was charged for this order, so no refund is required.", "#555", "#f5f5f5", "#bbb")

    body += """
    <tr><td style="padding:20px 40px 36px;">
      <p style="margin:0;color:#777;font-size:13px;">
        We hope to see you again soon. Visit
        <a href="http://localhost:5173/main" style="color:#2e7d32;">Ecomarket</a>
        to continue shopping sustainably. 🌿
      </p>
    </td></tr>"""

    html = _wrap(body)
    plain = (f"Hi {name},\n\nYour Order #{order.id} has been cancelled.\n"
             f"Total: Rs {order.total_amount}\n"
             f"{'A refund will be processed within 5-7 business days.' if was_paid else 'No payment was charged.'}\n\n"
             f"Ecomarket Team")
    _send(f"Order #{order.id} Cancelled | Ecomarket", plain, html, email)
