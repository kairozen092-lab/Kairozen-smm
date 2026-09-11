#!/usr/bin/env python3
"""Kairozen SMM — lightweight panel API + static site."""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
import time
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash

BASE = Path(__file__).resolve().parent
DEFAULT_DB = BASE / "db_default.json"
# Prefer persistent disk on Render (DATA_DIR=/var/data)
_DATA_DIR = Path(os.environ.get("DATA_DIR") or os.environ.get("KAIROZEN_DB_DIR") or BASE)
_DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = Path(os.environ.get("KAIROZEN_DB") or (_DATA_DIR / "db.json"))

app = Flask(__name__, static_folder=str(BASE), static_url_path="")
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(24))
# Secure cookies when behind HTTPS (Render)
_prod = bool(os.environ.get("RENDER") or os.environ.get("FORCE_HTTPS"))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=_prod,
)

_lock = threading.Lock()

# Optional Bakong
BAKONG_TOKEN = os.environ.get("BAKONG_TOKEN", "")
BAKONG_ACCOUNT_ID = os.environ.get("BAKONG_ACCOUNT_ID", "")
BAKONG_MERCHANT_NAME = os.environ.get("BAKONG_MERCHANT_NAME", "Kairozen SMM")
BAKONG_MERCHANT_CITY = os.environ.get("BAKONG_MERCHANT_CITY", "Phnom Penh")
BAKONG_CURRENCY = os.environ.get("BAKONG_CURRENCY", "USD")
_khqr = None
_pending_qr = {}  # deposit_id -> {md5, amount, user_id, created}

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")
# PerfectPanel-compatible provider (optional)
PROVIDER_API_URL = os.environ.get("PROVIDER_API_URL", "").rstrip("/")
PROVIDER_API_KEY = os.environ.get("PROVIDER_API_KEY", "")



def load_db():
    if not DB_PATH.exists():
        data = json.loads(DEFAULT_DB.read_text(encoding="utf-8"))
        save_db(data)
        return data
    with _lock:
        return json.loads(DB_PATH.read_text(encoding="utf-8"))


def save_db(data):
    with _lock:
        tmp = DB_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(DB_PATH)


def next_id(data, key):
    n = data.setdefault("next_ids", {}).get(key, 1)
    data["next_ids"][key] = n + 1
    return n


def ok(**kw):
    return jsonify({"success": True, **kw})


def err(msg, code=400):
    return jsonify({"success": False, "error": msg}), code


def current_user(data=None):
    uid = session.get("user_id")
    if not uid:
        return None
    data = data or load_db()
    for u in data.get("users", []):
        if u["id"] == uid:
            return u
    return None


def public_user(u):
    return {
        "id": u["id"],
        "username": u["username"],
        "email": u.get("email", ""),
        "balance": round(float(u.get("balance", 0)), 4),
        "created_at": u.get("created_at"),
        "api_key": u.get("api_key", ""),
    }


def user_by_apikey(data, key):
    key = (key or "").strip()
    if not key:
        return None
    for u in data.get("users", []):
        if u.get("api_key") and secrets.compare_digest(u["api_key"], key):
            return u
    return None


# ---------- pages ----------
@app.route("/")
def home():
    return send_from_directory(BASE, "index.html")


@app.route("/dashboard")
@app.route("/dashboard.html")
def dashboard_page():
    return send_from_directory(BASE, "dashboard.html")


@app.route("/admin")
@app.route("/admin.html")
def admin_page():
    return send_from_directory(BASE, "admin.html")


# ---------- auth ----------
@app.route("/api/register", methods=["POST"])
def register():
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    email = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""
    if len(username) < 3:
        return err("Username must be at least 3 characters")
    if len(password) < 6:
        return err("Password must be at least 6 characters")
    if not email or "@" not in email:
        return err("Valid email required")
    data = load_db()
    if any(u["username"].lower() == username.lower() for u in data["users"]):
        return err("Username already taken")
    if any((u.get("email") or "").lower() == email for u in data["users"]):
        return err("Email already registered")
    user = {
        "id": next_id(data, "users"),
        "username": username,
        "email": email,
        "password_hash": generate_password_hash(password),
        "balance": 0.0,
        "created_at": time.time(),
        "api_key": secrets.token_hex(20),
    }
    data["users"].append(user)
    save_db(data)
    session["user_id"] = user["id"]
    return ok(user=public_user(user))


@app.route("/api/login", methods=["POST"])
def login():
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    data = load_db()
    user = next((u for u in data["users"] if u["username"].lower() == username.lower()), None)
    if not user or not check_password_hash(user["password_hash"], password):
        return err("Invalid username or password", 401)
    session["user_id"] = user["id"]
    return ok(user=public_user(user))


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return ok()


@app.route("/api/me")
def me():
    data = load_db()
    user = current_user(data)
    if not user:
        return err("Not logged in", 401)
    return ok(user=public_user(user), settings=data.get("settings", {}))


@app.route("/api/me/apikey", methods=["POST"])
def regenerate_apikey():
    """Regenerate the current user's reseller API key."""
    data = load_db()
    user = current_user(data)
    if not user:
        return err("Not logged in", 401)
    new_key = secrets.token_hex(20)
    for u in data["users"]:
        if u["id"] == user["id"]:
            u["api_key"] = new_key
            user = u
            break
    save_db(data)
    return ok(user=public_user(user))


# ---------- catalogue ----------
@app.route("/api/services")
def services():
    data = load_db()
    return ok(services=data.get("services", []))


@app.route("/api/settings")
def public_settings():
    data = load_db()
    s = data.get("settings", {})
    return ok(
        settings={
            "SITE_NAME": s.get("SITE_NAME", "Kairozen SMM"),
            "LOGO_URL": s.get("LOGO_URL", ""),
            "TELEGRAM_LINK": s.get("TELEGRAM_LINK", ""),
            "SUPPORT_EMAIL": s.get("SUPPORT_EMAIL", ""),
            "CURRENCY": s.get("CURRENCY", "USD"),
        }
    )


# ---------- reseller API (standard SMM Panel API — PerfectPanel/JAP style) ----------
# Lets other people/panels buy services from us programmatically, the same
# way our own admin panel buys from an upstream provider via PROVIDER_API_URL.
# Docs: POST /api/v2  (form-encoded or JSON), params: key, action, ...
#   action=services       ->                                   -> [{service,name,type,category,rate,min,max,refill}, ...]
#   action=add            -> service, link, quantity            -> {order}
#   action=status         -> order                              -> {charge, start_count, status, remains, currency}
#   action=multistatus    -> orders (comma separated ids)       -> {id: {...}, ...}
#   action=refill         -> order                              -> {refill} | {error}
#   action=refill_status  -> refill                             -> {status}
#   action=cancel         -> orders (comma separated ids)       -> [{order, cancel: {status}}, ...]
#   action=balance        ->                                    -> {balance, currency}
# Matches the widely-used SMM Panel API convention so any reseller script,
# bot or third-party panel that already speaks that protocol works with us
# unmodified. Per that convention every well-formed request returns HTTP 200,
# with `{"error": "..."}` in the body on failure -- clients generally only
# inspect the JSON, not the status code.
_ORDER_STATUS_DISPLAY = {
    "processing": "In progress",
    "completed": "Completed",
    "partial": "Partial",
    "canceled": "Canceled",
    "failed": "Canceled",
}


def _order_status_payload(o, currency):
    return {
        "charge": o["charge"],
        "start_count": o.get("start_count", 0),
        "status": _ORDER_STATUS_DISPLAY.get(o.get("status"), (o.get("status") or "").capitalize()),
        "remains": o.get("remains", 0),
        "currency": currency,
    }


@app.route("/api/v2", methods=["GET", "POST"])
def reseller_api():
    if request.method == "POST" and request.is_json:
        body = request.get_json(silent=True) or {}
    else:
        body = request.values.to_dict()

    data = load_db()
    user = user_by_apikey(data, body.get("key"))
    if not user:
        return jsonify({"error": "Invalid API key"})

    action = (body.get("action") or "").strip().lower()
    currency = data.get("settings", {}).get("CURRENCY", "USD")

    if action == "services":
        out = [
            {
                "service": s["id"],
                "name": s["name"],
                "type": "Default",
                "category": s["category"],
                "rate": s["rate"],
                "min": s["min"],
                "max": s["max"],
                "refill": bool(s.get("refill")),
                "cancel": False,
            }
            for s in data.get("services", [])
        ]
        return jsonify(out)

    if action == "balance":
        return jsonify({"balance": f'{round(float(user.get("balance", 0)), 4):.4f}', "currency": currency})

    if action == "add":
        try:
            service_id = int(body.get("service"))
            quantity = int(body.get("quantity"))
        except (TypeError, ValueError):
            return jsonify({"error": "Incorrect service ID or quantity"})
        link = (body.get("link") or "").strip()
        if not link:
            return jsonify({"error": "Link / username required"})
        order, error, user = place_order(data, user, service_id, quantity, link)
        if error:
            return jsonify({"error": error})
        save_db(data)
        return jsonify({"order": order["id"]})

    if action in ("status", "multistatus"):
        ids_raw = body.get("orders") if action == "multistatus" else body.get("order")
        if not ids_raw:
            return jsonify({"error": "order id(s) required"})
        ids = [s.strip() for s in str(ids_raw).split(",") if s.strip()]
        result = {}
        for id_str in ids:
            try:
                oid = int(id_str)
            except ValueError:
                continue
            o = next((x for x in data.get("orders", []) if x["id"] == oid and x["user_id"] == user["id"]), None)
            result[id_str] = {"error": "Order not found"} if not o else _order_status_payload(o, currency)
        if action == "status":
            return jsonify(next(iter(result.values()), {"error": "Order not found"}))
        return jsonify(result)

    if action == "refill":
        try:
            oid = int(body.get("order"))
        except (TypeError, ValueError):
            return jsonify({"error": "Incorrect order id"})
        o = next((x for x in data.get("orders", []) if x["id"] == oid and x["user_id"] == user["id"]), None)
        if not o:
            return jsonify({"error": "Order not found"})
        svc = next((s for s in data.get("services", []) if s["id"] == o["service_id"]), None)
        if not (svc and svc.get("refill")):
            return jsonify({"error": "Refill not available for this service"})
        if o.get("status") != "completed":
            return jsonify({"error": "Order must be completed before it can be refilled"})
        refill_id = next_id(data, "refills")
        o.setdefault("refills", []).append(
            {"id": refill_id, "status": "Pending", "created_at": time.time()}
        )
        save_db(data)
        return jsonify({"refill": refill_id})

    if action == "refill_status":
        try:
            rid = int(body.get("refill"))
        except (TypeError, ValueError):
            return jsonify({"error": "Incorrect refill id"})
        for o in data.get("orders", []):
            if o["user_id"] != user["id"]:
                continue
            for r in o.get("refills", []):
                if r["id"] == rid:
                    return jsonify({"status": r["status"]})
        return jsonify({"error": "Refill not found"})

    if action == "cancel":
        ids_raw = body.get("orders") or body.get("order")
        if not ids_raw:
            return jsonify({"error": "order id(s) required"})
        ids = [s.strip() for s in str(ids_raw).split(",") if s.strip()]
        out = []
        changed = False
        for id_str in ids:
            try:
                oid = int(id_str)
            except ValueError:
                continue
            o = next((x for x in data.get("orders", []) if x["id"] == oid and x["user_id"] == user["id"]), None)
            if not o:
                out.append({"order": id_str, "cancel": {"error": "Order not found"}})
                continue
            if o.get("status") != "processing" or o.get("provider_order_id"):
                out.append({"order": id_str, "cancel": {"error": "Order can no longer be canceled"}})
                continue
            o["status"] = "canceled"
            o["remains"] = o.get("quantity", 0)
            o["updated_at"] = time.time()
            for u in data["users"]:
                if u["id"] == user["id"]:
                    u["balance"] = round(float(u["balance"]) + float(o["charge"]), 4)
                    break
            changed = True
            out.append({"order": id_str, "cancel": {"status": "Canceled"}})
        if changed:
            save_db(data)
        return jsonify(out)

    return jsonify({"error": "Incorrect action"})


# ---------- orders ----------
@app.route("/api/orders", methods=["GET", "POST"])
def orders():
    data = load_db()
    user = current_user(data)
    if not user:
        return err("Not logged in", 401)

    if request.method == "GET":
        changed = False
        now = time.time()
        for o in data.get("orders", []):
            if o["user_id"] != user["id"]:
                continue
            # Demo fulfilment: no provider id → complete after 45s
            if (
                o.get("status") == "processing"
                and not o.get("provider_order_id")
                and now - float(o.get("created_at") or 0) >= 45
            ):
                o["status"] = "completed"
                o["remains"] = 0
                o["updated_at"] = now
                o["demo_complete"] = True
                changed = True
        if changed:
            save_db(data)
        mine = [o for o in data.get("orders", []) if o["user_id"] == user["id"]]
        mine.sort(key=lambda o: o.get("created_at", 0), reverse=True)
        return ok(orders=mine)

    body = request.get_json(silent=True) or {}
    try:
        service_id = int(body.get("service_id"))
        quantity = int(body.get("quantity"))
    except (TypeError, ValueError):
        return err("Invalid service or quantity")
    link = (body.get("link") or "").strip()
    if not link:
        return err("Link / username required")

    order, error, user = place_order(data, user, service_id, quantity, link)
    if error:
        return err(error)
    save_db(data)
    return ok(order=order, user=public_user(user))


def place_order(data, user, service_id, quantity, link):
    """Shared order-placement logic used by the web app and the reseller API.
    Returns (order_dict_or_None, error_message_or_None, updated_user)."""
    svc = next((s for s in data["services"] if s["id"] == service_id), None)
    if not svc:
        return None, "Service not found", user
    if quantity < svc["min"] or quantity > svc["max"]:
        return None, f"Quantity must be between {svc['min']} and {svc['max']}", user

    # rate is per 1000
    cost = round((quantity / 1000.0) * float(svc["rate"]), 4)
    if float(user["balance"]) < cost:
        return None, f"Insufficient balance. Need ${cost:.4f}", user

    # debit
    for u in data["users"]:
        if u["id"] == user["id"]:
            u["balance"] = round(float(u["balance"]) - cost, 4)
            user = u
            break

    order = {
        "id": next_id(data, "orders"),
        "user_id": user["id"],
        "service_id": svc["id"],
        "service_name": svc["name"],
        "category": svc["category"],
        "link": link,
        "quantity": quantity,
        "charge": cost,
        "status": "processing",
        "start_count": 0,
        "remains": quantity,
        "created_at": time.time(),
        "updated_at": time.time(),
    }
    # Auto-send to provider when service has provider_service_id
    if svc.get("provider_service_id") and PROVIDER_API_URL and PROVIDER_API_KEY:
        result, perror = provider_request(
            "add",
            service=str(svc["provider_service_id"]),
            link=link,
            quantity=str(quantity),
        )
        if not perror and isinstance(result, dict):
            order["provider_order_id"] = result.get("order") or result.get("order_id")
            order["provider_raw"] = result
        elif perror:
            order["provider_error"] = perror

    data.setdefault("orders", []).append(order)
    return order, None, user


# ---------- wallet / Bakong ----------
def _get_khqr():
    global _khqr
    if _khqr is not None:
        return _khqr
    if not BAKONG_TOKEN:
        return None
    try:
        from bakong_khqr import KHQR

        _khqr = KHQR(BAKONG_TOKEN)
        return _khqr
    except Exception:
        return None


def _qr_image_b64(qr_string: str) -> str:
    try:
        import base64
        import io

        import qrcode

        img = qrcode.make(qr_string)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
    except Exception:
        return ""


@app.route("/api/deposit", methods=["POST"])
def deposit():
    data = load_db()
    user = current_user(data)
    if not user:
        return err("Not logged in", 401)
    body = request.get_json(silent=True) or {}
    try:
        amount = round(float(body.get("amount", 0)), 2)
    except (TypeError, ValueError):
        return err("Invalid amount")
    if amount < 0.5:
        return err("Minimum deposit $0.50")

    dep_id = next_id(data, "deposits")
    dep = {
        "id": dep_id,
        "user_id": user["id"],
        "amount": amount,
        "status": "pending",
        "created_at": time.time(),
        "md5": None,
    }

    qr_image = ""
    pay_hint = "Demo mode — set BAKONG_TOKEN to enable real KHQR"
    khqr = _get_khqr()
    if khqr and BAKONG_ACCOUNT_ID:
        try:
            kwargs = {
                "merchant_name": BAKONG_MERCHANT_NAME,
                "merchant_city": BAKONG_MERCHANT_CITY,
                "amount": amount,
                "currency": BAKONG_CURRENCY,
                "store_label": f"DEP{dep_id}",
                "bill_number": f"K{dep_id}",
            }
            qr_string = khqr.create_qr(bank_account=BAKONG_ACCOUNT_ID, **kwargs)
            md5 = hashlib.md5(qr_string.encode()).hexdigest()
            dep["md5"] = md5
            qr_image = _qr_image_b64(qr_string)
            _pending_qr[dep_id] = {
                "md5": md5,
                "amount": amount,
                "user_id": user["id"],
                "created": time.time(),
            }
            pay_hint = "Scan with any Bakong bank app"
        except Exception as e:
            pay_hint = f"KHQR error: {e}"
    else:
        # Demo: auto-credit after "check" for testing without Bakong
        dep["md5"] = f"demo-{dep_id}"
        _pending_qr[dep_id] = {
            "md5": dep["md5"],
            "amount": amount,
            "user_id": user["id"],
            "created": time.time(),
            "demo": True,
        }

    data.setdefault("deposits", []).append(dep)
    save_db(data)
    return ok(
        deposit_id=dep_id,
        amount=amount,
        qr_image=qr_image,
        hint=pay_hint,
        demo=not bool(khqr and BAKONG_ACCOUNT_ID),
    )


@app.route("/api/deposit/check", methods=["POST"])
def deposit_check():
    data = load_db()
    user = current_user(data)
    if not user:
        return err("Not logged in", 401)
    body = request.get_json(silent=True) or {}
    try:
        dep_id = int(body.get("deposit_id"))
    except (TypeError, ValueError):
        return err("Invalid deposit_id")

    dep = next((d for d in data.get("deposits", []) if d["id"] == dep_id and d["user_id"] == user["id"]), None)
    if not dep:
        return err("Deposit not found")
    if dep["status"] == "paid":
        return ok(paid=True, user=public_user(user))

    info = _pending_qr.get(dep_id)
    paid = False

    if info and info.get("demo"):
        # Demo auto-pay after 8 seconds
        if time.time() - info["created"] >= 8:
            paid = True
    elif info and info.get("md5"):
        khqr = _get_khqr()
        if khqr:
            try:
                # bakong-khqr check by md5
                status = khqr.check_payment(info["md5"])
                if status and str(status).upper() in ("PAID", "SUCCESS", "1", "TRUE"):
                    paid = True
            except Exception:
                pass

    if paid:
        dep["status"] = "paid"
        dep["paid_at"] = time.time()
        for u in data["users"]:
            if u["id"] == user["id"]:
                u["balance"] = round(float(u["balance"]) + float(dep["amount"]), 4)
                user = u
                break
        save_db(data)
        _pending_qr.pop(dep_id, None)
        return ok(paid=True, user=public_user(user))

    return ok(paid=False)


@app.route("/api/deposits")
def deposits_list():
    data = load_db()
    user = current_user(data)
    if not user:
        return err("Not logged in", 401)
    mine = [d for d in data.get("deposits", []) if d["user_id"] == user["id"]]
    mine.sort(key=lambda d: d.get("created_at", 0), reverse=True)
    return ok(deposits=mine[:50])



# ---------- admin helpers ----------
def require_admin_session():
    if not session.get("is_admin"):
        return err("Admin only", 401)
    return None


def provider_request(action: str, **params):
    """Call external SMM panel API (PerfectPanel-style form POST)."""
    if not PROVIDER_API_URL or not PROVIDER_API_KEY:
        return None, "Provider API not configured"
    try:
        import urllib.parse
        import urllib.request

        data = {"key": PROVIDER_API_KEY, "action": action, **params}
        body = urllib.parse.urlencode(data).encode()
        req = urllib.request.Request(
            PROVIDER_API_URL,
            data=body,
            headers={"User-Agent": "KairozenSMM/1.0", "Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        try:
            return json.loads(raw), None
        except json.JSONDecodeError:
            return {"raw": raw}, None
    except Exception as e:
        return None, str(e)


@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    body = request.get_json(silent=True) or {}
    if (body.get("username") or "") == ADMIN_USERNAME and (body.get("password") or "") == ADMIN_PASSWORD:
        session["is_admin"] = True
        session.pop("user_id", None)
        return ok(admin=True)
    return err("Invalid admin credentials", 401)


@app.route("/api/admin/logout", methods=["POST"])
def admin_logout():
    session.pop("is_admin", None)
    return ok()


@app.route("/api/admin/me")
def admin_me():
    if not session.get("is_admin"):
        return err("Admin only", 401)
    data = load_db()
    return ok(
        admin=True,
        stats={
            "users": len(data.get("users", [])),
            "orders": len(data.get("orders", [])),
            "deposits": len(data.get("deposits", [])),
            "services": len(data.get("services", [])),
            "provider_configured": bool(PROVIDER_API_URL and PROVIDER_API_KEY),
        },
        settings=data.get("settings", {}),
    )


@app.route("/api/admin/users")
def admin_users():
    if e := require_admin_session():
        return e
    data = load_db()
    rows = [
        {
            "id": u["id"],
            "username": u["username"],
            "email": u.get("email", ""),
            "balance": round(float(u.get("balance", 0)), 4),
            "created_at": u.get("created_at"),
        }
        for u in data.get("users", [])
    ]
    rows.sort(key=lambda r: r["id"], reverse=True)
    return ok(users=rows)


@app.route("/api/admin/users/balance", methods=["POST"])
def admin_set_balance():
    if e := require_admin_session():
        return e
    body = request.get_json(silent=True) or {}
    try:
        uid = int(body.get("user_id"))
        balance = round(float(body.get("balance")), 4)
    except (TypeError, ValueError):
        return err("Invalid user_id or balance")
    data = load_db()
    for u in data["users"]:
        if u["id"] == uid:
            u["balance"] = balance
            save_db(data)
            return ok(user=public_user(u))
    return err("User not found", 404)


@app.route("/api/admin/orders")
def admin_orders():
    if e := require_admin_session():
        return e
    data = load_db()
    orders = list(data.get("orders", []))
    orders.sort(key=lambda o: o.get("created_at", 0), reverse=True)
    users = {u["id"]: u["username"] for u in data.get("users", [])}
    for o in orders:
        o["username"] = users.get(o["user_id"], "?")
    return ok(orders=orders[:200])


@app.route("/api/admin/orders/status", methods=["POST"])
def admin_order_status():
    if e := require_admin_session():
        return e
    body = request.get_json(silent=True) or {}
    try:
        oid = int(body.get("order_id"))
    except (TypeError, ValueError):
        return err("Invalid order_id")
    status = (body.get("status") or "").strip().lower()
    if status not in ("processing", "completed", "partial", "canceled", "failed"):
        return err("Invalid status")
    data = load_db()
    for o in data.get("orders", []):
        if o["id"] == oid:
            o["status"] = status
            if status == "completed":
                o["remains"] = 0
            elif status in ("canceled", "failed"):
                o["remains"] = o.get("quantity", 0)
            o["updated_at"] = time.time()
            save_db(data)
            return ok(order=o)
    return err("Order not found", 404)


@app.route("/api/admin/deposits")
def admin_deposits():
    if e := require_admin_session():
        return e
    data = load_db()
    deps = list(data.get("deposits", []))
    deps.sort(key=lambda d: d.get("created_at", 0), reverse=True)
    users = {u["id"]: u["username"] for u in data.get("users", [])}
    for d in deps:
        d["username"] = users.get(d["user_id"], "?")
    return ok(deposits=deps[:200])


@app.route("/api/admin/deposits/confirm", methods=["POST"])
def admin_deposit_confirm():
    """Manually mark a pending deposit as paid and credit the user."""
    if e := require_admin_session():
        return e
    body = request.get_json(silent=True) or {}
    try:
        dep_id = int(body.get("deposit_id"))
    except (TypeError, ValueError):
        return err("Invalid deposit_id")
    data = load_db()
    dep = next((d for d in data.get("deposits", []) if d["id"] == dep_id), None)
    if not dep:
        return err("Deposit not found", 404)
    if dep.get("status") == "paid":
        return ok(deposit=dep, already=True)
    dep["status"] = "paid"
    dep["paid_at"] = time.time()
    dep["manual"] = True
    user = None
    for u in data["users"]:
        if u["id"] == dep["user_id"]:
            u["balance"] = round(float(u["balance"]) + float(dep["amount"]), 4)
            user = u
            break
    save_db(data)
    _pending_qr.pop(dep_id, None)
    return ok(deposit=dep, user=public_user(user) if user else None)


@app.route("/api/admin/services", methods=["GET", "POST", "PUT", "DELETE"])
def admin_services():
    if e := require_admin_session():
        return e
    data = load_db()
    if request.method == "GET":
        return ok(services=data.get("services", []))

    body = request.get_json(silent=True) or {}
    if request.method == "POST":
        svc = {
            "id": max([s["id"] for s in data.get("services", [])] or [0]) + 1,
            "category": (body.get("category") or "Other").strip(),
            "name": (body.get("name") or "").strip(),
            "rate": float(body.get("rate") or 0),
            "min": int(body.get("min") or 100),
            "max": int(body.get("max") or 10000),
            "refill": bool(body.get("refill")),
            "provider_service_id": body.get("provider_service_id") or None,
        }
        if not svc["name"]:
            return err("Name required")
        data.setdefault("services", []).append(svc)
        save_db(data)
        return ok(service=svc)

    if request.method == "PUT":
        try:
            sid = int(body.get("id"))
        except (TypeError, ValueError):
            return err("Invalid id")
        for s in data.get("services", []):
            if s["id"] == sid:
                for k in ("category", "name", "rate", "min", "max", "refill", "provider_service_id"):
                    if k in body:
                        s[k] = body[k]
                s["rate"] = float(s["rate"])
                s["min"] = int(s["min"])
                s["max"] = int(s["max"])
                save_db(data)
                return ok(service=s)
        return err("Not found", 404)

    # DELETE
    try:
        sid = int(request.args.get("id") or body.get("id"))
    except (TypeError, ValueError):
        return err("Invalid id")
    data["services"] = [s for s in data.get("services", []) if s["id"] != sid]
    save_db(data)
    return ok()


@app.route("/api/admin/settings", methods=["GET", "POST"])
def admin_settings():
    if e := require_admin_session():
        return e
    data = load_db()
    if request.method == "GET":
        return ok(settings=data.get("settings", {}))
    body = request.get_json(silent=True) or {}
    s = data.setdefault("settings", {})
    for k in ("SITE_NAME", "LOGO_URL", "TELEGRAM_LINK", "SUPPORT_EMAIL", "CURRENCY"):
        if k in body:
            s[k] = body[k]
    save_db(data)
    return ok(settings=s)


@app.route("/api/admin/provider/services")
def admin_provider_services():
    if e := require_admin_session():
        return e
    result, error = provider_request("services")
    if error:
        return err(error)
    return ok(provider_services=result if isinstance(result, list) else result)


@app.route("/api/admin/services/seed-defaults", methods=["POST"])
def admin_services_seed_defaults():
    """Add any starter services from db_default.json that are missing from the
    LIVE database (matched by name) — never touches existing users, orders,
    deposits or services. Safe to run any time, e.g. after a code update."""
    if e := require_admin_session():
        return e
    if not DEFAULT_DB.exists():
        return err("db_default.json not found next to server.py")
    try:
        defaults = json.loads(DEFAULT_DB.read_text(encoding="utf-8"))
    except Exception as ex:
        return err(f"Could not read db_default.json: {ex}")

    data = load_db()
    services_list = data.setdefault("services", [])
    existing_names = {(s.get("name") or "").strip().lower() for s in services_list}
    next_local_id = max([s["id"] for s in services_list] or [0]) + 1

    added = 0
    for svc in defaults.get("services", []):
        name = (svc.get("name") or "").strip()
        if not name or name.lower() in existing_names:
            continue
        new_svc = {
            "id": next_local_id,
            "category": svc.get("category", "Other"),
            "name": name,
            "rate": float(svc.get("rate", 1)),
            "min": int(svc.get("min", 100)),
            "max": int(svc.get("max", 10000)),
            "refill": bool(svc.get("refill", False)),
            "provider_service_id": svc.get("provider_service_id"),
        }
        services_list.append(new_svc)
        existing_names.add(name.lower())
        next_local_id += 1
        added += 1

    save_db(data)
    return ok(added=added, total=len(services_list))


@app.route("/api/admin/provider/import", methods=["POST"])
def admin_provider_import():
    """Bulk-import chosen services from the upstream provider's catalogue,
    applying a markup so our sell rate is above the provider's cost rate."""
    if e := require_admin_session():
        return e
    body = request.get_json(silent=True) or {}
    items = body.get("items") or []
    if not isinstance(items, list) or not items:
        return err("No items to import")
    try:
        markup_percent = float(body.get("markup_percent", 20))
    except (TypeError, ValueError):
        markup_percent = 20.0

    data = load_db()
    services_list = data.setdefault("services", [])
    by_provider_id = {str(s.get("provider_service_id")): s for s in services_list if s.get("provider_service_id")}
    next_local_id = max([s["id"] for s in services_list] or [0]) + 1

    imported, updated = 0, 0
    for item in items:
        provider_sid = str(item.get("service") or item.get("id") or "").strip()
        if not provider_sid:
            continue
        try:
            base_rate = float(item.get("rate") or 0)
        except (TypeError, ValueError):
            base_rate = 0.0
        sell_rate = round(base_rate * (1 + markup_percent / 100.0), 4)
        try:
            min_qty = int(float(item.get("min") or 100))
            max_qty = int(float(item.get("max") or 10000))
        except (TypeError, ValueError):
            min_qty, max_qty = 100, 10000
        name = (item.get("name") or "").strip() or f"Provider service {provider_sid}"
        category = (item.get("category") or "Other").strip()

        existing = by_provider_id.get(provider_sid)
        if existing:
            existing["name"] = name
            existing["category"] = category
            existing["rate"] = sell_rate
            existing["min"] = min_qty
            existing["max"] = max_qty
            updated += 1
        else:
            svc = {
                "id": next_local_id,
                "category": category,
                "name": name,
                "rate": sell_rate,
                "min": min_qty,
                "max": max_qty,
                "refill": bool(item.get("refill")),
                "provider_service_id": provider_sid,
            }
            services_list.append(svc)
            by_provider_id[provider_sid] = svc
            next_local_id += 1
            imported += 1

    save_db(data)
    return ok(imported=imported, updated=updated, total=len(services_list))


@app.route("/api/admin/provider/sync", methods=["POST"])
def admin_provider_sync():
    """Fetch the full catalogue from the upstream provider and sync into our local
    services. Existing services matched by provider_service_id get rates/min/max/
    name/category refreshed (with markup). Optionally import brand-new services
    that we don't have yet (import_new=true)."""
    if e := require_admin_session():
        return e
    if not PROVIDER_API_URL or not PROVIDER_API_KEY:
        return err("Provider API not configured (set PROVIDER_API_URL + PROVIDER_API_KEY)")

    body = request.get_json(silent=True) or {}
    try:
        markup_percent = float(body.get("markup_percent", 20))
    except (TypeError, ValueError):
        markup_percent = 20.0
    import_new = bool(body.get("import_new", True))

    result, error = provider_request("services")
    if error:
        return err(error)
    if not isinstance(result, list):
        return err("Provider did not return a services list")

    data = load_db()
    services_list = data.setdefault("services", [])
    by_provider_id = {
        str(s.get("provider_service_id")): s
        for s in services_list
        if s.get("provider_service_id")
    }
    next_local_id = max([s["id"] for s in services_list] or [0]) + 1

    updated, imported, skipped = 0, 0, 0
    for item in result:
        provider_sid = str(item.get("service") or item.get("id") or "").strip()
        if not provider_sid:
            continue
        try:
            base_rate = float(item.get("rate") or 0)
        except (TypeError, ValueError):
            base_rate = 0.0
        sell_rate = round(base_rate * (1 + markup_percent / 100.0), 4)
        try:
            min_qty = int(float(item.get("min") or 100))
            max_qty = int(float(item.get("max") or 10000))
        except (TypeError, ValueError):
            min_qty, max_qty = 100, 10000
        name = (item.get("name") or "").strip() or f"Provider service {provider_sid}"
        category = (item.get("category") or "Other").strip()
        refill = bool(item.get("refill"))

        existing = by_provider_id.get(provider_sid)
        if existing:
            existing["name"] = name
            existing["category"] = category
            existing["rate"] = sell_rate
            existing["min"] = min_qty
            existing["max"] = max_qty
            existing["refill"] = refill
            updated += 1
        elif import_new:
            svc = {
                "id": next_local_id,
                "category": category,
                "name": name,
                "rate": sell_rate,
                "min": min_qty,
                "max": max_qty,
                "refill": refill,
                "provider_service_id": provider_sid,
            }
            services_list.append(svc)
            by_provider_id[provider_sid] = svc
            next_local_id += 1
            imported += 1
        else:
            skipped += 1

    save_db(data)
    return ok(
        updated=updated,
        imported=imported,
        skipped=skipped,
        total=len(services_list),
        provider_count=len(result),
        markup_percent=markup_percent,
    )


@app.route("/api/admin/orders/send-provider", methods=["POST"])
def admin_send_provider():
    """Push a local order to the external SMM provider."""
    if e := require_admin_session():
        return e
    body = request.get_json(silent=True) or {}
    try:
        oid = int(body.get("order_id"))
    except (TypeError, ValueError):
        return err("Invalid order_id")
    data = load_db()
    order = next((o for o in data.get("orders", []) if o["id"] == oid), None)
    if not order:
        return err("Order not found", 404)
    svc = next((s for s in data.get("services", []) if s["id"] == order["service_id"]), None)
    provider_sid = (svc or {}).get("provider_service_id") or body.get("provider_service_id")
    if not provider_sid:
        return err("Set provider_service_id on the service first")
    result, error = provider_request(
        "add",
        service=str(provider_sid),
        link=order["link"],
        quantity=str(order["quantity"]),
    )
    if error:
        return err(error)
    # PerfectPanel returns {"order": 123}
    external_id = None
    if isinstance(result, dict):
        external_id = result.get("order") or result.get("order_id")
    order["provider_order_id"] = external_id
    order["provider_raw"] = result
    order["status"] = "processing"
    order["updated_at"] = time.time()
    save_db(data)
    return ok(order=order, provider=result)


@app.route("/api/admin/orders/sync-provider", methods=["POST"])
def admin_sync_provider():
    if e := require_admin_session():
        return e
    body = request.get_json(silent=True) or {}
    try:
        oid = int(body.get("order_id"))
    except (TypeError, ValueError):
        return err("Invalid order_id")
    data = load_db()
    order = next((o for o in data.get("orders", []) if o["id"] == oid), None)
    if not order:
        return err("Order not found", 404)
    if not order.get("provider_order_id"):
        return err("Order not sent to provider yet")
    result, error = provider_request("status", order=str(order["provider_order_id"]))
    if error:
        return err(error)
    if isinstance(result, dict):
        st = (result.get("status") or "").lower()
        mapping = {
            "completed": "completed",
            "partial": "partial",
            "canceled": "canceled",
            "cancelled": "canceled",
            "fail": "failed",
            "failed": "failed",
            "pending": "processing",
            "in progress": "processing",
            "processing": "processing",
        }
        if st in mapping:
            order["status"] = mapping[st]
        if "remains" in result:
            try:
                order["remains"] = int(result["remains"])
            except (TypeError, ValueError):
                pass
        if "start_count" in result:
            try:
                order["start_count"] = int(result["start_count"])
            except (TypeError, ValueError):
                pass
        order["provider_status"] = result
        order["updated_at"] = time.time()
        save_db(data)
    return ok(order=order, provider=result)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5055))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1" and not os.environ.get("RENDER")
    print(f"Kairozen SMM → http://0.0.0.0:{port}  db={DB_PATH}")
    app.run(host="0.0.0.0", port=port, debug=debug)
