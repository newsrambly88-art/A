#!/usr/bin/env python3
"""
af_event_builder.py — build an AppsFlyer iOS event payload (encrypted body + cksm_v2)
from a decrypted template, then optionally POST it to the live AF endpoint.

Wire format reproduced from real captures:
    POST https://{host}/api/v{major.minor}/iosevent?app_id={itunes_id}&buildnumber={sdk}
    Content-Type: application/octet-stream
    <ciphertext || IV(16) || salt(8)>          # NOT gzipped
    -> 200 "ok"

Recipe provenance (all CONFIRMED against real captures, 29/29):
  - cksm_v2 prefix: hex( HMAC-SHA256(key=uid, data=swap_pairs(AFSDKVersion
    + timestamp + systemversion + firstLaunchDate)) )[:16]
    (AFSDKChecksum 6.17.8, @0x7c10 / _afsdk_swap @0x7aac / _hmacForKeyAndData @0x35d18)
  - cksm_v2 suffix: hex( utf8("s{sim}&d{dev}&j{jail}&c{counterValid}&d{debugger}")
    XOR "*+" alternating )      (+AFSDKChecksum xor: @0x7ff0, key "*+")
  - AES key: PBKDF2-HMAC-SHA1(dev_key, salt = 8 zero bytes, 10000 iters, 16 bytes)
  - body: AES-128-CBC/PKCS7(ciphertext || IV(16) || salt(8)), key from dev_key
  - plaintext serialization: NSJSONSerialization-style — compact, keys in template
    order, "/" escaped as "\\/" (AF quirk)

Usage:
  python3 af_event_builder.py --event "SignIn" --verify
  python3 af_event_builder.py --event "SignIn" --send --app-id 1538601072
  python3 af_event_builder.py --event "SignIn" --send \
      --url 'https://86jplf.inapps.appsflyersdk.com/api/v6.17/iosevent?app_id=6471983323&buildnumber=6.17.8' \
      --fresh-time --bump-counter
  python3 af_event_builder.py --event "SignUp" --event-value '{"method":"email"}' \
      --send --app-id 1538601072 --fresh-time --bump-counter
  python3 af_event_builder.py --event "SignIn" --send --app-id 1538601072 --dry-run
  python3 af_event_builder.py --event "Level" --template other.json --dev-key KEY --out body.bin

Flags of note:
  --send        actually POST (default stays local-only)
  --url         full endpoint URL; overrides --host/--app-id and the path version
                + buildnumber derived from --af-sdk-version
  --host        override endpoint host (e.g. 86jplf.inapps.appsflyersdk.com)
  --gzip        gzip the plaintext before encryption (opt-in; real SDK doesn't)
  --insecure    skip TLS verification (MITM proxies)
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import hmac
import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

DEFAULT_TEMPLATE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "af_ios_event_template.json")

DEFAULT_HOST = "inapps.appsflyer.com"          # launches.appsflyer.com for install/launch events
DEFAULT_LANG = "en"


# ---------------------------------------------------------------- cksm_v2 ----
def _swap_pairs(s: str) -> str:
    b = list(s)
    for i in range(0, len(b) - 1, 2):
        b[i], b[i + 1] = b[i + 1], b[i]
    return "".join(b)


def _xor_starplus(s: str) -> str:
    key = b"*+"
    b = s.encode()
    return bytes(b[i] ^ key[i % 2] for i in range(len(b))).hex()


def compute_cksm_v2(uid, af_sdk_version, timestamp, systemversion,
                    first_launch_date, sim=0, dev=0, jail=0,
                    counter_valid=1, debugger=0) -> str:
    msg = _swap_pairs(af_sdk_version + timestamp + systemversion + first_launch_date)
    prefix = hmac.new(uid.encode(), msg.encode(), hashlib.sha256).hexdigest()[:16]
    flags = f"s{sim}&d{dev}&j{jail}&c{counter_valid}&d{debugger}"
    return prefix + _xor_starplus(flags)


def cksm_from_body(body: dict, af_sdk_version: str) -> str:
    """Recompute cksm_v2 from the fields inside a (captured) plaintext body."""
    return compute_cksm_v2(
        uid=body["uid"],
        af_sdk_version=af_sdk_version,
        timestamp=body["timestamp"],
        systemversion=body["systemversion"],
        first_launch_date=body["firstLaunchDate"],
    )


AF_SDK_VERSION_HINTS = ("6.17.7", "6.17.8", "6.17.9", "6.17.91",
                        "6.18.0", "6.18.1", "6.16.2")


def verify_candidates(primary: str) -> list:
    """Try the requested AFSDKVersion first, then nearby releases."""
    seen = [primary]
    for v in AF_SDK_VERSION_HINTS:
        if v not in seen:
            seen.append(v)
    return seen


# ------------------------------------------------------------- encryption ----
def derive_aes_key(dev_key: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha1", dev_key.encode(), b"\x00" * 8, 10000, dklen=16)


def _pkcs7_pad(data: bytes) -> bytes:
    p = 16 - (len(data) % 16)
    return data + bytes([p]) * p


def _af_serialize(obj, top=True) -> str:
    """NSJSONSerialization-style: compact, '/' escaped as '\\/' (AF quirk)."""
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, str):
        out = json.dumps(obj)          # standard JSON string escaping
        return out.replace("/", "\\/")
    if isinstance(obj, (int, float)):
        return json.dumps(obj)
    if isinstance(obj, dict):
        inner = ",".join(f"{_af_serialize(str(k), False)}:{_af_serialize(v, False)}"
                         for k, v in obj.items())
        return "{" + inner + "}"
    if isinstance(obj, list):
        return "[" + ",".join(_af_serialize(v, False) for v in obj) + "]"
    raise TypeError(f"unserializable: {type(obj)}")


def encrypt_body(plaintext_json: str, dev_key: str, use_gzip: bool = False) -> bytes:
    key = derive_aes_key(dev_key)
    iv = os.urandom(16)
    salt = b"\x00" * 8                      # AF uses a fixed zero salt
    payload = plaintext_json.encode()
    if use_gzip:
        payload = gzip.compress(payload, mtime=0)
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = enc.update(_pkcs7_pad(payload)) + enc.finalize()
    return ct + iv + salt


def decrypt_body(body: bytes, dev_key: str, use_gzip: bool = False) -> str:
    key = derive_aes_key(dev_key)
    ct, iv = body[:-24], body[-24:-8]
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    pad_len = padded[-1] if padded else 0
    raw = padded[:-pad_len] if 0 < pad_len <= 16 else padded
    if use_gzip:
        raw = gzip.decompress(raw)
    return raw.decode()


# ---------------------------------------------------------------- counter ----
def _counter_path(template_path: str) -> str:
    return os.path.join(os.path.dirname(os.path.abspath(template_path)),
                        ".af_counters.json")


def _bump_counter(body: dict, template_path: str) -> None:
    """Increment and PERSIST counter/iaecounter per template.

    The template is a pristine capture and is never rewritten, so the live
    values have to live in a sidecar or every run restarts at the same number.
    """
    path = _counter_path(template_path)
    key = os.path.basename(template_path)
    try:
        with open(path) as f:
            state = json.load(f)
        if not isinstance(state, dict):
            state = {}
    except (OSError, ValueError):
        state = {}

    cur = state.get(key) or {}
    counter = int(cur.get("counter", body.get("counter") or 0)) + 1
    iae = int(cur.get("iaecounter", body.get("iaecounter") or 0)) + 1

    body["counter"] = str(counter)
    body["iaecounter"] = str(iae)
    state[key] = {"counter": counter, "iaecounter": iae}
    try:
        with open(path, "w") as f:
            json.dump(state, f, indent=2, sort_keys=True)
    except OSError as e:
        print(f"warning: counter not persisted ({e})", file=sys.stderr)


# ------------------------------------------------------------------ build ----
def build(event_name: str, template_path: str, dev_key: str | None,
          event_value: str | None, fresh_time: bool, bump_counter: bool,
          af_sdk_version: str, use_gzip: bool = False,
          clear_event_value: bool = False) -> tuple[dict, bytes, str]:
    with open(template_path) as f:
        body = json.load(f)

    if fresh_time:
        import datetime
        now = datetime.datetime.now().astimezone()
        body["timestamp"] = f"{time.time():.6f}"
        body["af_timestamp"] = str(int(time.time() * 1000))
        body["date2"] = now.strftime("%Y-%m-%d_%H%M%S%z")
    if bump_counter:
        _bump_counter(body, template_path)

    body["event"] = event_name
    body["eventName"] = event_name

    # eventvalue is resolved to its FINAL state before cksm_v2 is computed and
    # before serialization, so the signed bytes always match the wire bytes.
    if clear_event_value and event_value is not None:
        print("warning: --clear-event-value wins over --event-value", file=sys.stderr)
    if clear_event_value:
        body.pop("eventvalue", None)
    elif event_value is not None:
        parsed = json.loads(event_value) if event_value.strip().startswith(("{", "[")) else event_value
        body["eventvalue"] = urllib.parse.quote(
            json.dumps(parsed, separators=(",", ":")) if not isinstance(parsed, str)
            else parsed, safe="")

    if dev_key:
        body["dev_key"] = dev_key
    if not body.get("dev_key"):
        raise SystemExit("no dev_key: pass --dev-key or set dev_key in the template")

    body["cksm_v2"] = cksm_from_body(body, af_sdk_version)

    plaintext = _af_serialize(body)
    encrypted = encrypt_body(plaintext, body["dev_key"], use_gzip)
    return body, encrypted, plaintext


# ------------------------------------------------------------------- send ----
def build_url(host: str, app_id: str, af_sdk_version: str) -> str:
    major_minor = ".".join(af_sdk_version.split(".")[:2])
    return ("https://{}/api/v{}/iosevent?app_id={}&buildnumber={}"
            .format(host, major_minor,
                    urllib.parse.quote(app_id, safe=""),
                    urllib.parse.quote(af_sdk_version, safe="")))


def _request_headers(body: dict, ua: str | None, lang: str) -> dict:
    bundle = body.get("bundleIdentifier") or "App"
    build_no = body.get("app_version_code") or body.get("buildNumber") or "1"
    return {
        "Content-Type": "application/octet-stream",
        "Accept": "*/*",
        "Accept-Language": lang,
        "Accept-Encoding": "gzip, deflate",
        "User-Agent": ua or f"{bundle}/{build_no} CFNetwork/1237 Darwin/20.6.0",
    }


def _read(resp) -> str:
    raw = resp.read()
    if "gzip" in (resp.headers.get("Content-Encoding") or "").lower():
        try:
            raw = gzip.decompress(raw)
        except Exception:
            pass
    return raw.decode("utf-8", "replace")


def send_payload(url: str, payload: bytes, headers: dict, timeout: float,
                 retries: int, insecure: bool = False) -> tuple[int, str]:
    ctx = ssl._create_unverified_context() if insecure else None
    last_err = None
    for attempt in range(1, retries + 1):
        req = urllib.request.Request(url, data=payload, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return resp.status, _read(resp)
        except urllib.error.HTTPError as e:          # 4xx/5xx still carry a body
            return e.code, _read(e)
        except (urllib.error.URLError, socket.timeout) as e:
            last_err = e
            if attempt < retries:
                time.sleep(1.5 * attempt)
    raise last_err


# -------------------------------------------------------------------- cli ----
def main():
    ap = argparse.ArgumentParser(
        description="Build an AF iOS event payload; optionally POST it to the live API.")
    ap.add_argument("--event", help="event name, e.g. SignIn (required unless --verify)")
    ap.add_argument("--event-value", help='JSON or string event value; default keeps template')
    ap.add_argument("--event-value-file", metavar="PATH",
                    help="read the event value from a file (no shell escaping)")
    ap.add_argument("--template", default=DEFAULT_TEMPLATE, help="decrypted-body JSON template")
    ap.add_argument("--dev-key", help="override dev key (else template's dev_key)")
    ap.add_argument("--af-sdk-version", default="6.17.8", help="AFSDKVersion for cksm message")
    ap.add_argument("--fresh-time", action="store_true", help="set timestamp/af_timestamp/date2 to now")
    ap.add_argument("--bump-counter", action="store_true", help="increment counter/iaecounter")
    ap.add_argument("--gzip", action="store_true", help="gzip plaintext before encrypting")
    ap.add_argument("--clear-event-value", action="store_true",
                    help="omit eventvalue entirely")
    ap.add_argument("--out", help="write encrypted body to file (octet-stream)")

    ap.add_argument("--send", action="store_true", help="actually POST to AppsFlyer")
    ap.add_argument("--app-id", help="iTunes app id, digits only (required with --send)")
    ap.add_argument("--host", default=DEFAULT_HOST, help=f"endpoint host (default {DEFAULT_HOST})")
    ap.add_argument("--url", help="full endpoint URL; overrides --host/--app-id and the "
                                  "path version + buildnumber derived from --af-sdk-version")
    ap.add_argument("--user-agent", help="override User-Agent")
    ap.add_argument("--accept-language", default=DEFAULT_LANG, help="Accept-Language header")
    ap.add_argument("--timeout", type=float, default=20.0, help="per-attempt timeout, seconds")
    ap.add_argument("--retries", type=int, default=3, help="attempts on network error")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification")
    ap.add_argument("--dry-run", action="store_true", help="with --send: print request, send nothing")

    ap.add_argument("--verify", action="store_true",
                    help="recompute cksm_v2 from untouched template and compare to captured value")
    args = ap.parse_args()

    if args.event_value_file:
        if args.event_value:
            ap.error("use either --event-value or --event-value-file, not both")
        if not os.path.isfile(args.event_value_file):
            ap.error(f"event value file not found: {args.event_value_file}")
        with open(args.event_value_file, encoding="utf-8") as f:
            args.event_value = f.read().strip()

    # cksm_v2 signs the AFSDKVersion the server reads off the URL, so a --url
    # buildnumber always wins over --af-sdk-version.
    if args.url:
        _bn = urllib.parse.parse_qs(
            urllib.parse.urlsplit(args.url).query).get("buildnumber", [""])[0]
        if _bn and _bn != args.af_sdk_version:
            print(f"note: cksm_v2 AFSDKVersion = URL buildnumber {_bn} "
                  f"(overrides --af-sdk-version {args.af_sdk_version})", file=sys.stderr)
            args.af_sdk_version = _bn

    if not args.verify and not args.event:
        ap.error("--event is required (unless --verify)")

    if not os.path.isfile(args.template):
        ap.error(f"template not found: {args.template}")

    if args.verify:
        with open(args.template) as f:
            captured = json.load(f)
        expect = captured.get("cksm_v2")
        matched = None
        for _v in verify_candidates(args.af_sdk_version):
            if expect is not None and cksm_from_body(captured, _v) == expect:
                matched = _v
                break
        ok = matched is not None
        recomputed = cksm_from_body(captured, matched or args.af_sdk_version)
        print(f"captured  : {expect}")
        print(f"recomputed: {recomputed}")
        if matched and matched != args.af_sdk_version:
            print(f"note: matched with AFSDKVersion {matched} "
                  f"(not {args.af_sdk_version}); pass --af-sdk-version {matched}")
        print("MATCH" if ok else "MISMATCH")
        sys.exit(0 if ok else 1)

    if args.send and not (args.url or args.app_id):
        ap.error("--app-id (or a full --url) is required with --send")

    body, encrypted, plaintext = build(
        args.event, args.template, args.dev_key, args.event_value,
        args.fresh_time, args.bump_counter, args.af_sdk_version, args.gzip,
        args.clear_event_value,
    )

    print(f"[{'live send' if args.send and not args.dry_run else 'local build only — nothing sent'}]")
    print(f"event          : {body['event']}")
    print(f"eventvalue     : {body.get('eventvalue') or '<omitted>'}")
    print(f"uid            : {body['uid']}")
    print(f"cksm_v2        : {body['cksm_v2']}")
    print(f"plaintext {len(plaintext)} B, encrypted body {len(encrypted)} B (ct+IV16+salt8)")

    if args.out:
        with open(args.out, "wb") as f:
            f.write(encrypted)
        print(f"encrypted body -> {args.out}")
        roundtrip = decrypt_body(encrypted, body["dev_key"], args.gzip)
        print("round-trip decrypt:", "OK" if roundtrip == plaintext else "FAIL")
        if roundtrip != plaintext:
            sys.exit(1)

    if not args.send:
        return

    url = args.url or build_url(args.host, args.app_id, args.af_sdk_version)
    if not url.lower().startswith("https://"):
        print(f"warning: non-https endpoint: {url}", file=sys.stderr)

    parsed = urllib.parse.urlsplit(url)
    headers = _request_headers(body, args.user_agent, args.accept_language)

    print(f"\nPOST {parsed.path}?{parsed.query}")
    print(f"  Host: {parsed.netloc}")
    for k, v in headers.items():
        print(f"  {k}: {v}")
    print(f"  Content-Length: {len(encrypted)}")

    qs = urllib.parse.parse_qs(parsed.query)
    if qs.get("buildnumber", [""])[0] not in ("", args.af_sdk_version):
        print(f"warning: URL buildnumber={qs['buildnumber'][0]} != "
              f"--af-sdk-version={args.af_sdk_version}; cksm_v2 will not match the "
              f"version the server sees", file=sys.stderr)

    if args.dry_run:
        print("\n[dry run — request not sent]")
        return

    try:
        status, text = send_payload(url, encrypted, headers, args.timeout,
                                    args.retries, args.insecure)
    except Exception as e:
        print(f"\nSEND FAILED: {type(e).__name__}: {e}")
        sys.exit(1)

    print(f"\nHTTP {status}")
    print(f"response: {text.strip()[:2000]}")
    ok = 200 <= status < 300
    print("OK" if ok else "REJECTED")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()