from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import threading
import time
import uuid
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor

import requests
import urllib3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from flask import Flask, g, request
from werkzeug.exceptions import HTTPException

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ[name])
    except (KeyError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ[name])
    except (KeyError, ValueError):
        return default


CLIENT_SECRET = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
APP_ID = 100067

OAUTH_URL = "https://100067.connect.garena.com/oauth/guest/token/grant"
INSPECT_URL = "https://100067.connect.garena.com/oauth/token/inspect"
RESOLVER_URL = "https://version.ggwhitehawk.com/live/ver.php"
PLAY_APP_ID = "com.dts.freefireth"

UNITY_VERSION = "2018.4.12f1"
USER_AGENT = "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)"

# LOWERED TIMEOUTS FOR VERCEL (10s max limit)
REQUEST_TIMEOUT = _env_float("REQUEST_TIMEOUT", 3.5)
LOGIN_TIMEOUT = _env_float("LOGIN_TIMEOUT", 4.0)
UPSTREAM_RETRIES = _env_int("UPSTREAM_RETRIES", 1)
RETRY_BACKOFF = _env_float("RETRY_BACKOFF", 0.3)

LIVE_CONFIG_TTL = _env_int("LIVE_CONFIG_TTL", 1800)
LIVE_CONFIG_TIMEOUT = _env_float("LIVE_CONFIG_TIMEOUT", 3.0)

TOKEN_CACHE_TTL = _env_int("TOKEN_CACHE_TTL", 300)
TOKEN_CACHE_MAX = _env_int("TOKEN_CACHE_MAX", 5000)

AES_KEY = b"Yg&tc%DEuh6%Zc^8"
AES_IV = b"6oyZDr22E3ychjM%"

PROTOBUF_OFFSETS = (0, 64, 128, 256)
PLATFORM_ORDER = (4, 3, 1, 5, 6, 8, 11, 13, 2, 7, 9)

FALLBACK_RELEASE_VERSION = "OB55"
FALLBACK_CLIENT_VERSION = "1.132.10"
FALLBACK_SERVER_URL = "https://loginbp.ppmainecoonghj.com"


logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)-7s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("jwt")


class ApiError(Exception):
    def __init__(self, code: str, message: str, http: int = 400, details=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.http = http
        self.details = details


def _json(body: dict, status: int = 200):
    return app.response_class(
        json.dumps(body, indent=2, ensure_ascii=False),
        status=status,
        mimetype="application/json",
    )


def ok(payload: dict):
    return _json({"success": True, **payload})


def fail(code: str, message: str, http: int = 400, details=None):
    body = {"success": False, "error": {"code": code, "message": message}}
    if details:
        body["error"]["details"] = details
    return _json(body, http)


def _varint(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        out.append(b | 0x80 if v else b)
        if not v:
            return bytes(out)


def _fvarint(field: int, value: int) -> bytes:
    return _varint((field << 3) | 0) + _varint(value)


def _fbytes(field: int, value) -> bytes:
    b = value.encode("utf-8") if isinstance(value, str) else bytes(value)
    return _varint((field << 3) | 2) + _varint(len(b)) + b


def encode_protobuf(fields: dict) -> bytes:
    out = bytearray()
    for f in sorted(fields):
        v = fields[f]
        if isinstance(v, bool):
            out.extend(_fvarint(f, int(v)))
        elif isinstance(v, int):
            out.extend(_fvarint(f, v))
        elif isinstance(v, (str, bytes, bytearray)):
            if len(v) == 0:
                continue
            out.extend(_fbytes(f, v))
        else:
            out.extend(_fbytes(f, str(v)))
    return bytes(out)


def _rvarint(buf: bytes, pos: int):
    v = s = 0
    while pos < len(buf):
        b = buf[pos]
        pos += 1
        v |= (b & 0x7F) << s
        if not (b & 0x80):
            return v, pos
        s += 7
        if s > 63:
            raise ValueError("varint")
    raise ValueError("eof")


def decode_protobuf(data: bytes) -> dict:
    out = {}
    pos = 0
    while pos < len(data):
        try:
            key, pos = _rvarint(data, pos)
        except Exception:
            break
        field = key >> 3
        wire = key & 7
        if field == 0:
            break
        try:
            if wire == 0:
                v, pos = _rvarint(data, pos)
            elif wire == 1:
                v = data[pos:pos + 8].hex(); pos += 8
            elif wire == 2:
                ln, pos = _rvarint(data, pos)
                if pos + ln > len(data):
                    break
                raw = data[pos:pos + ln]; pos += ln
                try:
                    v = raw.decode("utf-8")
                except Exception:
                    v = raw.hex()
            elif wire == 5:
                v = data[pos:pos + 4].hex(); pos += 4
            else:
                break
        except Exception:
            break
        if field in out:
            out[field] = out[field] + [v] if isinstance(out[field], list) else [out[field], v]
        else:
            out[field] = v
    return out


_JWT_RE = re.compile(rb"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")


def is_jwt(value) -> bool:
    if isinstance(value, (bytes, bytearray)):
        try:
            value = value.decode("utf-8", "ignore")
        except Exception:
            return False
    if not isinstance(value, str):
        return False
    return value.count(".") == 2 and value.startswith("eyJ") and len(value) > 60


def find_jwt_in_bytes(content: bytes):
    m = _JWT_RE.search(content)
    return m.group(0).decode("utf-8", "ignore") if m else None


def _unwrap_jwt(value):
    if isinstance(value, list):
        value = value[0] if value else ""
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "ignore")
    return value


def decode_jwt_payload(token: str) -> dict:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        p = parts[1]
        p += "=" * (-len(p) % 4)
        return json.loads(base64.urlsafe_b64decode(p))
    except Exception:
        return {}


def aes_encrypt(plain: bytes) -> bytes:
    return AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(pad(plain, AES.block_size))


_session = requests.Session()


def http_request(method: str, url: str, retries: int = UPSTREAM_RETRIES, **kwargs):
    kwargs.setdefault("timeout", REQUEST_TIMEOUT)
    kwargs.setdefault("verify", False)
    last = None
    for attempt in range(max(1, retries)):
        try:
            r = _session.request(method, url, **kwargs)
            if r.status_code < 500:
                return r
            last = r
        except requests.RequestException as e:
            last = e
        if attempt < retries - 1:
            time.sleep(RETRY_BACKOFF * (attempt + 1))
    if isinstance(last, Exception):
        raise last
    return last


class TTLCache:
    def __init__(self, max_size: int, ttl: float):
        self._max = max_size
        self._ttl = ttl
        self._data: OrderedDict = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            ts, val = entry
            if time.monotonic() - ts > self._ttl:
                self._data.pop(key, None)
                return None
            self._data.move_to_end(key)
            return val

    def set(self, key, value):
        with self._lock:
            self._data[key] = (time.monotonic(), value)
            self._data.move_to_end(key)
            while len(self._data) > self._max:
                self._data.popitem(last=False)

    def __len__(self):
        return len(self._data)


class LiveConfig:
    def __init__(self):
        self.release_version = FALLBACK_RELEASE_VERSION
        self.client_version = FALLBACK_CLIENT_VERSION
        self.server_url = FALLBACK_SERVER_URL
        self.fetched_at = 0.0
        self.source = "static"
        self._lock = threading.Lock()
        self._fetching = False

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "release_version": self.release_version,
                "client_version": self.client_version,
                "server_url": self.server_url,
                "fetched_at": self.fetched_at,
                "source": self.source,
            }

    def get(self) -> dict:
        if time.time() - self.fetched_at < LIVE_CONFIG_TTL:
            return self.snapshot()
        if self._fetching:
            return self.snapshot()
        self._refresh()
        return self.snapshot()

    def force_refresh(self) -> dict:
        if self._fetching:
            return self.snapshot()
        self._refresh()
        return self.snapshot()

    def _refresh(self):
        self._fetching = True
        try:
            fresh = self._fetch()
            with self._lock:
                if fresh:
                    self.release_version = fresh["release_version"]
                    self.client_version = fresh["client_version"]
                    self.server_url = fresh["server_url"]
                    self.source = "live"
                self.fetched_at = time.time()
            if fresh:
                log.info("live-config rel=%s client=%s server=%s",
                         fresh["release_version"], fresh["client_version"], fresh["server_url"])
        finally:
            self._fetching = False

    def _fetch(self):
        play_version = self._play_version()
        if not play_version:
            return None
        try:
            params = {
                "version": play_version,
                "lang": "en",
                "device": "android",
                "channel": "android",
                "appsttore": "googleplay",
                "region": "ME",
                "whitelist_version": "1.3.0",
                "whitelist_sp_version": "1.0.0",
                "device_name": "google G011A",
            }
            r = http_request("GET", RESOLVER_URL, params=params, timeout=LIVE_CONFIG_TIMEOUT)
            r.raise_for_status()
            data = r.json()
            server_url = (data.get("server_url") or "").rstrip("/")
            rel_ver = data.get("latest_release_version") or ""
            if not server_url or not rel_ver:
                log.warning("live-config: empty server_url or release_version")
                return None
            return {
                "release_version": rel_ver,
                "client_version": play_version,
                "server_url": server_url,
            }
        except Exception as e:
            log.warning("live-config fetch failed: %s", e)
            return None

    def _play_version(self):
        try:
            from google_play_scraper import app as store_lookup
        except ImportError:
            log.debug("google-play-scraper not installed")
            return None
        try:
            return store_lookup(PLAY_APP_ID, lang="fr", country="fr")["version"]
        except Exception as e:
            log.warning("play store lookup failed: %s", e)
            return None


live_config = LiveConfig()


def grant_access_token(uid: str, password: str):
    payload = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": CLIENT_SECRET,
        "client_id": str(APP_ID),
    }
    headers = {
        "User-Agent": "GarenaMSDK/4.0.30",
        "Accept": "application/json",
        "Accept-Encoding": "gzip",
        "Connection": "Keep-Alive",
    }
    r = http_request("POST", OAUTH_URL, data=payload, headers=headers)
    if r.status_code != 200:
        raise ApiError("oauth_failed", f"token grant HTTP {r.status_code}", 502)
    try:
        data = r.json()
    except ValueError:
        raise ApiError("oauth_failed", "token grant returned non-JSON", 502)
    at = data.get("access_token")
    oid = data.get("open_id")
    if not at or not oid:
        raise ApiError("oauth_failed", "token grant missing access_token/open_id", 502)
    return at, oid


def inspect_access_token(access_token: str):
    r = http_request(
        "GET", f"{INSPECT_URL}?token={access_token}",
        headers={"User-Agent": "GarenaMSDK/4.0.19P9", "Accept": "application/json"},
    )
    if r.status_code != 200:
        raise ApiError("inspect_failed", f"inspect HTTP {r.status_code}", 502)
    try:
        data = r.json()
    except ValueError:
        raise ApiError("inspect_failed", "inspect returned non-JSON", 502)

    inner = data.get("data", {}) if isinstance(data.get("data"), dict) else {}

    open_id = (
        data.get("open_id") or inner.get("open_id")
        or inner.get("uid") or data.get("uid")
    )
    if not open_id:
        raise ApiError("inspect_failed", "no open_id in inspect response", 502)

    platform = (
        data.get("main_active_platform") or data.get("login_platform")
        or data.get("platform") or inner.get("main_active_platform")
        or inner.get("login_platform") or inner.get("platform") or 4
    )
    try:
        platform = int(platform)
    except (TypeError, ValueError):
        platform = 4

    region = (
        data.get("region") or inner.get("region")
        or data.get("country_code") or inner.get("country_code") or "SG"
    )
    return str(open_id), platform, str(region)


MAJOR_LOGIN_STATIC = {
    4: "free fire",
    5: 1,
    8: "Android OS 10 / API-29 (QP1A.190711.020/V12.0.26.0.QCDINXM)",
    9: "Handheld",
    10: "Grameenphone",
    11: "WIFI",
    12: 1600,
    13: 720,
    14: "280",
    15: "ARMv7 VFPv3 NEON | 2002 | 8",
    16: 3790,
    17: "PowerVR Rogue GE8320",
    18: "OpenGL ES 3.2 build 1.11@5425693",
    19: "Google|00000000-0000-0000-0000-000000000000",
    20: "103.148.14.66",
    21: "en",
    25: "Xiaomi M2002F3",
    30: 1,
    41: "Grameenphone",
    42: "WIFI",
    57: "1ac4b80ecf0478a44203bf8fac6120f5",
    60: 53041,
    61: 7291,
    62: 2176,
    64: 7395,
    65: 53041,
    66: 7395,
    67: 53041,
    70: 4,
    73: 2,
    74: "/data/app/com.dts.freefireth-yAPXAhp2RyIlrtNAM0VzKQ==/lib/arm",
    76: 1,
    77: "066a589fa3f5658377634fe7b1d88556|/data/app/com.dts.freefireth-yAPXAhp2RyIlrtNAM0VzKQ==/base.apk",
    78: 6,
    79: 1,
    81: "32",
    83: "2019121227",
    85: 3,
    86: "OpenGLES2",
    87: 3071,
    88: 4,
    92: 9329,
    93: "3rd_party",
    94: "KqsHT3r+fXQIu/dyZrEa8fJBhbJ5uqDES7YsAUfu+Mck9A+Bly6lFfYk7Q7Nj68pqI8I3g4Oz3gLxWef6Eh/jKyzHug=",
    95: 111207,
    96: '{"cur_rate":null,"support_etc2":false}',
    97: 1,
    98: 1,
    104: 47591,
    105: 1,
    106: "https://dl-bs.ppmainecoonghj.com/live/ABHotUpdates/|https://core-bs.ppmainecoonghj.com/live/ABHotUpdates/|1c2462939e53942fc995400436a3dc7b",
    107: "c8e41b7a93f02d56e1a94c7b8203f5d1",
}


def _build_login_body(open_id: str, access_token: str, platform: int,
                      region: str, client_version: str) -> dict:
    body = dict(MAJOR_LOGIN_STATIC)
    body[3] = str(int(time.time()))
    body[7] = client_version
    body[22] = open_id
    body[23] = str(platform)
    body[26] = str(region)
    body[29] = access_token
    body[99] = str(platform)
    body[100] = str(platform)
    body[102] = b"BTL\x10S\x0e[\x040"
    return body


def _parse_major_login_response(content: bytes) -> dict:
    for offset in PROTOBUF_OFFSETS:
        if offset >= len(content):
            continue
        fields = decode_protobuf(content[offset:])

        token_raw = fields.get(8)
        if token_raw is not None:
            token_str = _unwrap_jwt(token_raw)
            if is_jwt(token_str):
                region = fields.get(2)
                client_url = fields.get(10)
                account_id = fields.get(1)
                return {
                    "token": token_str,
                    "region": region if isinstance(region, str) and region else None,
                    "client_url": client_url if isinstance(client_url, str) and client_url else None,
                    "account_id": account_id if isinstance(account_id, int) else None,
                }

    jwt = find_jwt_in_bytes(content)
    if jwt:
        return {"token": jwt, "region": None, "client_url": None, "account_id": None}

    top = sorted(decode_protobuf(content[:512]).keys())
    raise ApiError(
        "login_failed",
        "no JWT in MajorLogin response",
        502,
        details={"top_level_fields": top, "sample": content[:64].hex()},
    )


def _major_login_attempt(open_id: str, access_token: str, platform: int,
                         region: str, live: dict) -> dict:
    server = live["server_url"].rstrip("/")
    host = server.split("://", 1)[-1].split("/", 1)[0]

    body = _build_login_body(open_id, access_token, platform, region, live["client_version"])
    encrypted = aes_encrypt(encode_protobuf(body))

    headers = {
        "Host": host,
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Accept-Encoding": "deflate, gzip",
        "X-GA-SV": str(int(time.time())),
        "Authorization": "Bearer",
        "X-GA": "v1 1",
        "ReleaseVersion": live["release_version"],
        "Content-Type": "application/octet-stream",
        "X-Unity-Version": UNITY_VERSION,
        "Connection": "Keep-Alive",
        "Content-Length": str(len(encrypted)),
    }
    r = http_request(
        "POST", f"{server}/MajorLogin",
        headers=headers, data=encrypted,
        timeout=LOGIN_TIMEOUT, retries=1,
    )
    if r.status_code != 200:
        raise ApiError("login_failed", f"MajorLogin HTTP {r.status_code}", 502)
    if len(r.content) < 8:
        raise ApiError("login_failed", "MajorLogin response too short", 502)
    return _parse_major_login_response(r.content)


def major_login(open_id: str, access_token: str, platform: int, region: str) -> dict:
    live = live_config.get()
    attempts = {}

    try:
        result = _major_login_attempt(open_id, access_token, platform, region, live)
        log.info("major_login platform=%s (inspect)", platform)
        return result
    except ApiError as e:
        attempts[platform] = e.code
        log.info("major_login platform=%s failed: %s", platform, e.code)
    except Exception as e:
        attempts[platform] = type(e).__name__
        log.info("major_login platform=%s failed: %s", platform, type(e).__name__)

    remaining = [p for p in PLATFORM_ORDER if p != platform]
    done = threading.Event()
    winner = [None]
    lock = threading.Lock()

    def worker(p: int):
        if done.is_set():
            return
        try:
            result = _major_login_attempt(open_id, access_token, p, region, live)
            with lock:
                attempts[p] = "ok"
                if winner[0] is None:
                    winner[0] = result
                    done.set()
        except ApiError as e:
            with lock:
                attempts[p] = e.code
        except Exception as e:
            with lock:
                attempts[p] = type(e).__name__

    with ThreadPoolExecutor(max_workers=len(remaining)) as pool:
        futures = [pool.submit(worker, p) for p in remaining]
        for f in futures:
            try:
                f.result(timeout=LOGIN_TIMEOUT + 2)
            except Exception:
                pass

    if winner[0]:
        log.info("major_login race ok tried=%d", len(attempts))
        return winner[0]

    raise ApiError(
        "platform_error",
        "MajorLogin rejected all platform types",
        502,
        details={"region": region, "attempts": attempts},
    )


def validate_uid(raw) -> str:
    if not raw or not raw.strip():
        raise ApiError("missing_uid", "uid is required", 400)
    raw = raw.strip()
    if not raw.isdigit():
        raise ApiError("invalid_uid", "uid must be numeric", 400)
    return raw


def validate_password(raw) -> str:
    if not raw:
        raise ApiError("missing_password", "password is required", 400)
    return raw


def validate_token(raw) -> str:
    if not raw or not raw.strip():
        raise ApiError("missing_token", "token is required", 400)
    raw = raw.strip()
    if len(raw) < 20:
        raise ApiError("invalid_token", "token looks malformed", 400)
    return raw


_token_cache = TTLCache(TOKEN_CACHE_MAX, TOKEN_CACHE_TTL)
_inflight_lock = threading.Lock()
_inflight: dict[str, threading.Event] = {}


def _cached_or_fetch(cache_key: str, fetcher):
    cached = _token_cache.get(cache_key)
    if cached is not None:
        log.debug("cache hit %s…", cache_key[:16])
        return cached

    with _inflight_lock:
        event = _inflight.get(cache_key)
        if event is None:
            event = threading.Event()
            _inflight[cache_key] = event
            is_leader = True
        else:
            is_leader = False

    if is_leader:
        try:
            result = fetcher()
            _token_cache.set(cache_key, result)
            return result
        finally:
            with _inflight_lock:
                _inflight.pop(cache_key, None)
            event.set()

    event.wait(timeout=LOGIN_TIMEOUT + 5)
    cached = _token_cache.get(cache_key)
    if cached is not None:
        return cached
    return fetcher()


def fetch_jwt_for_guest(uid: str, password: str) -> dict:
    cache_key = f"guest:{uid}:{hashlib.sha256(password.encode()).hexdigest()[:16]}"

    def _do():
        access_token, _ = grant_access_token(uid, password)
        open_id, platform, region = inspect_access_token(access_token)
        ml = major_login(open_id, access_token, platform, region)
        return {
            "jwt": ml["token"],
            "region": ml.get("region"),
            "client_url": ml.get("client_url"),
            "account_id": ml.get("account_id"),
            "access_token": access_token,
        }

    return _cached_or_fetch(cache_key, _do)


def fetch_jwt_for_token(access_token: str) -> dict:
    cache_key = f"token:{access_token[:32]}"

    def _do():
        open_id, platform, region = inspect_access_token(access_token)
        ml = major_login(open_id, access_token, platform, region)
        return {
            "jwt": ml["token"],
            "region": ml.get("region"),
            "client_url": ml.get("client_url"),
            "account_id": ml.get("account_id"),
            "access_token": access_token,
        }

    return _cached_or_fetch(cache_key, _do)


def format_token_result(result: dict) -> dict:
    payload = decode_jwt_payload(result["jwt"])

    region = (
        payload.get("lock_region")
        or payload.get("noti_region")
        or result.get("region")
        or ""
    )

    account_id = result.get("account_id")
    if account_id is None:
        account_id = payload.get("account_id", "")
    account_id = str(account_id) if account_id != "" else ""

    return {
        "region": region,
        "url": result.get("client_url") or "",
        "token": result["jwt"],
        "token_access": result["access_token"],
        "account_id": account_id,
    }


app = Flask(__name__)
app.url_map.strict_slashes = False
BOOT_TIME = time.time()


@app.before_request
def _init_request():
    g.rid = uuid.uuid4().hex[:12]
    g.t0 = time.time()


@app.after_request
def _finalize(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "*"
    resp.headers["X-Request-ID"] = getattr(g, "rid", "")
    t0 = getattr(g, "t0", None)
    if t0:
        resp.headers["X-Response-Time"] = f"{int((time.time() - t0) * 1000)}ms"
    return resp


@app.route("/", methods=["GET"])
def home():
    live = live_config.get()
    return ok({
        "service": "Free Fire JWT Generator",
        "release_version": live["release_version"],
        "client_version": live["client_version"],
        "server_url": live["server_url"],
        "config_source": live["source"],
        "usage": {
            "guest": {
                "endpoint": "GET /api/public/token",
                "params": {"uid": "numeric", "password": "string"},
                "example": "/api/public/token?uid=8445523999&password=xxx",
            },
            "access_token": {
                "endpoint": "GET /api/public/token",
                "params": {"access_token": "Garena access token"},
                "example": "/api/public/token?access_token=xxx",
            },
        },
        "response_fields": {
            "region": "lock region from JWT payload",
            "url": "client URL from MajorLogin response",
            "token": "JWT string",
            "token_access": "Garena access token",
            "account_id": "account id from MajorLogin response",
        },
        "endpoints": {
            "/": "this guide",
            "/api/public/token": "unified: uid+password OR access_token",
            "/guest": "JWT via UID + password",
            "/access_token": "JWT via Garena access token",
            "/live-config": "current resolved versions (?force=1 to refresh)",
            "/health": "uptime + stats",
        },
    })


@app.route("/health", methods=["GET"])
def health():
    live = live_config.get()
    return ok({
        "uptime_sec": round(time.time() - BOOT_TIME, 1),
        "release_version": live["release_version"],
        "client_version": live["client_version"],
        "server_url": live["server_url"],
        "config_source": live["source"],
        "config_age_sec": round(time.time() - live["fetched_at"], 1) if live["fetched_at"] else 0,
        "token_cache_size": len(_token_cache),
    })


@app.route("/live-config", methods=["GET"])
def live_config_endpoint():
    if request.args.get("force") in ("1", "true", "yes"):
        return ok(live_config.force_refresh())
    return ok(live_config.get())


@app.route("/api/public/token", methods=["GET", "OPTIONS"])
def api_public_token():
    if request.method == "OPTIONS":
        return ("", 204)

    uid = request.args.get("uid")
    password = request.args.get("password")
    token = (
        request.args.get("access_token")
        or request.args.get("token")
        or request.args.get("at")
    )

    try:
        if uid and password:
            uid_v = validate_uid(uid)
            password_v = validate_password(password)
            log.info("[%s] guest uid=%s", g.rid, uid_v)
            result = fetch_jwt_for_guest(uid_v, password_v)
            return ok(format_token_result(result))

        if token:
            token_v = validate_token(token)
            log.info("[%s] token %s…", g.rid, token_v[:20])
            result = fetch_jwt_for_token(token_v)
            return ok(format_token_result(result))

        raise ApiError(
            "missing_input",
            "provide either (uid + password) or access_token",
            400,
            details={
                "guest": "/api/public/token?uid=<uid>&password=<password>",
                "token": "/api/public/token?access_token=<access_token>",
            },
        )
    except ApiError as e:
        log.info("[%s] error %s: %s", g.rid, e.code, e.message)
        return fail(e.code, e.message, e.http, e.details)
    except Exception:
        log.exception("[%s] unhandled", g.rid)
        return fail("internal_error", "internal server error", 500)


@app.route("/guest", methods=["GET", "OPTIONS"])
def guest():
    if request.method == "OPTIONS":
        return ("", 204)
    try:
        uid = validate_uid(request.args.get("uid"))
        password = validate_password(request.args.get("password"))
        log.info("[%s] guest uid=%s", g.rid, uid)
        result = fetch_jwt_for_guest(uid, password)
        return ok(format_token_result(result))
    except ApiError as e:
        log.info("[%s] error %s: %s", g.rid, e.code, e.message)
        return fail(e.code, e.message, e.http, e.details)
    except Exception:
        log.exception("[%s] unhandled", g.rid)
        return fail("internal_error", "internal server error", 500)


@app.route("/access_token", methods=["GET", "OPTIONS"])
def access_token_route():
    if request.method == "OPTIONS":
        return ("", 204)
    raw = (
        request.args.get("token")
        or request.args.get("access_token")
        or request.args.get("at")
        or ""
    )
    try:
        token = validate_token(raw)
        log.info("[%s] token %s…", g.rid, token[:20])
        result = fetch_jwt_for_token(token)
        return ok(format_token_result(result))
    except ApiError as e:
        log.info("[%s] error %s: %s", g.rid, e.code, e.message)
        return fail(e.code, e.message, e.http, e.details)
    except Exception:
        log.exception("[%s] unhandled", g.rid)
        return fail("internal_error", "internal server error", 500)


@app.errorhandler(ApiError)
def _handle_api_error(e):
    return fail(e.code, e.message, e.http, e.details)


@app.errorhandler(HTTPException)
def _handle_http_error(e):
    code = (e.name or "http_error").lower().replace(" ", "_")
    return fail(code, e.description, e.code)


@app.errorhandler(Exception)
def _handle_uncaught(e):
    log.exception("uncaught")
    return fail("internal_error", "internal server error", 500)


if __name__ == "__main__":
    log.info("Free Fire JWT Generator starting")
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False,
        use_reloader=False,
    )
