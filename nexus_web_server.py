#!/usr/bin/env python3
"""
NeXuS Web Server — portable, versatile HTTPS host  (Sane · Simple · Secure · Sustainable)

A single pure-Python-stdlib server (no node, no npm, no pip) that does two jobs:

  A) STATIC — serves a web ROOT directory. Drop an app folder in; it's served.
              Per-app SPA fallback; a landing index when ROOT holds several apps.
  B) PROXY  — one shared /api/* backend that injects API keys server-side from
              ~/.config/nexus/secrets/nexus.env, so NO app ever holds an sk_ key.
              Every app under ROOT shares it (char-gen, OpenCharacters, yours, …).

That split is the whole idea: files are swappable; the key-injecting proxy is the
valuable shared engine. To host your own app: put it under ROOT and point its fetch
calls at /api/* .

Routes:
  GET  /api/health                             liveness + which providers have keys
  GET  /api/providers                          sanitized registry (NO secrets)
  GET  /api/models/image | /api/models/text    keyless passthrough (Pollinations lists)
  GET  /api/pollinations/image?prompt=&model=&width=&height=
                                               image proxy, key injected, streams JPEG
  POST /api/llm                                 OpenAI-compatible text proxy;
                                               body: { "provider": "...", ...openai }
  POST /api/llm/{provider}/v1/chat/completions  same, but VANILLA OpenAI body
                                               (provider in URL — for OpenCharacters &
                                               any "custom endpoint" client)
  GET  /api/apps                               list sub-apps in ROOT (for manager UI)
  POST /api/wire                               run nexus-proxy-wire.sh on a given dir
  POST /api/upload/image                       multipart upload → ~/NeXuS/uploads/images/
  GET  /uploads/images/<filename>              serve uploaded image
  *                                            static file under ROOT (SPA fallback)

Usage:
  python3 nexus_web_server.py                       # ROOT=./dist (char-gen at /)
  python3 nexus_web_server.py --root ~/nexus-web    # multi-app: /chargen/ /oc/ ...
  python3 nexus_web_server.py --root . --port 8443 --cert cert.pem --key key.pem
"""

import os
import re
import sys
import ssl
import json
import html
import argparse
import datetime
import urllib.parse
import urllib.request
import urllib.error
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ── Defaults / config ─────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).resolve().parent
SECRETS_DIR = Path(os.environ.get("NEXUS_SECRETS_DIR",
                   os.path.join(os.environ.get("HOME", ""), "NeXuS/secrets")))
UPLOAD_IMAGES_DIR = Path(os.environ.get("NEXUS_UPLOAD_IMAGES_DIR",
                    os.path.join(os.environ.get("HOME", ""), "NeXuS/uploads/images")))

# set from argv in main(); module-level so the handler can read them
ROOT: Path = BASE_DIR / "dist"

# Ordered list of local env files (project-local overrides), set in main().
# Precedence, highest first: process env  >  .local.env (these)  >  nexus.env  >  legacy key file.
LOCAL_ENV_FILES: list = []

# Files the STATIC server must never serve (defense in depth — secrets are never web-reachable
# even if one lands inside the web root). Matches by basename suffix or a leading dot.
SECRET_SUFFIXES = (".env", ".key", ".pem", ".secret", ".pfx", ".p12")

MIME_TYPES = {
    ".html": "text/html", ".htm": "text/html", ".js": "application/javascript",
    ".mjs": "application/javascript", ".css": "text/css", ".json": "application/json",
    ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif",
    ".svg": "image/svg+xml", ".webp": "image/webp", ".ico": "image/x-icon",
    ".woff": "font/woff", ".woff2": "font/woff2", ".ttf": "font/ttf", ".otf": "font/otf",
    ".eot": "application/vnd.ms-fontobject", ".wasm": "application/wasm", ".txt": "text/plain",
    ".xml": "text/xml", ".map": "application/json", ".webmanifest": "application/manifest+json",
}

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://esm.sh https://cdn.jsdelivr.net https://unpkg.com https://cdnjs.cloudflare.com; "
        "worker-src 'self' blob:; child-src 'self' blob:; "
        "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://fonts.googleapis.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "img-src 'self' data: blob: https:; "
        "connect-src 'self' https: http://localhost:*; "
        "font-src 'self' data: https://fonts.gstatic.com https://esm.sh https://cdnjs.cloudflare.com;"
    ),
}

# ── Provider registry (endpoints + which nexus.env var holds the key) ──────────
# One place declares every OpenAI-compatible endpoint. requires_key=False => keyless.
PROVIDERS = {
    "pollinations": {"label": "Pollinations.ai",  "base_url": "https://gen.pollinations.ai/v1",
                     "key_env": "POLLINATIONS_API_KEY", "requires_key": True,  "kind": "chat+image"},
    "openai":       {"label": "OpenAI",            "base_url": "https://api.openai.com/v1",
                     "key_env": "OPENAI_API_KEY",       "requires_key": True,  "kind": "chat+image"},
    "mistral":      {"label": "Mistral",           "base_url": "https://api.mistral.ai/v1",
                     "key_env": "MISTRAL_API_KEY",      "requires_key": True,  "kind": "chat"},
    "groq":         {"label": "Groq",              "base_url": "https://api.groq.com/openai/v1",
                     "key_env": "GROQ_API_KEY",         "requires_key": True,  "kind": "chat"},
    "openrouter":   {"label": "OpenRouter",        "base_url": "https://openrouter.ai/api/v1",
                     "key_env": "OPENROUTER_API_KEY",   "requires_key": True,  "kind": "chat"},
    "aichat":       {"label": "aichat (local)",    "base_url": "http://localhost:3030/v1",
                     "key_env": None,                   "requires_key": False, "kind": "chat"},
    "ollama":       {"label": "Ollama (local)",    "base_url": "http://localhost:11434/v1",
                     "key_env": None,                   "requires_key": False, "kind": "chat"},
    "aihorde":      {"label": "AI Horde (free)",  "base_url": "https://aihorde.net/api/v2",
                     "key_env": "AIHORDE_API_KEY",      "requires_key": False, "kind": "chat+image",
                     "async_horde": True},
}
# Free AI Horde is the default for BOTH text and image (sovereign, keyless).
# Media types resolve through different mechanisms: text/image = HTTP providers,
# audio = local piper TTS engine, video = go2rtc camera/encode source.
DEFAULTS = {"main": "aihorde", "text": "aihorde", "image": "aihorde",
            "audio": "piper", "video": "go2rtc", "embedding": "local"}

POLLI_BASE = "https://gen.pollinations.ai"
UA = "nexus-web-server"
LLM_PATH_RE = re.compile(r"^/api/llm/([A-Za-z0-9_.-]+)/(?:v1/)?chat/completions/?$")

# ── Charcard backend (nexus_png2_editor.py Flask app) ────────────────────────
CHARCARD_BACKEND   = os.environ.get("CHARCARD_URL",     "http://127.0.0.1:7420")
CHARCARD_PREFIX    = "/charcard"
COPYPARTY_BACKEND  = os.environ.get("COPYPARTY_URL",   "http://127.0.0.1:8802")
COPYPARTY_PREFIX   = "/files"
NETDATA_BACKEND    = os.environ.get("NETDATA_URL",      "http://127.0.0.1:19999")
NETDATA_PREFIX     = "/netdata"
GRAFANA_BACKEND    = os.environ.get("GRAFANA_URL",      "http://127.0.0.1:3000")
GRAFANA_PREFIX     = "/grafana"
HISTER_BACKEND     = os.environ.get("HISTER_URL",       "http://127.0.0.1:4433")
HISTER_PREFIX      = "/hister"
AICHAT_BACKEND     = os.environ.get("AICHAT_URL",       "http://127.0.0.1:3030")
AICHAT_PREFIX      = "/aichat"

# ── NeXuS Gateway proxy — all outbound API calls routed through microVM ───────
# Set NEXUS_GATEWAY_URL=http://192.168.122.x:8118 (privoxy in Firecracker VM)
# Leave unset to go direct (default). Local/loopback traffic always bypasses.
NEXUS_GATEWAY_URL  = os.environ.get("NEXUS_GATEWAY_URL", "")
NO_PROXY_HOSTS     = {"127.0.0.1", "localhost", "::1"}

def _install_gateway_proxy():
    if not NEXUS_GATEWAY_URL:
        return
    proxy_handler = urllib.request.ProxyHandler({
        "http":  NEXUS_GATEWAY_URL,
        "https": NEXUS_GATEWAY_URL,
    })
    no_proxy_handler = urllib.request.ProxyHandler({})   # passthrough for locals

    class _SmartProxy(urllib.request.BaseHandler):
        def http_open(self, req):
            return self._dispatch(req, "http")
        def https_open(self, req):
            return self._dispatch(req, "https")
        def _dispatch(self, req, scheme):
            host = req.host.split(":")[0]
            if host in NO_PROXY_HOSTS or host.startswith("127.") or host.startswith("192.168."):
                return urllib.request.HTTPSHandler().https_open(req) if scheme == "https" \
                       else urllib.request.HTTPHandler().http_open(req)
            return None  # fall through to proxy_handler

    opener = urllib.request.build_opener(proxy_handler)
    urllib.request.install_opener(opener)
    print(f"[gateway] all outbound API calls → {NEXUS_GATEWAY_URL}")

# ── App registry — discovered from NEXUS_APP_<ID>_* env vars ─────────────────
# Schema per app:
#   NEXUS_APP_<ID>_prefix    /nncc               (required)
#   NEXUS_APP_<ID>_static    ~/nexus-network/web (optional — serve static files)
#   NEXUS_APP_<ID>_backend   http://127.0.0.1:8801 (optional — proxy target)
#   NEXUS_APP_<ID>_api_prefix /api               (optional — only proxy paths with this prefix)
def _build_app_registry():
    apps = {}
    seen = set()
    pfx_re = re.compile(r'^NEXUS_APP_([A-Za-z0-9]+)_prefix$', re.IGNORECASE)
    env = {**_env_dict(), **os.environ}   # nexus.env + process env; process env wins
    for key, val in env.items():
        m = pfx_re.match(key)
        if not m:
            continue
        aid = m.group(1).upper()
        if aid in seen:
            continue
        seen.add(aid)
        apps[aid] = {
            "prefix":      val.rstrip("/"),
            "static":      env.get(f"NEXUS_APP_{aid}_static", ""),
            "backend":     env.get(f"NEXUS_APP_{aid}_backend", ""),
            "api_prefix":  env.get(f"NEXUS_APP_{aid}_api_prefix", ""),
            "rewrite_api": env.get(f"NEXUS_APP_{aid}_rewrite_api", ""),
            "start":       env.get(f"NEXUS_APP_{aid}_start", ""),
            "label":       env.get(f"NEXUS_APP_{aid}_label", aid.title()),
        }
    # Longest prefix first so /search doesn't swallow /search-extended
    return dict(sorted(apps.items(), key=lambda x: -len(x[1]["prefix"])))

APP_REGISTRY: dict = {}   # populated after env is loaded in main()


PROVIDER_RE = re.compile(r"^PROVIDER_([A-Za-z0-9]+)_BASE_URL$")


def _read_env_var(path, name):
    """Return the value of KEY=value for `name` in a dotenv-style file, or None."""
    try:
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            if k.strip() == name:
                return v.strip().strip('"').strip("'")
    except OSError:
        pass
    return None


def _read_env_file(path):
    """Parse a whole dotenv file into {KEY: value}, or {} if missing."""
    out = {}
    try:
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return out


def _env_dict():
    """Merged env view for scanning (not for single-key reads — use load_secret for those).
    Applied low→high precedence so the final dict matches load_secret: nexus.env (base) <
    .local.env files (later listed = lower) < process env (highest)."""
    merged = {}
    merged.update(_read_env_file(SECRETS_DIR / "nexus.env"))
    for f in reversed(LOCAL_ENV_FILES):          # LOCAL_ENV_FILES[0] is highest → apply last
        merged.update(_read_env_file(f))
    merged.update({k: v for k, v in os.environ.items() if k.startswith("PROVIDER_")})
    return merged


def discover_providers():
    """Built-in registry PLUS any providers declared in the env via the convention:
        PROVIDER_<ID>_BASE_URL=https://host/v1     (required — makes <id> exist)
        PROVIDER_<ID>_API_KEY=...                   (optional → requires_key; keyless if absent)
        PROVIDER_<ID>_KIND=chat|image|chat+image    (optional, default chat)
        PROVIDER_<ID>_LABEL=Friendly Name           (optional)
    Env-declared providers override built-ins of the same id. Computed on demand, so editing
    .local.env adds a provider with NO restart. This is what makes it a universal API server."""
    provs = {pid: dict(p) for pid, p in PROVIDERS.items()}
    env = _env_dict()
    for k, v in env.items():
        m = PROVIDER_RE.match(k)
        if not m or not v.strip():
            continue
        raw, pid = m.group(1), m.group(1).lower()
        keyvar = f"PROVIDER_{raw}_API_KEY"
        has_key = bool(env.get(keyvar))
        provs[pid] = {
            "label": env.get(f"PROVIDER_{raw}_LABEL", pid),
            "base_url": v.strip().rstrip("/"),
            "key_env": keyvar if has_key else None,
            "requires_key": has_key,
            "kind": (env.get(f"PROVIDER_{raw}_KIND") or "chat").strip(),
            "dynamic": True,
        }
    return provs


def load_secret(name):
    """Resolve a secret by precedence (highest first):
         1) process environment       (os.environ[name])
         2) .local.env project files  (LOCAL_ENV_FILES, in order)
         3) ~/.config/nexus/secrets/nexus.env   (global)
         4) legacy ~/.config/nexus/secrets/pollinations.key  (POLLINATIONS_API_KEY only)
    Read on demand (edit a file, no restart). Never logged, never returned to the browser."""
    if not name:
        return None
    # 1) real process env wins
    if os.environ.get(name):
        return os.environ[name].strip()
    # 2) project-local .local.env (override), in listed order
    for f in LOCAL_ENV_FILES:
        v = _read_env_var(f, name)
        if v:
            return v
    # 3) global nexus.env
    v = _read_env_var(SECRETS_DIR / "nexus.env", name)
    if v:
        return v
    # 4) legacy single-key file
    if name == "POLLINATIONS_API_KEY":
        try:
            return (SECRETS_DIR / "pollinations.key").read_text(encoding="utf-8").strip()
        except OSError:
            pass
    return None


def is_secret_path(p: Path) -> bool:
    """True if this file must never be served (dotfiles, .env/.key/.pem, etc.)."""
    name = p.name.lower()
    if name.startswith(".") and name not in (".well-known",):
        return True
    return name.endswith(SECRET_SUFFIXES)


def keyed_providers(provs=None):
    provs = provs if provs is not None else discover_providers()
    return {pid: ((not p["requires_key"]) or bool(load_secret(p["key_env"])))
            for pid, p in provs.items()}


def log(msg):
    print(f"[{datetime.datetime.now().isoformat(timespec='seconds')}] {msg}", flush=True)


class Handler(BaseHTTPRequestHandler):
    server_version = "NeXuS-Web/1.0"

    def log_message(self, fmt, *args):
        log(f"{self.address_string()} {fmt % args}")

    # ── low-level send helpers ────────────────────────────────────────────────
    def _send(self, code, ctype, extra=None, sec_override=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        headers = sec_override if sec_override is not None else SECURITY_HEADERS
        for k, v in headers.items():
            self.send_header(k, v)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode("utf-8")
        self._send(code, "application/json",
                   {"Content-Length": str(len(body)), "Cache-Control": "no-store"})
        self.wfile.write(body)

    def _bytes(self, data, ctype, cache="no-store", code=200, sec_override=None):
        self._send(code, ctype, {"Content-Length": str(len(data)), "Cache-Control": cache},
                   sec_override=sec_override)
        self.wfile.write(data)

    # ── routing ───────────────────────────────────────────────────────────────
    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path in ("/", "/map", "/map/"):
            return self._serve_map()
        if path == "/api/health":
            return self._json({"ok": True, "root": str(ROOT), "providers_with_keys": keyed_providers()})
        if path == "/api/providers":
            return self._json(self._registry())
        if path == "/api/models/image":
            return self._passthrough(f"{POLLI_BASE}/image/models")
        if path == "/api/models/text":
            return self._passthrough(f"{POLLI_BASE}/text/models")
        if path.startswith("/api/models/provider/"):
            return self._provider_models(path.rsplit("/", 1)[-1])
        if path == "/api/pollinations/image":
            return self._pollinations_image()
        if path == "/api/apps":
            return self._list_apps()
        if path == "/api/servers":
            return self._servers_status()
        if path == "/api/nexus/ncm/terminal" and self.headers.get("Upgrade", "").lower() == "websocket":
            return self._ncm_terminal_ws()
        if path == "/api/nexus/studio/terminal" and self.headers.get("Upgrade", "").lower() == "websocket":
            return self._studio_terminal_ws()
        if path.startswith("/api/nexus/"):
            return self._nexus_api(path)
        if path.startswith("/api/"):
            return self._json({"error": f"unknown API route {path}"}, 404)
        if path.startswith(CHARCARD_PREFIX):
            return self._charcard_proxy()
        if path.startswith(COPYPARTY_PREFIX):
            return self._copyparty_proxy()
        if path.startswith(GRAFANA_PREFIX):
            return self._grafana_proxy()
        if path.startswith(HISTER_PREFIX):
            return self._hister_proxy()
        if path.startswith(AICHAT_PREFIX):
            return self._aichat_proxy()
        if path in ("/governor", "/governor/"):
            return self._serve_static("/governor/index.html")
        if path.startswith("/governor/"):
            return self._serve_static(path)
        if path in ("/publish", "/publish/"):
            return self._serve_static("/publish/index.html")
        if path.startswith("/publish/"):
            return self._serve_static(path)
        if path == "/twtxt.txt":
            return self._serve_twtxt_feed()
        if path == "/oc/":
            self._send(302, "text/plain", {"Location": "/oc/index.html"})
            return
        if path in ("/timeline", "/timeline/"):
            return self._serve_timeline()
        if path.startswith("/timeline/images/"):
            return self._serve_timeline_image(path)
        if path.startswith("/uploads/images/"):
            return self._serve_upload(path)
        reg = self._match_registry(path)
        if reg:
            return self._dispatch_registry(reg, path)
        return self._serve_static(path)

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/llm":
            return self._llm_proxy(provider_from_url=None)
        m = LLM_PATH_RE.match(path)
        if m:
            return self._llm_proxy(provider_from_url=m.group(1))
        if path == "/api/wire":
            return self._wire_app()
        if path == "/api/upload/image":
            return self._upload_image()
        if path.startswith("/api/nexus/"):
            return self._nexus_api(path)
        if path.startswith(CHARCARD_PREFIX):
            return self._charcard_proxy()
        if path.startswith(COPYPARTY_PREFIX):
            return self._copyparty_proxy()
        if path.startswith(GRAFANA_PREFIX):
            return self._grafana_proxy()
        if path.startswith(HISTER_PREFIX):
            return self._hister_proxy()
        if path.startswith(AICHAT_PREFIX):
            return self._aichat_proxy()
        reg = self._match_registry(path)
        if reg:
            return self._dispatch_registry(reg, path)
        return self._json({"error": f"unknown API route {path}"}, 404)

    def do_PATCH(self):
        path = urllib.parse.urlparse(self.path).path
        if path.startswith(GRAFANA_PREFIX):
            return self._grafana_proxy()
        if path.startswith(HISTER_PREFIX):
            return self._hister_proxy()
        if path.startswith(AICHAT_PREFIX):
            return self._aichat_proxy()
        reg = self._match_registry(path)
        if reg:
            return self._dispatch_registry(reg, path)
        return self._json({"error": f"unknown route {path}"}, 404)

    def do_DELETE(self):
        path = urllib.parse.urlparse(self.path).path
        if path.startswith(GRAFANA_PREFIX):
            return self._grafana_proxy()
        if path.startswith(HISTER_PREFIX):
            return self._hister_proxy()
        if path.startswith(AICHAT_PREFIX):
            return self._aichat_proxy()
        reg = self._match_registry(path)
        if reg:
            return self._dispatch_registry(reg, path)
        return self._json({"error": f"unknown route {path}"}, 404)

    def do_PUT(self):
        path = urllib.parse.urlparse(self.path).path
        if path.startswith(GRAFANA_PREFIX):
            return self._grafana_proxy()
        if path.startswith(HISTER_PREFIX):
            return self._hister_proxy()
        if path.startswith(AICHAT_PREFIX):
            return self._aichat_proxy()
        reg = self._match_registry(path)
        if reg:
            return self._dispatch_registry(reg, path)
        return self._json({"error": f"unknown route {path}"}, 404)

    def do_OPTIONS(self):
        self._send(204, "text/plain", {
            "Access-Control-Allow-Origin": "'self'",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
        })

    # ── registry ──────────────────────────────────────────────────────────────
    def _registry(self):
        provs = discover_providers()
        keyed = keyed_providers(provs)
        providers = {pid: {"id": pid, "label": p["label"], "kind": p["kind"],
                           "requires_key": p["requires_key"], "key_present": keyed[pid],
                           "dynamic": p.get("dynamic", False), "proxied": True}
                     for pid, p in provs.items()}
        return {"providers": providers, "defaults": DEFAULTS}

    # ── live per-provider model list (any provider's /models, normalized) ─────
    def _provider_models(self, pid):
        prov = discover_providers().get(pid or "")
        if not prov:
            return self._json({"error": f"unknown provider '{pid}'"}, 404)
        # Pollinations text models — normalize to same {provider, models} shape.
        if pid == "pollinations":
            try:
                req = urllib.request.Request(f"{POLLI_BASE}/text/models", headers={"User-Agent": UA})
                with urllib.request.urlopen(req, timeout=20) as up:
                    raw = json.loads(up.read() or b"[]")
                rows = raw if isinstance(raw, list) else raw.get("data", [])
                ids = sorted(set(
                    r.get("name") or r.get("id") or ""
                    for r in rows if isinstance(r, dict)
                ) - {""})
                return self._json({"provider": "pollinations", "models": ids})
            except Exception as e:
                return self._json({"provider": "pollinations", "models": [], "error": str(e)[:200]})
        base = prov["base_url"].rstrip("/")
        headers = {"User-Agent": UA}
        if prov["requires_key"]:
            key = load_secret(prov["key_env"])
            if not key:
                return self._json({"models": [], "error": f"{prov['label']} has no key"}, 200)
            headers["Authorization"] = f"Bearer {key}"
        try:
            req = urllib.request.Request(f"{base}/models", headers=headers)
            with urllib.request.urlopen(req, timeout=20) as up:
                raw = json.loads(up.read() or b"{}")
        except Exception as e:
            return self._json({"models": [], "error": str(e)[:200]}, 200)
        # OpenAI shape {data:[{id}]}; some return a bare list.
        rows = raw.get("data", raw) if isinstance(raw, dict) else raw
        ids = []
        for r in rows if isinstance(rows, list) else []:
            mid = r.get("id") or r.get("name") if isinstance(r, dict) else (r if isinstance(r, str) else None)
            if mid:
                ids.append(mid)
        return self._json({"provider": pid, "models": sorted(set(ids))})

    # ── keyless passthrough (model lists) ─────────────────────────────────────
    def _passthrough(self, url):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=20) as up:
                data = up.read()
                ctype = up.headers.get("Content-Type", "application/json")
            self._bytes(data, ctype, cache="max-age=300")
        except Exception as e:
            self._json({"error": "passthrough failed", "detail": str(e)[:300]}, 502)

    # ── image proxy (key injected server-side; streams image) ─────────────────
    def _pollinations_image(self):
        key = load_secret("POLLINATIONS_API_KEY")
        if not key or not key.startswith("sk_"):
            return self._json({"error": "No valid POLLINATIONS_API_KEY (sk_...) in nexus.env"}, 500)
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        prompt = (q.get("prompt", [""])[0]).strip()
        if not prompt:
            return self._json({"error": "Missing prompt"}, 400)
        model, width, height = q.get("model", ["flux"])[0], q.get("width", ["1024"])[0], q.get("height", ["1024"])[0]
        upstream = (f"{POLLI_BASE}/image/{urllib.parse.quote(prompt)}"
                    f"?model={urllib.parse.quote(model)}&width={urllib.parse.quote(width)}"
                    f"&height={urllib.parse.quote(height)}&nologo=true"
                    f"&key={urllib.parse.quote(key)}&referrer={UA}")
        log(f"[PROXY] image (model={model} {width}x{height}) key=sk_***")
        try:
            req = urllib.request.Request(upstream, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=120) as up:
                self._send(200, up.headers.get("Content-Type", "image/jpeg"), {"Cache-Control": "no-store"})
                while (chunk := up.read(65536)):
                    self.wfile.write(chunk)
        except urllib.error.HTTPError as e:
            self._json({"error": f"Pollinations {e.code}", "detail": e.read()[:300].decode("utf-8", "replace")}, e.code)
        except Exception as e:
            self._json({"error": "Upstream request failed", "detail": str(e)[:300]}, 502)

    # ── generic OpenAI-compatible text proxy (body- or path-style) ────────────
    def _llm_proxy(self, provider_from_url):
        try:
            length = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(length) or b"{}")
        except Exception as e:
            return self._json({"error": "bad JSON body", "detail": str(e)[:200]}, 400)

        pid = provider_from_url or payload.pop("provider", None)
        provs = discover_providers()
        prov = provs.get(pid or "")
        if not prov:
            return self._json({"error": f"unknown provider '{pid}'", "known": list(provs)}, 400)
        # AI Horde speaks its own async API, not OpenAI — dedicated handler.
        if prov.get("async_horde"):
            return self._horde_text(payload)
        base = (payload.pop("base_url", None) or prov["base_url"]).rstrip("/")
        url = f"{base}/chat/completions"
        headers = {"Content-Type": "application/json", "User-Agent": UA}
        if prov["requires_key"]:
            key = load_secret(prov["key_env"])
            if not key:
                return self._json({"error": f"{prov['label']} needs a key: set {prov['key_env']} in nexus.env"}, 502)
            headers["Authorization"] = f"Bearer {key}"

        # Translate OpenAI model names to provider-native equivalents server-side.
        # This keeps client-side model names intact (so OC's modelNameToModelType works)
        # while sending the provider a model name it actually accepts.
        _MODEL_XLAT = {
            "groq": {
                "gpt-4": "groq/compound", "gpt-4-turbo": "groq/compound",
                "gpt-4-turbo-preview": "groq/compound", "gpt-4-0125-preview": "groq/compound",
                "gpt-3.5-turbo": "groq/compound-mini", "gpt-3.5-turbo-16k": "groq/compound-mini",
            },
        }
        _GROQ_NATIVE = {"groq/compound", "groq/compound-mini", "openai/gpt-oss-120b",
                        "openai/gpt-oss-20b", "qwen/qwen3.6-27b", "qwen/qwen3.8-27b"}
        m = payload.get("model", "")
        translated = _MODEL_XLAT.get(pid, {}).get(m)
        if not translated and pid == "groq" and m not in _GROQ_NATIVE and not m.startswith("whisper"):
            translated = "groq/compound"
        if translated:
            payload["model"] = translated

        body = json.dumps(payload).encode("utf-8")
        log(f"[PROXY] llm {pid} -> {url} model={payload.get('model')} (stream={bool(payload.get('stream'))})")
        try:
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=180) as up:
                self._send(200, up.headers.get("Content-Type", "application/json"), {"Cache-Control": "no-store"})
                while (chunk := up.read(8192)):
                    self.wfile.write(chunk)
                    try:
                        self.wfile.flush()
                    except Exception:
                        break
        except urllib.error.HTTPError as e:
            self._json({"error": f"{prov['label']} {e.code}", "detail": e.read()[:500].decode("utf-8", "replace")}, e.code)
        except Exception as e:
            self._json({"error": "Upstream request failed", "detail": str(e)[:300]}, 502)

    # ── AI Horde (free, sovereign default) — async submit→poll ──────────────────
    # Anonymous key "0000000000" works (low priority). Set AIHORDE_API_KEY for a
    # registered account = faster kudos-priority. Server is threaded, so a bounded
    # blocking poll here doesn't stall other clients.

    _HORDE_BASE = "https://aihorde.net/api/v2"

    def _horde_key(self):
        return load_secret("AIHORDE_API_KEY") or "0000000000"

    def _horde_req(self, path, data=None, method="GET"):
        body = json.dumps(data).encode() if data is not None else None
        req = urllib.request.Request(self._HORDE_BASE + path, data=body, method=method,
            headers={"apikey": self._horde_key(), "Content-Type": "application/json",
                     "User-Agent": UA, "Client-Agent": "nexus-studio:1.0:nxsnet"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read() or b"{}")

    def _horde_text(self, payload):
        """OpenAI-shaped chat → Horde text async → OpenAI-shaped completion."""
        import time as _t
        msgs = payload.get("messages", [])
        prompt = "\n".join(f"{m.get('role','user')}: {m.get('content','')}" for m in msgs)
        prompt += "\nassistant:"
        want = payload.get("model") or ""
        req = {"prompt": prompt,
               "params": {"max_length": int(payload.get("max_tokens", 320)),
                          "max_context_length": 2048},
               "models": [want] if want and want != "default" else []}
        try:
            sub = self._horde_req("/generate/text/async", req, "POST")
        except urllib.error.HTTPError as e:
            return self._json({"error": "AI Horde rejected request",
                               "detail": e.read()[:300].decode("utf-8", "replace")}, 502)
        except Exception as e:
            return self._json({"error": f"AI Horde unreachable: {e}"}, 502)
        jid = sub.get("id")
        if not jid:
            return self._json({"error": "AI Horde: no job id", "detail": str(sub)[:200]}, 502)
        deadline = _t.time() + 90          # bounded — anon queue can be long
        text = None
        while _t.time() < deadline:
            _t.sleep(2)
            try:
                st = self._horde_req(f"/generate/text/status/{jid}")
            except Exception:
                continue
            if st.get("done"):
                gens = st.get("generations", [])
                text = (gens[0].get("text", "") if gens else "").strip()
                break
            if st.get("faulted"):
                return self._json({"error": "AI Horde job faulted"}, 502)
        if text is None:
            return self._json({"error": "AI Horde still cooking — anonymous queue is busy. "
                               "Try again, or add AIHORDE_API_KEY for priority.",
                               "job": jid}, 504)
        return self._json({
            "id": f"horde-{jid}", "object": "chat.completion", "model": "aihorde",
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": text}}],
        })

    def _horde_image(self, payload):
        """Horde image async → {images:[data-uri...]}. Separate shape from chat."""
        import time as _t, base64 as _b64
        prompt = payload.get("prompt", "")
        if not prompt.strip():
            return self._json({"error": "prompt required"}, 400)
        want = payload.get("model") or "stable_diffusion"
        req = {"prompt": prompt,
               "params": {"n": 1, "width": int(payload.get("width", 512)),
                          "height": int(payload.get("height", 512)),
                          "steps": int(payload.get("steps", 25))},
               "models": [want] if want else [], "nsfw": bool(payload.get("nsfw", False))}
        try:
            sub = self._horde_req("/generate/async", req, "POST")
        except Exception as e:
            return self._json({"error": f"AI Horde image: {e}"}, 502)
        jid = sub.get("id")
        if not jid:
            return self._json({"error": "AI Horde: no job id"}, 502)
        deadline = _t.time() + 150         # image gen is slower than text
        images = None
        while _t.time() < deadline:
            _t.sleep(3)
            try:
                st = self._horde_req(f"/generate/status/{jid}")
            except Exception:
                continue
            if st.get("done"):
                images = [g.get("img", "") for g in st.get("generations", [])]
                break
            if st.get("faulted"):
                return self._json({"error": "AI Horde image faulted"}, 502)
        if images is None:
            return self._json({"error": "AI Horde image still cooking — try again or add a key.",
                               "job": jid}, 504)
        return self._json({"images": images, "model": "aihorde", "job": jid})

    # ── manager API ───────────────────────────────────────────────────────────

    def _list_apps(self):
        """GET /api/apps — list sub-apps in ROOT."""
        import stat as _stat
        apps = []
        try:
            for entry in sorted(ROOT.iterdir(), key=lambda p: p.name.lower()):
                if entry.name.startswith("."):
                    continue
                resolved = entry.resolve()
                is_dir   = resolved.is_dir()
                idx      = (resolved / "index.html").is_file() if is_dir else False
                apps.append({
                    "name":       entry.name,
                    "path":       str(resolved),
                    "symlink":    entry.is_symlink(),
                    "has_index":  idx,
                    "url":        f"/{entry.name}/",
                })
        except Exception as e:
            return self._json({"error": str(e)}, 500)
        self._json({"apps": apps, "root": str(ROOT)})

    def _servers_status(self):
        """GET /api/servers — service health, port checks, recent log lines."""
        import subprocess, socket

        def proc_info(pattern):
            try:
                r = subprocess.run(["pgrep", "-af", pattern], capture_output=True, text=True, timeout=3)
                lines = [l.strip() for l in r.stdout.strip().splitlines() if l.strip() and "grep" not in l]
                if not lines:
                    return {"running": False, "pid": None, "cmd": None}
                parts = lines[0].split(None, 1)
                return {"running": True, "pid": int(parts[0]), "cmd": parts[1] if len(parts) > 1 else ""}
            except Exception:
                return {"running": False, "pid": None, "cmd": None}

        def port_open(host, port, timeout=1.0):
            try:
                with socket.create_connection((host, port), timeout=timeout):
                    return True
            except Exception:
                return False

        def log_tail(path, n=25):
            import re as _re
            ansi = _re.compile(r'\x1b\[[0-9;]*m')
            try:
                with open(path, "rb") as f:
                    f.seek(0, 2)
                    size = f.tell()
                    chunk = min(size, 16384)
                    f.seek(-chunk, 2)
                    raw = f.read().decode("utf-8", "replace")
                    raw = ansi.sub("", raw)
                    lines = [l for l in raw.splitlines() if l.strip('\x00').strip()]
                    return lines[-n:]
            except Exception as e:
                return [f"(log unavailable: {e})"]

        def mem_mb(pid):
            try:
                with open(f"/proc/{pid}/status") as f:
                    for line in f:
                        if line.startswith("VmRSS:"):
                            return round(int(line.split()[1]) / 1024, 1)
            except Exception:
                pass
            return None

        services = []

        # NeXuS Web Server (self)
        ws = proc_info("nexus_web_server")
        services.append({
            "id": "nexus-web",
            "name": "NeXuS Web Server",
            "desc": "HTTPS static + API proxy",
            **ws,
            "port": 8443,
            "port_ok": port_open("127.0.0.1", 8443),
            "mem_mb": mem_mb(ws["pid"]) if ws["pid"] else None,
            "log": None,
            "log_path": None,
            "links": [
                {"label": "Server script", "path": str(Path.home() / "Projects/nexus-web-server/nexus_web_server.py")},
                {"label": "Web root", "path": str(ROOT)},
            ],
            "docs": None,
        })

        # Conduit (Matrix) — match binary, not supervise-daemon
        cond = proc_info("/usr/bin/conduit")
        services.append({
            "id": "conduit",
            "name": "Conduit",
            "desc": "Matrix homeserver · matrix.nexusnet.network",
            **cond,
            "port": 6167,
            "port_ok": port_open("127.0.0.1", 6167),
            "mem_mb": mem_mb(cond["pid"]) if cond["pid"] else None,
            "log": log_tail("/var/log/conduit.log"),
            "log_path": "/var/log/conduit.log",
            "links": [
                {"label": "/var/lib/conduit/", "path": "/var/lib/conduit"},
                {"label": "Caddyfile", "path": "/etc/caddy/Caddyfile"},
            ],
            "docs": "https://conduit.rs/",
        })

        # Caddy
        caddy = proc_info("/usr/sbin/caddy")
        services.append({
            "id": "caddy",
            "name": "Caddy",
            "desc": "TLS reverse proxy (Matrix + future vhosts)",
            **caddy,
            "port": 443,
            "port_ok": port_open("127.0.0.1", 443),
            "mem_mb": mem_mb(caddy["pid"]) if caddy["pid"] else None,
            "log": None,
            "log_path": None,
            "links": [
                {"label": "Caddyfile", "path": "/etc/caddy/Caddyfile"},
            ],
            "docs": "https://caddyserver.com/docs/",
        })

        # NXS Search
        search = proc_info("nexus-search-serve")
        if not search["running"]:
            search = proc_info("app.py")
        services.append({
            "id": "nxs-search",
            "name": "NXS Search",
            "desc": "File-search · :5000",
            **search,
            "port": 5000,
            "port_ok": port_open("127.0.0.1", 5000),
            "mem_mb": mem_mb(search["pid"]) if search["pid"] else None,
            "log": None,
            "log_path": None,
            "links": [
                {"label": "App dir", "path": str(Path.home() / "NeXuS/nxs-search")},
            ],
            "docs": None,
        })

        # Copyparty file server
        cp = proc_info("copyparty")
        services.append({
            "id": "copyparty",
            "name": "Copyparty",
            "desc": "File server · upload · browse · /files/",
            **cp,
            "port": 8802,
            "port_ok": port_open("127.0.0.1", 8802),
            "mem_mb": mem_mb(cp["pid"]) if cp["pid"] else None,
            "log": log_tail("/tmp/nexus-copyparty-start.log"),
            "log_path": "/tmp/nexus-copyparty-start.log",
            "links": [
                {"label": "Open /files/", "path": "/files/"},
                {"label": "Upload dir", "path": str(Path.home() / "NeXuS/uploads")},
                {"label": "Script", "path": str(Path.home() / "scripts/nexus-copyparty.sh")},
            ],
            "docs": "https://github.com/9001/copyparty",
        })

        # Fail2ban
        f2b = proc_info("fail2ban-server")
        services.append({
            "id": "fail2ban",
            "name": "Fail2ban",
            "desc": "SSH / brute-force protection",
            **f2b,
            "port": None,
            "port_ok": None,
            "mem_mb": mem_mb(f2b["pid"]) if f2b["pid"] else None,
            "log": log_tail("/var/log/fail2ban.log"),
            "log_path": "/var/log/fail2ban.log",
            "links": [
                {"label": "/etc/fail2ban/", "path": "/etc/fail2ban"},
            ],
            "docs": None,
        })

        # Darkman
        dark = proc_info("darkman")
        services.append({
            "id": "darkman",
            "name": "Darkman",
            "desc": "Auto dark/light mode switcher (unconfigured)",
            **dark,
            "port": None,
            "port_ok": None,
            "mem_mb": mem_mb(dark["pid"]) if dark["pid"] else None,
            "log": None,
            "log_path": None,
            "links": [
                {"label": "Examples", "path": "/usr/share/darkman/examples"},
            ],
            "docs": "https://darkman.whynothugo.nl/",
        })

        self._json({"ts": __import__("time").time(), "services": services})

    def _upload_image(self):
        """POST /api/upload/image — accept multipart/form-data image upload, save to NEXUS_UPLOAD_IMAGES_DIR."""
        import cgi, uuid as _uuid
        ALLOWED = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".avif", ".svg"}
        ctype = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in ctype:
            return self._json({"error": "expected multipart/form-data"}, 400)
        length = int(self.headers.get("Content-Length", 0))
        if length > 50 * 1024 * 1024:
            return self._json({"error": "file too large (max 50 MB)"}, 413)
        env = {"REQUEST_METHOD": "POST", "CONTENT_TYPE": ctype, "CONTENT_LENGTH": str(length)}
        form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ=env)
        field = form.get("image") or form.get("file")
        if field is None or not field.filename:
            return self._json({"error": "no image field in upload"}, 400)
        ext = Path(field.filename).suffix.lower()
        if ext not in ALLOWED:
            return self._json({"error": f"unsupported type {ext}"}, 415)
        UPLOAD_IMAGES_DIR.mkdir(parents=True, exist_ok=True)
        name = f"{_uuid.uuid4().hex}{ext}"
        dest = UPLOAD_IMAGES_DIR / name
        dest.write_bytes(field.file.read())
        return self._json({"ok": True, "filename": name, "path": str(dest), "url": f"/uploads/images/{name}"})

    def _serve_upload(self, path):
        """GET /uploads/images/<filename> — serve a previously uploaded image."""
        filename = Path(path).name
        target = (UPLOAD_IMAGES_DIR / filename).resolve()
        if not str(target).startswith(str(UPLOAD_IMAGES_DIR.resolve())):
            return self._json({"error": "forbidden"}, 403)
        if not target.exists():
            return self._json({"error": "not found"}, 404)
        ctype = MIME_TYPES.get(target.suffix.lower(), "application/octet-stream")
        self._bytes(target.read_bytes(), ctype, cache="max-age=86400")

    def _wire_app(self):
        """POST /api/wire — run nexus-proxy-wire.sh on a given directory."""
        import subprocess, shlex
        try:
            length  = int(self.headers.get("Content-Length", 0))
            body    = json.loads(self.rfile.read(length)) if length else {}
        except Exception:
            return self._json({"error": "invalid JSON body"}, 400)

        app_path = body.get("path", "").strip()
        app_name = body.get("name", "").strip()

        # Validate path — must be absolute existing directory
        if not app_path or not os.path.isabs(app_path):
            return self._json({"error": "path must be an absolute directory path"}, 400)
        if not os.path.isdir(app_path):
            return self._json({"error": f"not a directory: {app_path}"}, 400)

        # Validate name — alphanumeric + dash only (prevents shell injection)
        if app_name and not re.match(r'^[a-z0-9][a-z0-9\-]{0,63}$', app_name):
            return self._json({"error": "name must be lowercase alphanumeric + dash"}, 400)

        wire = Path.home() / "scripts" / "nexus-proxy-wire.sh"
        if not wire.is_file():
            return self._json({"error": f"wire script not found: {wire}"}, 500)

        cmd = [str(wire), app_path] + ([app_name] if app_name else [])
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            output = result.stdout + result.stderr
            self._json({
                "success":    result.returncode == 0,
                "output":     output,
                "returncode": result.returncode,
                "name":       app_name or os.path.basename(app_path).lower(),
            })
        except subprocess.TimeoutExpired:
            self._json({"error": "wire timed out (180 s) — npm install may be slow", "output": ""}, 504)
        except Exception as e:
            self._json({"error": str(e)}, 500)

    # ── charcard reverse proxy ────────────────────────────────────────────────
    def _charcard_proxy(self):
        """Reverse-proxy /charcard/* → Flask PNG² editor at CHARCARD_BACKEND.
        Rewrites absolute paths in HTML responses so /thumb/, /card/, etc. work
        through the proxy prefix instead of resolving at the root."""
        parsed   = urllib.parse.urlparse(self.path)
        subpath  = parsed.path[len(CHARCARD_PREFIX):] or "/"
        target   = CHARCARD_BACKEND + subpath
        if parsed.query:
            target += "?" + parsed.query

        method      = self.command
        content_len = int(self.headers.get("Content-Length", 0) or 0)
        body        = self.rfile.read(content_len) if content_len > 0 else None

        req = urllib.request.Request(target, data=body, method=method)
        for h in ("Content-Type", "Accept", "X-Requested-With"):
            v = self.headers.get(h)
            if v:
                req.add_header(h, v)

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data  = resp.read()
                ctype = resp.headers.get("Content-Type", "application/octet-stream")
                if "text/html" in ctype:
                    html = data.decode("utf-8", errors="replace")
                    for old, new in [
                        ('src="/thumb/',      f'src="{CHARCARD_PREFIX}/thumb/'),
                        ("src='/thumb/",      f"src='{CHARCARD_PREFIX}/thumb/"),
                        ("'/thumb/' +",       f"'{CHARCARD_PREFIX}/thumb/' +"),
                        ('"/thumb/" +',       f'"{CHARCARD_PREFIX}/thumb/" +'),
                        ("fetch('/card/",     f"fetch('{CHARCARD_PREFIX}/card/"),
                        ('fetch("/card/',     f'fetch("{CHARCARD_PREFIX}/card/'),
                        ("fetch('/save/",     f"fetch('{CHARCARD_PREFIX}/save/"),
                        ('fetch("/save/',     f'fetch("{CHARCARD_PREFIX}/save/'),
                        ("fetch('/export/",   f"fetch('{CHARCARD_PREFIX}/export/"),
                        ('fetch("/export/',   f'fetch("{CHARCARD_PREFIX}/export/'),
                    ]:
                        html = html.replace(old, new)
                    data = html.encode("utf-8")
                self._send(resp.status, ctype, {"Content-Length": str(len(data))})
                self.wfile.write(data)
        except urllib.error.HTTPError as e:
            data  = e.read()
            ctype = e.headers.get("Content-Type", "text/html")
            self._send(e.code, ctype, {"Content-Length": str(len(data))})
            self.wfile.write(data)
        except Exception as e:
            self._json({"error": f"charcard backend unreachable — start PNG² editor first ({e})"}, 502)

    # ── static files with per-app SPA fallback ────────────────────────────────
    def _copyparty_proxy(self):
        """Reverse-proxy /files/* → copyparty at COPYPARTY_BACKEND."""
        parsed  = urllib.parse.urlparse(self.path)
        subpath = parsed.path[len(COPYPARTY_PREFIX):] or "/"
        target  = COPYPARTY_BACKEND + subpath
        if parsed.query:
            target += "?" + parsed.query

        method      = self.command
        content_len = int(self.headers.get("Content-Length", 0) or 0)
        body        = self.rfile.read(content_len) if content_len > 0 else None

        req = urllib.request.Request(target, data=body, method=method)
        for h in ("Content-Type", "Accept", "X-Requested-With", "Range"):
            v = self.headers.get(h)
            if v:
                req.add_header(h, v)
        req.add_header("X-Forwarded-Prefix", COPYPARTY_PREFIX)

        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data  = resp.read()
                ctype = resp.headers.get("Content-Type", "application/octet-stream")
                scode = resp.status
                if "text/html" in ctype:
                    text = data.decode("utf-8", errors="replace")
                    # rewrite absolute paths so assets resolve through the proxy prefix
                    text = text.replace('href="/',  f'href="{COPYPARTY_PREFIX}/')
                    text = text.replace("href='/",  f"href='{COPYPARTY_PREFIX}/")
                    text = text.replace('src="/',   f'src="{COPYPARTY_PREFIX}/')
                    text = text.replace("src='/",   f"src='{COPYPARTY_PREFIX}/")
                    text = text.replace('action="/', f'action="{COPYPARTY_PREFIX}/')
                    data = text.encode("utf-8")
                self._bytes(data, ctype, code=scode)
        except urllib.error.HTTPError as e:
            self._bytes(e.read(), e.headers.get("Content-Type", "text/plain"), code=e.code)
        except Exception as e:
            self._json({"error": f"copyparty unavailable: {e}"}, 502)

    def _grafana_proxy(self):
        """Reverse-proxy /grafana/* → Grafana.
        Path is preserved — Grafana owns the /grafana/ prefix via serve_from_sub_path."""
        parsed      = urllib.parse.urlparse(self.path)
        target      = GRAFANA_BACKEND + parsed.path
        if parsed.query:
            target += "?" + parsed.query

        method      = self.command
        content_len = int(self.headers.get("Content-Length", 0) or 0)
        body        = self.rfile.read(content_len) if content_len > 0 else None

        req = urllib.request.Request(target, data=body, method=method)
        for h in ("Content-Type", "Accept", "Authorization", "Cookie",
                  "X-Requested-With", "X-Grafana-Org-Id", "X-CSRF-Token",
                  "X-Grafana-NoCache", "If-None-Match", "If-Modified-Since"):
            v = self.headers.get(h)
            if v:
                req.add_header(h, v)

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data  = resp.read()
                ctype = resp.headers.get("Content-Type", "application/octet-stream")
                extra = {"Content-Length": str(len(data))}
                loc   = resp.headers.get("Location")
                if loc:
                    extra["Location"] = loc
                sc = resp.headers.get("Set-Cookie")
                if sc:
                    extra["Set-Cookie"] = sc
                etag = resp.headers.get("ETag")
                if etag:
                    extra["ETag"] = etag
                # Strip the proxy's own security headers — use Grafana's
                self._send(resp.status, ctype, extra, sec_override={})
                self.wfile.write(data)
        except urllib.error.HTTPError as e:
            data = e.read()
            self._bytes(data, e.headers.get("Content-Type", "text/plain"), code=e.code)
        except Exception as e:
            self._json({"error": f"Grafana unreachable — is it running? ({e})"}, 502)

    def _hister_proxy(self):
        """Reverse-proxy /hister/* → Hister on :4433.
        Hister owns its base_url prefix via server.base_url in config.yml."""
        parsed      = urllib.parse.urlparse(self.path)
        target      = HISTER_BACKEND + parsed.path
        if parsed.query:
            target += "?" + parsed.query

        method      = self.command
        content_len = int(self.headers.get("Content-Length", 0) or 0)
        body        = self.rfile.read(content_len) if content_len > 0 else None

        req = urllib.request.Request(target, data=body, method=method)
        for h in ("Content-Type", "Accept", "Authorization", "Cookie",
                  "X-Requested-With", "If-None-Match", "If-Modified-Since"):
            v = self.headers.get(h)
            if v:
                req.add_header(h, v)

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data  = resp.read()
                ctype = resp.headers.get("Content-Type", "application/octet-stream")
                extra = {"Content-Length": str(len(data))}
                loc   = resp.headers.get("Location")
                if loc:
                    extra["Location"] = loc
                sc = resp.headers.get("Set-Cookie")
                if sc:
                    extra["Set-Cookie"] = sc
                etag = resp.headers.get("ETag")
                if etag:
                    extra["ETag"] = etag
                self._send(resp.status, ctype, extra, sec_override={})
                self.wfile.write(data)
        except urllib.error.HTTPError as e:
            data = e.read()
            self._bytes(data, e.headers.get("Content-Type", "text/plain"), code=e.code)
        except Exception as e:
            self._json({"error": f"Hister unreachable — is it running? ({e})"}, 502)

    def _aichat_proxy(self):
        """Reverse-proxy /aichat/* → aichat --serve on :3030.
        Strips /aichat prefix so aichat sees its own root paths."""
        parsed  = urllib.parse.urlparse(self.path)
        subpath = parsed.path[len(AICHAT_PREFIX):]  # strip /aichat
        if not subpath or subpath == "/":
            subpath = "/playground"
        target  = AICHAT_BACKEND + subpath
        if parsed.query:
            target += "?" + parsed.query

        method      = self.command
        content_len = int(self.headers.get("Content-Length", 0) or 0)
        body        = self.rfile.read(content_len) if content_len > 0 else None

        req = urllib.request.Request(target, data=body, method=method)
        for h in ("Content-Type", "Accept", "Authorization", "Cookie",
                  "X-Requested-With", "If-None-Match", "If-Modified-Since"):
            v = self.headers.get(h)
            if v:
                req.add_header(h, v)

        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data  = resp.read()
                ctype = resp.headers.get("Content-Type", "application/octet-stream")
                extra = {"Content-Length": str(len(data))}
                loc   = resp.headers.get("Location")
                if loc:
                    extra["Location"] = loc
                self._send(resp.status, ctype, extra, sec_override={})
                self.wfile.write(data)
        except urllib.error.HTTPError as e:
            data = e.read()
            self._bytes(data, e.headers.get("Content-Type", "text/plain"), code=e.code)
        except Exception as e:
            self._json({"error": f"aichat unreachable — run: aichat --serve 3030 ({e})"}, 502)

    def _resolve(self, path):
        """Map a URL path to a file under ROOT. Returns (Path|None, is_spa_fallback)."""
        rel = urllib.parse.unquote(path).lstrip("/")
        # Containment check uses normpath (no symlink follow) so symlinked sub-apps are allowed.
        # Traversal (../../etc) is caught because normpath collapses the segments.
        root_r   = ROOT.resolve()
        norm     = Path(os.path.normpath(ROOT / rel))
        if not (norm == ROOT or str(norm).startswith(str(ROOT) + os.sep)):
            return None, False                       # traversal blocked
        # Resolve after containment check — now safe to follow symlinks into the real target.
        target = norm.resolve()
        # never serve secrets/dotfiles — even if one sits inside the web root
        if any(seg.startswith(".") and seg not in (".well-known",) for seg in rel.split("/") if seg) \
           or is_secret_path(norm):
            return None, False
        if target.is_dir():
            idx = target / "index.html"
            return (idx if idx.is_file() else target), False   # dir -> its index.html (or dir marker)
        if target.is_file():
            return target, False
        # SPA fallback: nearest index.html walking up toward ROOT
        parts = rel.split("/")
        while parts:
            parts.pop()
            cand = root_r.joinpath(*parts, "index.html") if parts else root_r / "index.html"
            if cand.is_file():
                return cand, True
        return None, False

    # Script injected into OpenCharacters HTML.
    # 1. Fetch interceptor — rewrites AI provider URLs to same-origin proxy, strips auth header.
    # 2. DB seeder — writes a dummy API key + nexus proxy model configs into OC's IndexedDB
    #    so OC's client-side "no key → skip" gate passes. Runs after a short delay to let
    #    OC create the DB schema first; idempotent (skips if already configured).
    _OC_INJECT = (
        '<script>/* NeXuS proxy auto-config for OpenCharacters */\n'
        '(function(){\n'
        '  var BASE=window.location.origin;\n'
        '\n'
        '  /* 1 ── fetch interceptor */\n'
        '  var MAP={\n'
        '    "api.openai.com":  BASE+"/api/llm/openai/v1",\n'
        '    "api.mistral.ai":  BASE+"/api/llm/mistral/v1",\n'
        '    "api.groq.com":    BASE+"/api/llm/groq/v1",\n'
        '    "openrouter.ai":   BASE+"/api/llm/openrouter/v1",\n'
        '    "aihorde.net":     BASE+"/api/llm/aihorde/v1",\n'
        '  };\n'
        '  var _f=window.fetch.bind(window);\n'
        '  window.fetch=async function(url,opts){\n'
        '    if(typeof url==="string"){\n'
        '      for(var host in MAP){\n'
        '        if(url.indexOf(host)!==-1){\n'
        '          url=MAP[host]+url.replace(/^https?:\\/\\/[^\\/]+/,"");\n'
        '          opts=Object.assign({},opts||{});\n'
        '          opts.headers=Object.assign({},opts.headers||{});\n'
        '          delete opts.headers["Authorization"];\n'
        '          delete opts.headers["authorization"];\n'
        '          break;\n'
        '        }\n'
        '      }\n'
        '    }\n'
        '    return _f(url,opts);\n'
        '  };\n'
        '\n'
        '  /* 2 ── seed IndexedDB after OC has had time to create the schema */\n'
        '  function seedDB(){\n'
        '    var req=indexedDB.open("chatbot-ui-v1");\n'
        '    req.onerror=function(){};\n'
        '    req.onsuccess=function(e){\n'
        '      var db=e.target.result;\n'
        '      if(!db.objectStoreNames.contains("misc")){db.close();return;}\n'
        '      var tx=db.transaction("misc","readwrite");\n'
        '      var st=tx.objectStore("misc");\n'
        '      /* dummy API key so OC\'s client-side gate passes */\n'
        '      var kr=st.get("openAiApiKey");\n'
        '      kr.onsuccess=function(e){\n'
        '        if(!e.target.result||!e.target.result.value)\n'
        '          st.put({key:"openAiApiKey",value:"nexus-proxy"});\n'
        '      };\n'
        '      /* proxy model configs — only if user hasn\'t set any */\n'
        '      var cr=st.get("customModelConfigs");\n'
        '      cr.onsuccess=function(e){\n'
        '        if(e.target.result&&e.target.result.value)return;\n'
        '        var cfgs=[\n'
        '          \'{ name:"nexus-mistral",shortLabel:"NeXuS · Mistral",\'\n'
        '          +\'endpointUrl:"\'+BASE+\'/api/llm/mistral/v1/chat/completions",\'\n'
        '          +\'apiKey:"nexus-proxy",maxSequenceLength:32768,\'\n'
        '          +\'type:"chat-completion",tokenPricing:{prompt:0,completion:0} }\',\n'
        '          \'{ name:"nexus-groq",shortLabel:"NeXuS · Groq",\'\n'
        '          +\'endpointUrl:"\'+BASE+\'/api/llm/groq/v1/chat/completions",\'\n'
        '          +\'apiKey:"nexus-proxy",maxSequenceLength:32768,\'\n'
        '          +\'type:"chat-completion",tokenPricing:{prompt:0,completion:0} }\',\n'
        '          \'{ name:"nexus-openai",shortLabel:"NeXuS · OpenAI",\'\n'
        '          +\'endpointUrl:"\'+BASE+\'/api/llm/openai/v1/chat/completions",\'\n'
        '          +\'apiKey:"nexus-proxy",maxSequenceLength:128000,\'\n'
        '          +\'type:"chat-completion",tokenPricing:{prompt:0,completion:0} }\',\n'
        '        ].join("\\n");\n'
        '        st.put({key:"customModelConfigs",value:cfgs});\n'
        '      };\n'
        '      tx.oncomplete=function(){db.close();};\n'
        '    };\n'
        '  }\n'
        '  /* delay so OC can create the DB schema first */\n'
        '  setTimeout(seedDB,1500);\n'
        '})();\n'
        '</script>'
    )

    # ── App registry routing ──────────────────────────────────────────────────
    def _match_registry(self, path):
        for aid, app in APP_REGISTRY.items():
            pfx = app["prefix"]
            if path == pfx or path.startswith(pfx + "/"):
                return app
        return None

    def _dispatch_registry(self, app, path):
        pfx        = app["prefix"]
        rel        = path[len(pfx):]          # e.g. /api/networks or /css/nexus.css
        api_pfx    = app["api_prefix"]
        has_static  = bool(app["static"])
        has_backend = bool(app["backend"])

        # Redirect bare prefix (no trailing slash) to prefix/ so relative asset
        # paths (css/nexus.css, js/app.js) resolve correctly in the browser.
        if has_static and rel == "" and not path.endswith("/"):
            self.send_response(301)
            self.send_header("Location", pfx + "/")
            self.end_headers()
            return

        # proxy if: backend exists AND (no api_prefix OR rel starts with api_prefix)
        if has_backend and (not api_pfx or rel.startswith(api_pfx) or rel.startswith(api_pfx + "/")):
            return self._registry_proxy(app, rel)
        if has_static:
            return self._registry_static(app, rel)
        if has_backend:
            # no api_prefix restriction — proxy everything
            return self._registry_proxy(app, rel)
        return self._json({"error": "app misconfigured"}, 500)

    def _registry_proxy(self, app, rel):
        parsed = urllib.parse.urlparse(self.path)
        qs     = ("?" + parsed.query) if parsed.query else ""
        url    = app["backend"].rstrip("/") + (rel or "/") + qs

        length = int(self.headers.get("Content-Length", 0) or 0)
        body   = self.rfile.read(length) if length > 0 else None

        fwd = {"User-Agent": UA}
        ct  = self.headers.get("Content-Type")
        if ct:
            fwd["Content-Type"] = ct
        auth = self.headers.get("Authorization")
        if auth:
            fwd["Authorization"] = auth

        try:
            req = urllib.request.Request(url, data=body, headers=fwd, method=self.command)
            with urllib.request.urlopen(req, timeout=30) as resp:
                data  = resp.read()
                ctype = resp.headers.get("Content-Type", "application/octet-stream")
                self._bytes(data, ctype)
        except urllib.error.HTTPError as e:
            data  = e.read()
            ctype = e.headers.get("Content-Type", "application/json")
            self._bytes(data, ctype, e.code)
        except Exception as e:
            import errno as _errno
            is_refused = (
                isinstance(e, ConnectionRefusedError) or
                (hasattr(e, 'reason') and isinstance(getattr(e, 'reason', None), ConnectionRefusedError)) or
                (hasattr(e, 'reason') and getattr(getattr(e, 'reason', None), 'errno', None) == _errno.ECONNREFUSED)
            )
            start_cmd = app.get("start", "")
            if is_refused and start_cmd:
                import subprocess as _sp
                try:
                    _sp.Popen(start_cmd, shell=True, stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
                except Exception:
                    pass
                label = app.get("label", app["backend"])
                pfx   = app["prefix"]
                splash = f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><title>Starting {label}…</title>
<style>
  body{{background:#0d1117;color:#c9d1d9;font-family:'Segoe UI',system-ui,sans-serif;
        display:flex;flex-direction:column;align-items:center;justify-content:center;
        min-height:100vh;margin:0;gap:20px;}}
  .logo{{font-family:monospace;font-size:18px;font-weight:800;color:#39d353;letter-spacing:2px;}}
  .title{{font-size:22px;font-weight:600;}}
  .sub{{color:#6e7681;font-size:14px;}}
  .spinner{{width:48px;height:48px;border:4px solid #30363d;border-top:4px solid #39d353;
            border-radius:50%;animation:spin 0.9s linear infinite;}}
  @keyframes spin{{to{{transform:rotate(360deg)}}}}
  .bar-wrap{{width:280px;height:4px;background:#30363d;border-radius:2px;overflow:hidden;}}
  .bar{{height:100%;background:linear-gradient(90deg,#39d353,#58a6ff);
        border-radius:2px;animation:fill 8s linear forwards;}}
  @keyframes fill{{from{{width:0%}}to{{width:100%}}}}
</style>
<script>
  var attempts=0;
  function check(){{
    attempts++;
    fetch('/api/nexus/app-status?prefix={pfx}',{{cache:'no-cache'}})
      .then(r=>r.json())
      .then(d=>{{ if(d.up){{window.location='{pfx}/';}}else{{retry();}} }})
      .catch(()=>retry());
  }}
  function retry(){{
    if(attempts<40)setTimeout(check, attempts<5?2000:4000);
    else document.getElementById('msg').textContent='Service taking longer than expected — try refreshing manually.';
  }}
  setTimeout(check, 3000);
</script>
</head><body>
<div class="logo">NeXuS</div>
<div class="spinner"></div>
<div class="title">Starting {label}…</div>
<div class="sub" id="msg">This usually takes 5–15 seconds. The page will redirect automatically.</div>
<div class="bar-wrap"><div class="bar"></div></div>
</body></html>"""
                self._bytes(splash.encode(), "text/html; charset=utf-8", 503)
            else:
                self._json({"error": f"{app['backend']} unavailable: {str(e)[:120]}"}, 503)

    def _registry_static(self, app, rel):
        static_dir = Path(app["static"]).expanduser().resolve()
        file_rel   = (rel or "/index.html").lstrip("/") or "index.html"
        target     = (static_dir / file_rel).resolve()

        # security: must stay inside static_dir
        if not str(target).startswith(str(static_dir)):
            return self._json({"error": "forbidden"}, 403)

        # dir → index.html
        if target.is_dir():
            target = target / "index.html"

        # SPA fallback
        if not target.exists():
            target = static_dir / "index.html"

        if not target.is_file():
            return self._json({"error": "not found"}, 404)

        ctype = MIME_TYPES.get(target.suffix.lower(), "application/octet-stream")
        # Extensionless files with JS content (e.g. toastify-js) — sniff first bytes
        if ctype == "application/octet-stream" and not target.suffix:
            try:
                first = target.read_bytes()[:256].lstrip()
                if first[:2] in (b"/*", b"//") or first[:3] in (b"var", b"fun", b"let", b"con"):
                    ctype = "application/javascript"
            except Exception:
                pass
        data  = target.read_bytes()

        # For apps with rewrite_api, use permissive headers so complex single-file
        # apps (OC, etc.) can initialize without CSP blocking their CDN deps.
        sec = None
        if app.get("rewrite_api"):
            sec = {k: v for k, v in SECURITY_HEADERS.items()
                   if k != "Content-Security-Policy" and k != "X-Content-Type-Options"}

        # Optional: rewrite external AI provider URLs to local proxy paths.
        # Enabled per-app via NEXUS_APP_<ID>_rewrite_api=1 in nexus.env.
        if app.get("rewrite_api") and ctype in (
            "text/html", "application/javascript", "text/javascript"
        ):
            data = self._rewrite_api_urls(data, app["prefix"])

        self._bytes(data, ctype, sec_override=sec)

    # Build a rewrite map from the live provider registry so it stays in sync.
    def _rewrite_api_urls(self, data: bytes, app_prefix: str) -> bytes:
        import re as _re
        text = data.decode("utf-8", errors="replace")
        # OC's otherCharacterList contains multi-line single-quoted string literals
        # (raw newlines inside '' quotes) — a SyntaxError that kills the entire script.
        # These are just community example characters; null the array to fix parsing.
        text = _re.sub(
            r'let otherCharacterList\s*=\s*\[.*?\n\s*\];',
            'let otherCharacterList = [];',
            text, flags=_re.DOTALL
        )
        # index.html has the marked CDN script commented out, so marked.parse() throws.
        text = text.replace(
            '<!-- <script src="https://cdn.jsdelivr.net/npm/marked@4.2.12/marked.min.js"></script> -->',
            '<script src="https://cdn.jsdelivr.net/npm/marked@4.2.12/marked.min.js"></script>'
        )
        provs = discover_providers()
        # Rewrite known provider base URLs → same-origin /api/llm/<id>/v1.
        # Skips api.openai.com — those are handled at runtime by the injected fetch proxy
        # so OpenAI model names (gpt-4 etc.) pass through to OpenRouter unchanged.
        _SKIP_DOMAINS = {"api.openai.com"}
        for pid, prov in provs.items():
            ext = prov["base_url"].rstrip("/")
            if any(d in ext for d in _SKIP_DOMAINS):
                continue
            local = f"/api/llm/{pid}/v1"
            text = text.replace(ext, local)
        _DOMAIN_MAP = {
            "https://api.mistral.ai/v1":       "/api/llm/mistral/v1",
            "https://api.groq.com/openai/v1":  "/api/llm/groq/v1",
            "https://openrouter.ai/api/v1":    "/api/llm/openrouter/v1",
            "https://api.together.xyz/v1":     "/api/llm/together/v1",
            "https://api.anthropic.com/v1":    "/api/llm/anthropic/v1",
            "https://api.mistral.ai":          "/api/llm/mistral",
            "https://api.groq.com":            "/api/llm/groq",
            "https://openrouter.ai":           "/api/llm/openrouter",
            "https://api.together.xyz":        "/api/llm/together",
            "https://api.anthropic.com":       "/api/llm/anthropic",
        }
        for ext, local in _DOMAIN_MAP.items():
            text = text.replace(ext, local)
        # Stub out OC's getOpenAiApiKey() so it never prompts for a key.
        # The proxy injects the real key server-side regardless of what OC sends.
        # We replace the whole function body; the === "<OPENAI>" checks still fire
        # and call this function, but it returns "nexus-proxy" immediately.
        _GET_KEY_ORIG = (
            'async function getOpenAiApiKey() {\n'
            '              let apiKey = (await db.misc.get("openAiApiKey"))?.value;\n'
            '              while (!apiKey) {\n'
            '                let result = await prompt2({\n'
            '                  openAiApiKey: { label: "Please create a new OpenAI API secret key and paste it here. Go to <a style=\'color:blue\' href=\'https://platform.mistral.ai/account/api-keys\' target=\'_blank\'>this page</a> to do that. You can change or delete this later by clicking the \'settings\' button.", type: "textLine", placeholder: "sk-...", focus: true },\n'
            '                });\n'
            '                if (!result || !result.openAiApiKey) continue;\n'
            '                apiKey = result.openAiApiKey;\n'
            '                break;\n'
            '              }\n'
            '              await db.misc.put({ key: "openAiApiKey", value: apiKey });\n'
            '              return apiKey;\n'
            '            }'
        )
        _GET_KEY_STUB = 'async function getOpenAiApiKey() { return "nexus-proxy"; }'
        if _GET_KEY_ORIG in text:
            text = text.replace(_GET_KEY_ORIG, _GET_KEY_STUB)
        # index.html fetches the key inline (3×) rather than via getOpenAiApiKey().
        # Stub the DB lookup so it never prompts — proxy injects real key server-side.
        text = text.replace(
            'let OPENAI_API_KEY = (await db.misc.get("openAiApiKey"))?.value;',
            'let OPENAI_API_KEY = "nexus-proxy";'
        )
        # Inject a fetch proxy that intercepts remaining api.openai.com runtime calls,
        # routes them to Groq (fast, free tier), and translates gpt-* model names.
        # Runs before any user interaction so OC never reaches the real OpenAI endpoint.
        _FETCH_PROXY = (
            '<script>\n'
            '(function(){\n'
            '  var P="groq";\n'
            '  var M={"gpt-4":"groq/compound","gpt-4-turbo":"groq/compound",\n'
            '    "gpt-4-turbo-preview":"groq/compound","gpt-4-0125-preview":"groq/compound",\n'
            '    "gpt-3.5-turbo":"groq/compound-mini","gpt-3.5-turbo-16k":"groq/compound-mini"};\n'
            '  window.fetch=new Proxy(window.fetch,{apply:async function(t,s,a){\n'
            '    var url=a[0],opts=a[1]||{};\n'
            '    if(typeof url==="string"&&url.includes("api.openai.com")){\n'
            '      url=url.replace("https://api.openai.com","https://localhost:8443/api/llm/"+P);\n'
            '      if(!opts.headers)opts.headers={};\n'
            '      opts.headers.authorization="Bearer nexus-proxy";\n'
            '      if(opts.body){try{\n'
            '        var b=JSON.parse(opts.body);\n'
            '        /* model name kept as-is so OC modelNameToModelType lookup still works */\n'
            '        /* proxy translates gpt-* → groq/compound server-side */\n'
            '        opts.body=JSON.stringify(b);\n'
            '      }catch(e){}}\n'
            '      a=[url,opts,...a.slice(2)];\n'
            '    }\n'
            '    return t.apply(s,a);\n'
            '  }});\n'
            '})();\n'
            '</script>'
        )
        # Replace the LAST </body> — DOMPurify's inline code contains an earlier one as a string literal.
        idx = text.rfind("</body>")
        if idx != -1:
            text = text[:idx] + _FETCH_PROXY + "\n</body>" + text[idx+7:]
        return text.encode("utf-8")

    # ── NeXuS Living Timeline ─────────────────────────────────────────────────
    def _serve_timeline(self):
        nexus_home = Path(os.environ.get("NEXUS_HOME", Path.home() / "NeXuS"))
        md_path = nexus_home / "timeline" / "NEXUS_TIMELINE.md"
        if not md_path.is_file():
            return self._json({"error": "timeline not found", "expected": str(md_path)}, 404)
        md = md_path.read_text(encoding="utf-8")
        page = self._timeline_render(md)
        self._bytes(page.encode("utf-8"), "text/html")

    def _serve_timeline_image(self, path):
        nexus_home = Path(os.environ.get("NEXUS_HOME", Path.home() / "NeXuS"))
        timeline_dir = (nexus_home / "timeline").resolve()
        # /timeline/images/diagrams/foo.png → timeline/images/diagrams/foo.png
        rel = path[len("/timeline/"):]
        img_path = (timeline_dir / rel).resolve()
        if not str(img_path).startswith(str(timeline_dir)):
            return self._json({"error": "forbidden"}, 403)
        if not img_path.is_file():
            return self._json({"error": "not found"}, 404)
        ctype = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
                 ".gif": "image/gif", ".webp": "image/webp",
                 ".svg": "image/svg+xml"}.get(img_path.suffix.lower(), "application/octet-stream")
        self._bytes(img_path.read_bytes(), ctype)

    # ── NeXuS Map — intranet home ─────────────────────────────────────────────
    def _serve_map(self):
        self._bytes(self._map_html(), "text/html", cache="no-cache")

    def _nexus_api(self, path):
        sub = path[len("/api/nexus/"):]
        if sub in ("map", "map/"):
            return self._nexus_api_map()
        if sub in ("wiki-sync", "wiki-sync/") and self.command == "POST":
            return self._nexus_wiki_sync()
        if sub.startswith("portcheck"):
            return self._nexus_portcheck()
        if sub.startswith("service/") and self.command == "POST":
            return self._nexus_service_ctl(sub[len("service/"):])
        if sub.startswith("exec") and self.command == "POST":
            return self._nexus_exec()
        if sub.startswith("appmon") and self.command == "GET":
            return self._nexus_appmon()
        if sub.startswith("ncm/status") and self.command == "GET":
            return self._nexus_ncm_status()
        if sub.startswith("ncm/action") and self.command == "POST":
            return self._nexus_ncm_action()
        if sub.startswith("governor"):
            return self._nexus_governor(sub[len("governor"):].lstrip("/"))
        if sub.startswith("app-status"):
            return self._nexus_app_status()
        if sub.startswith("publish") and self.command == "POST":
            return self._nexus_publish()
        if sub.startswith("posts") and self.command == "GET":
            return self._nexus_posts()
        if sub.startswith("aether/"):
            return self._nexus_aether(sub[len("aether/"):])
        if sub.startswith("rss-fetch"):
            return self._nexus_rss_fetch()
        if sub.startswith("spider"):
            return self._nexus_spider()
        if sub.startswith("search-web"):
            return self._nexus_search_web()
        return self._json({"error": f"unknown nexus API route: {path}"}, 404)

    # ── twtxt feed ───────────────────────────────────────────────────────────

    def _serve_twtxt_feed(self):
        twtxt = Path.home() / "NeXuS" / "projects" / "nexus-publisher" / "data" / "twtxt.txt"
        data  = twtxt.read_bytes() if twtxt.is_file() else b""
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # ── Publisher proxy ───────────────────────────────────────────────────────

    _PUB_URL = "http://127.0.0.1:8092"

    def _nexus_publish(self):
        """POST /api/nexus/publish → forwards to nexus_publisher.py, auto-starts if needed."""
        import subprocess as _sp, sys as _sys
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length) if length else b"{}"
        try:
            import urllib.request as _ur
            req = _ur.Request(self._PUB_URL + "/publish", data=body,
                              headers={"Content-Type": "application/json"}, method="POST")
            with _ur.urlopen(req, timeout=25) as r:
                return self._json(json.loads(r.read()))
        except Exception:
            # publisher not running — start it
            pub = Path.home() / "NeXuS" / "projects" / "nexus-publisher" / "nexus_publisher.py"
            _sp.Popen([_sys.executable, str(pub)], stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
            import time as _t; _t.sleep(2)
            try:
                req = urllib.request.Request(self._PUB_URL + "/publish", data=body,
                                             headers={"Content-Type": "application/json"}, method="POST")
                with urllib.request.urlopen(req, timeout=25) as r:
                    return self._json(json.loads(r.read()))
            except Exception as e:
                return self._json({"error": f"publisher unavailable: {e}"}, 503)

    def _nexus_posts(self):
        """GET /api/nexus/posts → recent posts from nexus_publisher."""
        try:
            with urllib.request.urlopen(self._PUB_URL + "/posts", timeout=5) as r:
                return self._json(json.loads(r.read()))
        except Exception:
            posts_file = Path.home() / "NeXuS" / "projects" / "nexus-publisher" / "data" / "posts.jsonl"
            if posts_file.is_file():
                posts = []
                for ln in reversed(posts_file.read_text().splitlines()[-50:]):
                    try: posts.append(json.loads(ln))
                    except: pass
                return self._json({"posts": posts})
            return self._json({"posts": []})

    # ── Aether Production House — radio / broadcast / fireside / AI control ─────
    #
    # Control surface shared by the human studio UI and (when authorized) the AI
    # autopilot. Every shell-out is whitelisted; no request input is ever passed
    # to a shell. Captain's Chair doctrine: AI may act only within granted scopes.

    _AETHER_SH        = str(Path.home() / "NeXuS" / "scripts" / "nexus-aether.sh")
    _AETHER_CAST_SH   = str(Path.home() / "NeXuS" / "scripts" / "nexus-aether-broadcast.sh")
    _AETHER_CONF      = str(Path.home() / "NeXuS" / "projects" / "nexus-aether" / "conf" / "broadcast.conf")
    _FIRESIDE_LOG     = Path.home() / "NeXuS" / "projects" / "nexus-aether" / "chat" / "fireside.jsonl"
    _AUTHORITY_FILE   = SECRETS_DIR / "aether_ai_authority.json"
    _RADIO_CMDS       = ("play", "pause", "next", "prev", "stop", "status")
    _NET_NAMES        = ("tor", "i2p", "yggdrasil", "nostr", "matrix", "activitypub")
    _AI_SCOPES        = ("radio", "soundboard", "chat", "networks")

    def _nexus_aether(self, tail):
        tail = tail.rstrip("/")
        if tail == "status":                 return self._aether_status()
        if tail == "authority":              return self._aether_authority()
        if tail == "networks":               return self._aether_networks()
        if tail == "chat":                   return self._aether_chat()
        if tail == "personas":               return self._aether_personas()
        if tail == "interview" and self.command == "POST":
            return self._aether_interview()
        if tail == "broadcast" and self.command == "POST":
            return self._aether_broadcast()
        if tail == "cameras":
            return self._aether_cameras()
        if tail == "camera" and self.command == "POST":
            return self._aether_camera_ctl()
        if tail.startswith("camera-mjpeg"):
            return self._aether_camera_mjpeg()
        if tail == "image" and self.command == "POST":
            length = int(self.headers.get("Content-Length", 0))
            try: body = json.loads(self.rfile.read(length) or b"{}")
            except Exception: return self._json({"error": "bad json"}, 400)
            # Default image provider is AI Horde (free). Others can be added later.
            return self._horde_image(body)
        if tail.startswith("radio/") and self.command == "POST":
            return self._aether_radio(tail[len("radio/"):])
        if tail.startswith("network/") and self.command == "POST":
            return self._aether_network(tail[len("network/"):])
        return self._json({"error": f"unknown aether route: {tail}"}, 404)

    def _sh(self, cmd, timeout=15):
        """Run a whitelisted command list, return (rc, combined output)."""
        import subprocess as _sp
        try:
            r = _sp.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.returncode, (r.stdout + r.stderr).strip()
        except Exception as e:
            return 1, str(e)

    def _aether_status(self):
        """GET /api/nexus/aether/status — service state + now-playing + queue + stream URL."""
        import shutil, socket as _sock
        def _port_up(p):
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM); s.settimeout(0.4)
            try: return s.connect_ex(("127.0.0.1", p)) == 0
            finally: s.close()
        have_mpc = shutil.which("mpc") is not None
        now_playing, state, queue = "", "stopped", []
        mpd_up = False
        if have_mpc:
            rc, st = self._sh(["mpc", "status"], timeout=4)
            mpd_up = rc == 0 and "error" not in st.lower()
            if mpd_up:
                _, cur = self._sh(["mpc", "current"], timeout=4)
                now_playing = cur if "error" not in cur.lower() else ""
                import re as _re
                m = _re.search(r"\[(\w+)\]", st); state = m.group(1) if m else "stopped"
                _, pl = self._sh(["mpc", "playlist"], timeout=4)
                queue = [l for l in pl.splitlines() if l and "error" not in l.lower()][:30]
        return self._json({
            "stream_url":  load_secret("NEXUS_RADIO_STREAM") or "http://127.0.0.1:8000/nexus.ogg",
            "mpd":         mpd_up,
            "mpd_installed": have_mpc,
            "icecast":     _port_up(int(load_secret("NEXUS_RADIO_PORT") or 8000)),
            "murmur":      _port_up(64738),
            "owncast":     _port_up(8086),
            "state":       state,
            "now_playing": now_playing,
            "queue":       queue,
        })

    def _aether_radio(self, cmd):
        """POST /api/nexus/aether/radio/{play|pause|next|prev|stop|status} — whitelisted."""
        cmd = cmd.strip("/")
        if cmd not in self._RADIO_CMDS:
            return self._json({"error": f"radio cmd not allowed: {cmd}"}, 400)
        if not self._ai_allowed("radio"):
            return self._json({"error": "AI autopilot lacks 'radio' scope"}, 403)
        if not Path(self._AETHER_SH).exists():
            return self._json({"error": "nexus-aether.sh not found"}, 503)
        rc, out = self._sh(["sh", self._AETHER_SH, "radio", cmd])
        return self._json({"ok": rc == 0, "cmd": cmd, "output": out})

    def _aether_networks(self):
        """GET /api/nexus/aether/networks — parse broadcast.conf BROADCAST_* states."""
        states = {}
        conf = Path(self._AETHER_CONF)
        if conf.is_file():
            for ln in conf.read_text().splitlines():
                ln = ln.strip()
                if ln.startswith("BROADCAST_") and "=" in ln:
                    k, v = ln.split("=", 1)
                    states[k[len("BROADCAST_"):].lower()] = v.strip().strip('"') == "1"
        return self._json({"networks": states})

    def _aether_network(self, tail):
        """POST /api/nexus/aether/network/{net}/{enable|disable} — whitelisted."""
        parts = tail.strip("/").split("/")
        if len(parts) != 2:
            return self._json({"error": "usage: network/{net}/{enable|disable}"}, 400)
        net, action = parts[0].lower(), parts[1]
        if net not in self._NET_NAMES or action not in ("enable", "disable"):
            return self._json({"error": "invalid network or action"}, 400)
        if not self._ai_allowed("networks"):
            return self._json({"error": "AI autopilot lacks 'networks' scope"}, 403)
        if not Path(self._AETHER_CAST_SH).exists():
            return self._json({"error": "nexus-aether-broadcast.sh not found"}, 503)
        rc, out = self._sh(["sh", self._AETHER_CAST_SH, action, net])
        return self._json({"ok": rc == 0, "network": net, "action": action, "output": out})

    # ── Camera sources via go2rtc (phone / IP cam / Pi Zero → WebRTC hub) ───────

    def _go2rtc_url(self):
        return (load_secret("NEXUS_GO2RTC_URL") or "http://127.0.0.1:1984").rstrip("/")

    def _aether_cameras(self):
        """GET → go2rtc streams + status. Proxied so the HTTPS studio stays same-origin."""
        base = self._go2rtc_url()
        try:
            with urllib.request.urlopen(base + "/api/streams", timeout=5) as r:
                streams = json.loads(r.read())
            names = list(streams.keys()) if isinstance(streams, dict) else []
            return self._json({"up": True, "cameras": names, "go2rtc": base})
        except Exception as e:
            return self._json({"up": False, "cameras": [], "go2rtc": base,
                               "error": f"go2rtc unreachable: {e}"})

    def _aether_camera_ctl(self):
        """POST {action:add|remove, name, src} → manage a go2rtc stream.
        src/name go to go2rtc's HTTP API (not a shell) — injection-safe."""
        import urllib.parse as _up
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return self._json({"error": "bad json"}, 400)
        action = body.get("action", "add")
        name   = str(body.get("name", "")).strip()
        base   = self._go2rtc_url()
        if not name:
            return self._json({"error": "name required"}, 400)
        try:
            if action == "add":
                src = str(body.get("src", "")).strip()
                if not src:
                    return self._json({"error": "src required"}, 400)
                q = _up.urlencode({"name": name, "src": src})
                req = urllib.request.Request(f"{base}/api/streams?{q}", method="PUT")
            elif action == "remove":
                q = _up.urlencode({"src": name})
                req = urllib.request.Request(f"{base}/api/streams?{q}", method="DELETE")
            else:
                return self._json({"error": f"bad action: {action}"}, 400)
            with urllib.request.urlopen(req, timeout=8) as r:
                r.read()
            return self._json({"ok": True, "action": action, "name": name})
        except Exception as e:
            return self._json({"error": f"go2rtc: {e}"}, 502)

    def _aether_camera_mjpeg(self):
        """GET ?src=NAME → proxy go2rtc's MJPEG preview (same-origin HTTPS for the studio)."""
        import urllib.parse as _up
        qs  = _up.parse_qs(_up.urlparse(self.path).query)
        src = qs.get("src", [""])[0]
        if not src:
            return self._json({"error": "src required"}, 400)
        base = self._go2rtc_url()
        url  = f"{base}/api/stream.mjpeg?{_up.urlencode({'src': src})}"
        try:
            up = urllib.request.urlopen(url, timeout=10)
        except Exception as e:
            return self._json({"error": f"go2rtc mjpeg: {e}"}, 502)
        self.send_response(200)
        self.send_header("Content-Type", up.headers.get("Content-Type", "multipart/x-mixed-replace"))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            while (chunk := up.read(8192)):
                self.wfile.write(chunk)
                self.wfile.flush()
        except Exception:
            pass
        finally:
            up.close()

    # ── Forge Sessions — announce a live session to enabled networks ────────────

    def _aether_broadcast(self):
        """POST {title, desc?, live?, stream_url?} → announce to enabled networks.
        Args passed as a subprocess list (no shell) so titles are injection-safe."""
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return self._json({"error": "bad json"}, 400)
        if not self._ai_allowed("networks"):
            return self._json({"error": "AI autopilot lacks 'networks' scope"}, 403)
        if not Path(self._AETHER_CAST_SH).exists():
            return self._json({"error": "nexus-aether-broadcast.sh not found"}, 503)
        title = str(body.get("title", "Forge Session"))[:200]
        desc  = str(body.get("desc", "The Forge Beyond the CoDe where the code becomes alive · Na PH"))[:500]
        if body.get("live"):
            url = str(body.get("stream_url", ""))[:300]
            rc, out = self._sh(["sh", self._AETHER_CAST_SH, "live", url, title], timeout=30)
        else:
            rc, out = self._sh(["sh", self._AETHER_CAST_SH, "announce", title, desc], timeout=30)
        return self._json({
            "ok": rc == 0, "title": title, "output": out,
            "rtmp_ingest": load_secret("NEXUS_OWNCAST_RTMP") or "rtmp://127.0.0.1:1935/live",
        })

    # ── AI authority (Captain's Chair) ─────────────────────────────────────────

    def _load_authority(self):
        try:
            return json.loads(self._AUTHORITY_FILE.read_text())
        except Exception:
            return {"enabled": False, "scopes": {s: False for s in self._AI_SCOPES}}

    def _ai_allowed(self, scope):
        """Human UI calls carry X-Nexus-Origin: user and always pass. AI-origin calls
        (X-Nexus-Origin: ai) must have autopilot enabled AND the scope granted."""
        if self.headers.get("X-Nexus-Origin", "user").lower() != "ai":
            return True
        a = self._load_authority()
        return bool(a.get("enabled")) and bool(a.get("scopes", {}).get(scope))

    def _aether_authority(self):
        """GET  → current AI authority state.
        POST → {enabled, scopes:{radio,soundboard,chat,networks}} — user sets grants."""
        if self.command == "GET":
            return self._json(self._load_authority())
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return self._json({"error": "bad json"}, 400)
        scopes = {s: bool(body.get("scopes", {}).get(s)) for s in self._AI_SCOPES}
        state  = {"enabled": bool(body.get("enabled")), "scopes": scopes}
        try:
            self._AUTHORITY_FILE.parent.mkdir(parents=True, exist_ok=True)
            self._AUTHORITY_FILE.write_text(json.dumps(state, indent=2))
            os.chmod(self._AUTHORITY_FILE, 0o600)
        except Exception as e:
            return self._json({"error": str(e)}, 500)
        return self._json({"ok": True, **state})

    # ── Fireside chat (local JSONL; optional Matrix mirror) ─────────────────────

    def _aether_chat(self):
        """GET  → last 100 fireside messages.
        POST → {author, role, text} append a message (human or AI)."""
        if self.command == "GET":
            msgs = []
            if self._FIRESIDE_LOG.is_file():
                for ln in self._FIRESIDE_LOG.read_text().splitlines()[-100:]:
                    try: msgs.append(json.loads(ln))
                    except: pass
            return self._json({"messages": msgs})
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return self._json({"error": "bad json"}, 400)
        role = body.get("role", "human")
        if role == "ai" and not self._ai_allowed("chat"):
            return self._json({"error": "AI autopilot lacks 'chat' scope"}, 403)
        msg = {
            "author": str(body.get("author", "anon"))[:64],
            "role":   role,
            "text":   str(body.get("text", ""))[:2000],
            "ts":     __import__("time").time(),
        }
        if not msg["text"].strip():
            return self._json({"error": "empty message"}, 400)
        try:
            self._FIRESIDE_LOG.parent.mkdir(parents=True, exist_ok=True)
            with self._FIRESIDE_LOG.open("a") as f:
                f.write(json.dumps(msg) + "\n")
        except Exception as e:
            return self._json({"error": str(e)}, 500)
        return self._json({"ok": True, "message": msg})

    # ── Personas + live interview ───────────────────────────────────────────────

    def _aether_personas(self):
        """GET → persona list from the characters dir + AI Foundry (best-effort)."""
        personas = []
        chars = Path(load_secret("CARDS_DIR") or (Path.home() / "NeXuS" / "characters"))
        if chars.is_dir():
            for d in sorted(chars.iterdir()):
                if d.is_dir() and (d / f"{d.name}.json").exists():
                    personas.append({"id": d.name, "name": d.name, "source": "characters"})
        return self._json({"personas": personas})

    def _aether_interview(self):
        """POST {persona, question} → ask the persona, append Q+A to fireside, return answer.
        Routes through aichat (:3030) if up, else the LLM proxy."""
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return self._json({"error": "bad json"}, 400)
        persona  = str(body.get("persona", "Guest"))[:64]
        question = str(body.get("question", ""))[:2000]
        if not question.strip():
            return self._json({"error": "question required"}, 400)
        if not self._ai_allowed("chat"):
            return self._json({"error": "AI autopilot lacks 'chat' scope"}, 403)
        answer = self._ask_llm(persona, question)
        # append the interview turn to the shared fireside timeline
        try:
            self._FIRESIDE_LOG.parent.mkdir(parents=True, exist_ok=True)
            import time as _t
            with self._FIRESIDE_LOG.open("a") as f:
                f.write(json.dumps({"author": "Host", "role": "human", "text": f"@{persona}: {question}", "ts": _t.time()}) + "\n")
                f.write(json.dumps({"author": persona, "role": "ai", "text": answer, "ts": _t.time()}) + "\n")
        except Exception:
            pass
        return self._json({"ok": True, "persona": persona, "answer": answer})

    def _ask_llm(self, persona, question):
        """Best-effort persona response: aichat serve → else fail message."""
        prompt = f"You are {persona}, a guest on a live NeXuS radio show. Answer in character, concise and lively.\n\nHost: {question}\n{persona}:"
        try:
            data = json.dumps({"model": "default", "messages": [
                {"role": "user", "content": prompt}]}).encode()
            req = urllib.request.Request("http://127.0.0.1:3030/v1/chat/completions",
                                         data=data, headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=30) as r:
                j = json.loads(r.read())
                return j["choices"][0]["message"]["content"].strip()
        except Exception as e:
            return f"[{persona} is off-air — aichat :3030 unreachable: {e}]"

    # ── Dock plugins: RSS / Spider / Web search (zero-dep) ─────────────────────

    def _nexus_rss_fetch(self):
        """GET /api/nexus/rss-fetch?url=... → parse RSS/Atom → {items:[{title,link,pubDate}]}."""
        import urllib.parse as _up, xml.etree.ElementTree as ET
        qs  = _up.parse_qs(_up.urlparse(self.path).query)
        url = qs.get("url", [""])[0]
        if not url:
            return self._json({"error": "url required"}, 400)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=12) as r:
                raw = r.read()
        except Exception as e:
            return self._json({"error": f"fetch failed: {e}", "items": []}, 502)
        items = []
        try:
            root = ET.fromstring(raw)
            # RSS <item> or Atom <entry>
            for it in root.iter():
                tag = it.tag.split("}")[-1]
                if tag not in ("item", "entry"):
                    continue
                title = link = pub = ""
                for c in it:
                    ct = c.tag.split("}")[-1]
                    if ct == "title": title = (c.text or "").strip()
                    elif ct == "link":
                        link = (c.get("href") or c.text or "").strip()
                    elif ct in ("pubDate", "updated", "published"):
                        pub = (c.text or "").strip()
                if title:
                    items.append({"title": title, "link": link, "pubDate": pub})
                if len(items) >= 40:
                    break
        except Exception as e:
            return self._json({"error": f"parse failed: {e}", "items": []}, 200)
        return self._json({"items": items})

    def _nexus_spider(self):
        """GET /api/nexus/spider?url=...&depth=1 → extract links → {links:[{href,text}]}."""
        import urllib.parse as _up
        from html.parser import HTMLParser
        qs  = _up.parse_qs(_up.urlparse(self.path).query)
        url = qs.get("url", [""])[0]
        if not url:
            return self._json({"error": "url required"}, 400)
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        class _LinkGrab(HTMLParser):
            def __init__(self): super().__init__(); self.links = []; self._href = None; self._txt = []
            def handle_starttag(self, tag, attrs):
                if tag == "a":
                    self._href = dict(attrs).get("href"); self._txt = []
            def handle_data(self, data):
                if self._href is not None: self._txt.append(data)
            def handle_endtag(self, tag):
                if tag == "a" and self._href:
                    text = " ".join("".join(self._txt).split())[:120]
                    href = _up.urljoin(url, self._href)
                    if href.startswith("http"):
                        self.links.append({"href": href, "text": text or href})
                    self._href = None
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=12) as r:
                html = r.read().decode("utf-8", "replace")
        except Exception as e:
            return self._json({"error": f"fetch failed: {e}", "links": []}, 502)
        p = _LinkGrab(); p.feed(html)
        seen, uniq = set(), []
        for l in p.links:
            if l["href"] in seen: continue
            seen.add(l["href"]); uniq.append(l)
            if len(uniq) >= 100: break
        return self._json({"url": url, "links": uniq})

    def _nexus_search_web(self):
        """GET /api/nexus/search-web?q=... → DuckDuckGo HTML results → {results:[{title,href}]}."""
        import urllib.parse as _up, html as _html, re as _re
        qs = _up.parse_qs(_up.urlparse(self.path).query)
        q  = qs.get("q", [""])[0]
        if not q:
            return self._json({"error": "q required"}, 400)
        try:
            data = _up.urlencode({"q": q}).encode()
            req = urllib.request.Request("https://html.duckduckgo.com/html/", data=data,
                                         headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=12) as r:
                page = r.read().decode("utf-8", "replace")
        except Exception as e:
            return self._json({"error": f"search failed: {e}", "results": []}, 502)
        results = []
        for m in _re.finditer(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', page, _re.S):
            href = _html.unescape(m.group(1))
            title = _html.unescape(_re.sub(r"<[^>]+>", "", m.group(2))).strip()
            if title:
                results.append({"title": title, "href": href})
            if len(results) >= 25:
                break
        return self._json({"query": q, "results": results})

    # ── App TCP health check ──────────────────────────────────────────────────

    def _nexus_app_status(self):
        """GET /api/nexus/app-status?prefix=/txt
        Returns {"up": true/false} based on a TCP connect to the app's backend.
        Does NOT proxy — purely checks reachability."""
        import socket as _sock, urllib.parse as _up
        qs     = _up.parse_qs(_up.urlparse(self.path).query)
        prefix = qs.get("prefix", [""])[0].rstrip("/")
        if not prefix:
            return self._json({"error": "prefix required"}, 400)
        app = next((a for a in APP_REGISTRY.values() if a["prefix"] == prefix), None)
        if not app:
            return self._json({"error": f"no app registered at {prefix}"}, 404)
        backend = app.get("backend", "")
        if not backend:
            return self._json({"up": True, "note": "static-only app"})
        try:
            from urllib.parse import urlparse as _ul
            p = _ul(backend)
            host = p.hostname or "127.0.0.1"
            port = p.port or 80
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
            s.settimeout(1.0)
            s.connect((host, port))
            s.close()
            return self._json({"up": True})
        except Exception:
            return self._json({"up": False})

    # ── Governor API ──────────────────────────────────────────────────────────

    def _nexus_governor(self, sub):
        """
        GET  /api/nexus/governor/status   — current resource snapshot
        GET  /api/nexus/governor/presets  — list all presets
        POST /api/nexus/governor/set      — {process, preset}
        GET  /api/nexus/governor/log      — last 50 log entries
        POST /api/nexus/governor/kill     — {pid, reason}
        """
        import subprocess, json as _json, re as _re, signal as _sig

        gov_py = Path.home() / "NeXuS" / "projects" / "governor" / "nexus_governor.py"
        python  = Path.home() / ".venv" / "nexus-mcp" / "bin" / "python"
        if not python.is_file():
            python = Path("/usr/bin/python3")

        if sub in ("status", "status/", ""):
            try:
                import importlib.util, time
                spec = importlib.util.spec_from_file_location("nexus_governor", str(gov_py))
                mod  = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                gov  = mod.Governor("bridge-api", preset="balanced")
                r    = gov.check("bridge-status-poll")
                swap_total = swap_free = 0
                try:
                    for line in open("/proc/meminfo"):
                        if line.startswith("SwapTotal:"): swap_total = int(line.split()[1])
                        if line.startswith("SwapFree:"):  swap_free  = int(line.split()[1])
                except Exception: pass
                r["swap_pct"]      = round((1 - swap_free/swap_total)*100, 1) if swap_total else 0.0
                r["swap_total_mb"] = round(swap_total/1024)
                r["swap_free_mb"]  = round(swap_free/1024)
                r["ts"] = time.time()
                return self._json(r)
            except Exception as exc:
                return self._json({"error": str(exc)}, 500)

        if sub in ("presets", "presets/"):
            try:
                import importlib.util
                spec = importlib.util.spec_from_file_location("nexus_governor", str(gov_py))
                mod  = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                out = {name: {"label": p.get("label", name), "frees_for": p.get("frees_for", ""),
                              "tau_cpu": p.get("tau_cpu", 80), "tau_ram": p.get("tau_ram", 80)}
                       for name, p in mod.PRESETS.items()}
                return self._json({"presets": out})
            except Exception as exc:
                return self._json({"error": str(exc)}, 500)

        if sub in ("set", "set/") and self.command == "POST":
            length = int(self.headers.get("Content-Length", 0))
            body   = _json.loads(self.rfile.read(length).decode()) if length else {}
            proc   = _re.sub(r"[^a-zA-Z0-9_.\-]", "", str(body.get("process", "")))[:64]
            preset = _re.sub(r"[^a-zA-Z0-9_.\-]", "", str(body.get("preset", "")))[:32]
            if not proc or not preset:
                return self._json({"error": "process and preset required"}, 400)
            try:
                r = subprocess.run([str(python), str(gov_py), "set", proc, preset],
                                   capture_output=True, text=True, timeout=6)
                return self._json({"ok": r.returncode == 0, "output": r.stdout.strip()})
            except Exception as exc:
                return self._json({"error": str(exc)}, 500)

        if sub in ("log", "log/"):
            log_path = Path.home() / "NeXuS" / "projects" / "governor" / "governor.jsonl"
            if not log_path.is_file():
                return self._json({"lines": []})
            try:
                lines = log_path.read_text().splitlines()[-50:]
                entries = []
                for ln in lines:
                    try: entries.append(_json.loads(ln))
                    except: entries.append({"raw": ln})
                return self._json({"lines": entries})
            except Exception as exc:
                return self._json({"error": str(exc)}, 500)

        if sub in ("kill", "kill/") and self.command == "POST":
            length = int(self.headers.get("Content-Length", 0))
            body   = _json.loads(self.rfile.read(length).decode()) if length else {}
            try: pid = int(body.get("pid", 0))
            except Exception: return self._json({"error": "invalid pid"}, 400)
            if pid <= 1: return self._json({"error": "invalid pid"}, 400)
            try:
                import os as _os
                _os.kill(pid, _sig.SIGTERM)
                return self._json({"ok": True, "pid": pid, "signal": "SIGTERM"})
            except ProcessLookupError:
                return self._json({"error": f"pid {pid} not found"}, 404)
            except PermissionError:
                return self._json({"error": f"no permission to kill {pid}"}, 403)

        return self._json({"error": f"unknown governor sub-route: {sub}"}, 404)

    # ── Whitelisted exec endpoint ─────────────────────────────────────────────
    # Only exact pre-approved commands run. No shell=True. No user-controlled args.
    _EXEC_WHITELIST = None   # built lazily so Path.home() resolves at runtime
    _ncm_stat_cache: dict = {}  # {iface: {rx, tx, ts}} for rate calculation

    @classmethod
    def _build_whitelist(cls):
        h = Path.home()
        sc = h / "scripts"
        aether = h / "NeXuS" / "projects" / "nexus-aether"
        cls._EXEC_WHITELIST = {
            # ── Na PH · Element 11 Production ─────────────────────────────────
            "aether status":              [str(aether/"nexus-aether.sh"), "status"],
            # Track A — MPD radio
            "aether radio status":        ["mpc", "status"],
            "aether radio start":         [str(sc/"nexus-aether.sh"), "radio", "start"],
            "aether radio stop":          ["mpc", "stop"],
            "aether radio next":          ["mpc", "next"],
            "aether radio prev":          ["mpc", "prev"],
            "aether radio pause":         ["mpc", "toggle"],
            "aether radio queue":         ["mpc", "playlist"],
            "aether radio current":       ["mpc", "current"],
            # Track B — scheduler
            "aether scheduler status":    [str(aether/"nexus-aether-scheduler.sh"), "status"],
            "aether scheduler start":     [str(aether/"nexus-aether-scheduler.sh"), "start"],
            "aether scheduler stop":      [str(aether/"nexus-aether-scheduler.sh"), "stop"],
            "aether scheduler list":      [str(aether/"nexus-aether-scheduler.sh"), "list"],
            "aether scheduler clear":     [str(aether/"nexus-aether-scheduler.sh"), "clear"],
            # Library
            "aether library export":      [str(aether/"nexus-aether-scheduler.sh"), "export"],
            # studio management
            "nexus-studio status":        [str(sc/"nexus-studio.sh"), "status"],
            "nexus-studio start":         [str(sc/"nexus-studio.sh"), "start"],
            "nexus-studio stop":          [str(sc/"nexus-studio.sh"), "stop"],
            "nexus-studio murmur":        [str(sc/"nexus-studio.sh"), "murmur"],
            "nexus-studio owncast":       [str(sc/"nexus-studio.sh"), "owncast"],
            # proxy
            "nexus-api-proxy status":     [str(sc/"nexus-api-proxy.sh"), "status"],
            "nexus-api-proxy restart":    [str(sc/"nexus-api-proxy.sh"), "restart"],
            # containers
            "podman ps":                  ["podman", "ps", "-a", "--format", "table {{.Names}}\\t{{.Status}}\\t{{.Ports}}"],
            "podman logs nexus-owncast":  ["podman", "logs", "--tail", "30", "nexus-owncast"],
            "podman logs nexus-ipfs":     ["podman", "logs", "--tail", "30", "nexus-ipfs"],
            "podman logs nexus-i2p":      ["podman", "logs", "--tail", "30", "nexus-i2p"],
            # system info
            "df -h":                      ["df", "-h", str(h)],
            "murmur status":              ["ss", "-tlnp"],
            "bridge health":              ["curl", "-sk", "https://localhost:8443/api/health"],
        }

    def _nexus_exec(self):
        import subprocess as _sp, json as _json
        if self.__class__._EXEC_WHITELIST is None:
            self.__class__._build_whitelist()
        try:
            length = int(self.headers.get("Content-Length", 0))
            body   = _json.loads(self.rfile.read(length)) if length else {}
            cmd    = str(body.get("cmd", "")).strip()
        except Exception:
            return self._json({"ok": False, "error": "invalid request body"}, 400)

        argv = self._EXEC_WHITELIST.get(cmd)
        if not argv:
            # Return allowed commands so the UI can display them
            allowed = sorted(self._EXEC_WHITELIST.keys())
            return self._json({"ok": False, "error": f"command not whitelisted",
                               "allowed": allowed}, 403)
        try:
            r = _sp.run(argv, capture_output=True, text=True, timeout=15)
            stdout = r.stdout[:8192]  # cap at 8KB
            stderr = r.stderr[:2048]
            self._json({"ok": r.returncode == 0, "code": r.returncode,
                        "stdout": stdout, "stderr": stderr})
        except _sp.TimeoutExpired:
            self._json({"ok": False, "error": "command timed out (15s)"}, 504)
        except Exception as e:
            self._json({"ok": False, "error": str(e)}, 500)

    # Per-service direct commands — run as regular user, no doas needed.
    # start: launched in background (Popen), portcheck confirms it came up.
    # stop:  pkill by process name.
    # status: pgrep — 0 = running, 1 = not running.
    # Services not listed here fall back to doas rc-service.
    _SVC_DIRECT = {
        # "path" overrides shutil.which for non-standard install locations
        "tor":        {"bin": "tor",              "stop": "tor"},
        "privoxy":    {"bin": "privoxy",          "path": "/usr/sbin/privoxy",          "stop": "privoxy"},
        "yggdrasil":  {"bin": "yggdrasil",        "args": ["-useconffile", "/etc/yggdrasil.conf"], "stop": "yggdrasil"},
        "reticulum":  {"bin": "rnsd",             "path": "/home/user/.local/bin/rnsd", "stop": "rnsd"},
        "snowflake":  {"bin": "snowflake-proxy",  "stop": "snowflake-proxy"},
        "gemini":     {"bin": "agate",            "stop": "agate"},
        "amule":      {"bin": "amule",            "stop": "amule"},
        "irc":        {"bin": "inspircd",         "stop": "inspircd"},
        "retroshare": {"bin": "RetroShare-nogui", "stop": "RetroShare-nogui"},
        "webtorrent": {"bin": "webtorrent",       "stop": "webtorrent"},
        "whonix":     {"bin": "whonix",           "stop": "whonix"},
        "murmur":     {"bin": "mumble-server",    "path": "/usr/bin/mumble-server", "stop": "mumble-server"},
    }
    # Services that need root — fall back to doas rc-service
    _SVC_ROOT = {
        "opensnitch": "opensnitch",
        "gopher":     "gopherd",
        "batman":     "batman-adv",
    }
    # Rootless Podman containers — started/stopped by container name
    # Map service id → name pattern (substring match via podman ps --filter name=)
    _SVC_CONTAINER = {
        "ipfs":       "nexus-ipfs",      # docker.io/ipfs/kubo, port 5001
        "i2p":        "nexus-i2p",       # docker.io/purplei2p/i2pd, port 4444
        "owncast":    "nexus-owncast",   # owncast/owncast, port 8080 + rtmp 1935
        # txt blogger container not yet built — no entry
    }

    def _nexus_service_ctl(self, tail):
        import subprocess as _sp, shutil
        parts = tail.rstrip("/").split("/")
        if len(parts) != 2:
            return self._json({"error": "usage: /api/nexus/service/{id}/{start|stop|restart|status}"}, 400)
        svc_id, action = parts
        if action not in ("start", "stop", "restart", "status"):
            return self._json({"error": f"invalid action: {action}"}, 400)

        direct = self._SVC_DIRECT.get(svc_id)
        if direct:
            return self._svc_direct(svc_id, action, direct)

        container = self._SVC_CONTAINER.get(svc_id)
        if container:
            return self._svc_container(svc_id, action, container)

        # Root-required services — only if explicitly listed in _SVC_ROOT
        openrc = self._SVC_ROOT.get(svc_id)
        if openrc is None:
            return self._json({
                "ok": False, "service": svc_id,
                "error": f"'{svc_id}' is not configured for service control",
                "cli": f"# In nexus_web_server.py add one of:\n# _SVC_DIRECT:    \"{svc_id}\": {{\"bin\": \"<binary>\", \"stop\": \"<binary>\"}}\n# _SVC_CONTAINER: \"{svc_id}\": \"<container-name>\"\n# _SVC_ROOT:      \"{svc_id}\": \"<openrc-name>\""
            }, 404)
        for cmd in (["doas", "-n", "rc-service", openrc, action],
                    ["doas",       "rc-service", openrc, action]):
            try:
                r = _sp.run(cmd, capture_output=True, text=True, timeout=15)
                out = (r.stdout + r.stderr).strip()
                if "tty" in out.lower() or "password" in out.lower():
                    continue
                self._json({"ok": r.returncode == 0, "service": svc_id, "action": action, "output": out})
                return
            except FileNotFoundError:
                continue
            except Exception as e:
                self._json({"ok": False, "error": str(e)}, 500)
                return
        self._json({"ok": False,
                    "error": f"Add 'permit nopass :wheel as root cmd rc-service' to /etc/doas.conf",
                    "cli": f"doas rc-service {openrc} {action}"}, 403)

    def _svc_direct(self, svc_id, action, direct):
        import subprocess as _sp, shutil, time as _time
        bin_name  = direct["bin"]
        stop_name = direct["stop"]
        try:
            if action == "status":
                r = _sp.run(["/usr/bin/pgrep", "-x", stop_name], capture_output=True)
                running = r.returncode == 0
                self._json({"ok": running, "service": svc_id, "action": "status",
                            "output": "running" if running else "not running"})

            elif action == "start":
                if _sp.run(["/usr/bin/pgrep", "-x", stop_name], capture_output=True).returncode == 0:
                    self._json({"ok": True, "service": svc_id, "action": "start",
                                "output": f"{bin_name} already running"})
                    return
                bin_path = direct.get("path") or shutil.which(bin_name)
                if not bin_path or not os.path.isfile(bin_path):
                    bin_path = shutil.which(bin_name)  # fallback: try PATH anyway
                if not bin_path:
                    self._json({"ok": False, "service": svc_id, "action": "start",
                                "output": f"{bin_name} not found",
                                "cli": f"doas apk add {bin_name}"})
                    return
                extra_args = direct.get("args", [])
                _sp.Popen([bin_path] + extra_args, stdout=_sp.DEVNULL, stderr=_sp.DEVNULL,
                          start_new_session=True)
                # Wait briefly, then confirm the process didn't immediately exit
                _time.sleep(0.8)
                alive = _sp.run(["/usr/bin/pgrep", "-x", stop_name], capture_output=True).returncode == 0
                if alive:
                    self._json({"ok": True, "service": svc_id, "action": "start",
                                "output": f"{bin_name} launched — status updates in ~5s"})
                else:
                    cmd_str = " ".join([bin_name] + direct.get("args", []))
                    self._json({"ok": False, "service": svc_id, "action": "start",
                                "output": f"{bin_name} exited immediately — check config or logs",
                                "cli": cmd_str})

            elif action == "stop":
                r = _sp.run(["/usr/bin/pkill", "-x", stop_name], capture_output=True, text=True)
                ok = r.returncode == 0
                self._json({"ok": ok, "service": svc_id, "action": "stop",
                            "output": "stopped" if ok else f"{stop_name} was not running"})

            elif action == "restart":
                _sp.run(["/usr/bin/pkill", "-x", stop_name], capture_output=True)
                _time.sleep(1)
                self._svc_direct(svc_id, "start", direct)

        except Exception as exc:
            self._json({"ok": False, "service": svc_id, "action": action,
                        "error": str(exc)}, 500)

    def _svc_container(self, svc_id, action, name_pattern):
        import subprocess as _sp
        try:
            # Resolve actual container name dynamically — podman filter is a substring match.
            # This survives container recreation, version suffixes, or minor name changes.
            r = _sp.run(["podman", "ps", "-a", "--filter", f"name={name_pattern}",
                         "--format", "{{.Names}}"],
                        capture_output=True, text=True, timeout=5)
            matches = [n.strip() for n in r.stdout.strip().splitlines() if n.strip()]

            if not matches:
                # Helpful error: list what IS available
                avail_r = _sp.run(["podman", "ps", "-a", "--format", "{{.Names}}"],
                                  capture_output=True, text=True, timeout=5)
                avail = sorted(n.strip() for n in avail_r.stdout.strip().splitlines() if n.strip())
                return self._json({
                    "ok": False, "service": svc_id, "action": action,
                    "error": f"No container matching '{name_pattern}'",
                    "cli": f"podman ps -a  # find container name, then update _SVC_CONTAINER[\"{svc_id}\"]",
                    "available_containers": avail
                }, 404)

            cname = matches[0]  # first match wins

            if action == "status":
                r = _sp.run(["podman", "inspect", cname, "--format", "{{.State.Running}}"],
                            capture_output=True, text=True, timeout=5)
                running = r.stdout.strip().lower() == "true"
                self._json({"ok": running, "service": svc_id, "action": "status",
                            "container": cname, "output": "running" if running else "not running"})
            elif action in ("start", "stop", "restart"):
                r = _sp.run(["podman", action, cname],
                            capture_output=True, text=True, timeout=30)
                ok  = r.returncode == 0
                out = (r.stdout + r.stderr).strip() or ("ok" if ok else "failed")
                self._json({"ok": ok, "service": svc_id, "action": action,
                            "container": cname, "output": out})
        except FileNotFoundError:
            self._json({"ok": False, "service": svc_id, "action": action,
                        "error": "podman not found — is rootless Podman installed?"}, 500)
        except Exception as exc:
            self._json({"ok": False, "service": svc_id, "action": action,
                        "error": str(exc)}, 500)

    def _nexus_appmon(self):
        """GET /api/nexus/appmon?app=<name>[&app2=<name>]
        Returns JSON resource stats for one or two named processes.
        App name is validated to [a-zA-Z0-9_.-] only — no shell injection possible.
        """
        import subprocess, re
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        app1 = params.get("app",  [""])[0].strip()
        app2 = params.get("app2", [""])[0].strip()

        _safe = re.compile(r'^[a-zA-Z0-9_.\-]{1,64}$')
        if not _safe.match(app1):
            return self._json({"error": "invalid app name"}, 400)
        if app2 and not _safe.match(app2):
            return self._json({"error": "invalid app2 name"}, 400)

        script = Path.home() / "scripts" / "nexus-appmon.sh"
        if not script.is_file():
            return self._json({"error": f"nexus-appmon.sh not found at {script}"}, 500)

        def _query(app):
            try:
                r = subprocess.run(
                    [str(script), "--json", app],
                    capture_output=True, text=True, timeout=8
                )
                import json as _json
                return _json.loads(r.stdout.strip())
            except Exception as e:
                return {"app": app, "status": "error", "error": str(e)}

        result = {"a": _query(app1)}
        if app2:
            result["b"] = _query(app2)

        self._json(result)

    # ── NCM Network Manager API ───────────────────────────────────────────────

    def _nexus_ncm_status(self):
        """GET /api/nexus/ncm/status — interface stats, services, routing, TCP connections."""
        import subprocess, time, re as _re
        now  = time.time()
        result = {"ts": now, "interfaces": {}, "services": {}, "dns": [],
                  "default_route": None, "connections": [], "conn_count": 0, "udp_count": 0}
        cache = Handler._ncm_stat_cache

        # Default route
        try:
            r = subprocess.run(["ip", "route", "show", "default"],
                               capture_output=True, text=True, timeout=3)
            for line in r.stdout.splitlines():
                parts = line.split()
                if "via" in parts and "dev" in parts:
                    result["default_route"] = {
                        "iface": parts[parts.index("dev") + 1],
                        "gw":    parts[parts.index("via") + 1],
                    }
                    break
        except Exception:
            pass

        for iface in ("eth0", "usb0", "wlan0"):
            sys_dir = f"/sys/class/net/{iface}"
            if not os.path.isdir(sys_dir):
                continue
            def _rs(p, d="0"):
                try: return Path(p).read_text().strip()
                except: return d
            rx_now  = int(_rs(f"{sys_dir}/statistics/rx_bytes"))
            tx_now  = int(_rs(f"{sys_dir}/statistics/tx_bytes"))
            state   = _rs(f"{sys_dir}/operstate", "unknown")
            # USB tethering always reports operstate=unknown; carrier=1 means connected
            if state == "unknown" and _rs(f"{sys_dir}/carrier", "0") == "1":
                state = "up"
            prev    = cache.get(iface, {})
            prev_rx = prev.get("rx", rx_now); prev_tx = prev.get("tx", tx_now)
            prev_ts = prev.get("ts", now);    dt = now - prev_ts
            rx_rate = max(0, int((rx_now - prev_rx) / dt)) if dt > 0.1 and rx_now >= prev_rx else 0
            tx_rate = max(0, int((tx_now - prev_tx) / dt)) if dt > 0.1 and tx_now >= prev_tx else 0
            cache[iface] = {"rx": rx_now, "tx": tx_now, "ts": now}
            ip_addr = ""
            try:
                r = subprocess.run(["ip", "-4", "addr", "show", "dev", iface],
                                   capture_output=True, text=True, timeout=3)
                m = _re.search(r'inet (\S+)', r.stdout)
                if m: ip_addr = m.group(1)
            except Exception:
                pass
            result["interfaces"][iface] = {
                "state": state, "ip": ip_addr,
                "rx_bytes": rx_now, "tx_bytes": tx_now,
                "rx_rate": rx_rate, "tx_rate": tx_rate,
                "is_default": (result["default_route"] or {}).get("iface") == iface,
            }

        # Services
        for svc, proc in {"tor": "tor", "i2pd": "i2pd",
                           "privoxy": "privoxy", "dnscrypt": "dnscrypt-proxy"}.items():
            try:
                r = subprocess.run(["pgrep", "-x", proc], capture_output=True, timeout=2)
                result["services"][svc] = r.returncode == 0
            except Exception:
                result["services"][svc] = False
        try:
            r = subprocess.run(["wg", "show", "interfaces"], capture_output=True, text=True, timeout=2)
            result["services"]["wireguard"] = bool(r.stdout.strip())
            result["wg_iface"] = r.stdout.strip().split()[0] if r.stdout.strip() else ""
        except Exception:
            result["services"]["wireguard"] = False; result["wg_iface"] = ""

        # VPN configs — vault dir + /etc/wireguard/; split by type
        vpn_dir = Path(os.environ.get("NCM_VPN_DIR", str(Path.home() / "vault")))
        try:
            _wg_map = {}   # name → full path
            for _p in sorted(Path("/etc/wireguard").glob("*.conf"), key=lambda p: p.name):
                _wg_map[_p.stem] = str(_p)
            for _p in sorted(vpn_dir.glob("*.conf"), key=lambda p: p.name):
                _wg_map[_p.stem] = str(_p)   # vault overrides /etc/wireguard
            result["wg_configs"]  = sorted(_wg_map.keys())
            result["wg_conf_map"] = _wg_map
        except Exception:
            result["wg_configs"] = []; result["wg_conf_map"] = {}
        try:
            _ov_map = {}  # name → full path
            for _p in sorted(vpn_dir.glob("*.ovpn"), key=lambda p: p.name):
                _ov_map[_p.stem] = str(_p)
            for _p in sorted(vpn_dir.glob("*.conf"), key=lambda p: p.name):
                # .conf in vault that isn't a WG conf (heuristic: no [Interface] header)
                try:
                    txt = _p.read_text(errors="replace")
                    if "[Interface]" not in txt and "remote " in txt:
                        _ov_map[_p.stem] = str(_p)
                except Exception:
                    pass
            result["ovpn_configs"]  = sorted(_ov_map.keys())
            result["ovpn_conf_map"] = _ov_map
        except Exception:
            result["ovpn_configs"] = []; result["ovpn_conf_map"] = {}
        # OpenVPN running?
        try:
            r = subprocess.run(["pgrep", "-x", "openvpn"], capture_output=True, timeout=2)
            result["services"]["openvpn"] = r.returncode == 0
        except Exception:
            result["services"]["openvpn"] = False

        # DNS
        try:
            for line in Path("/etc/resolv.conf").read_text().splitlines():
                if line.startswith("nameserver"):
                    result["dns"].append(line.split()[1])
        except Exception:
            pass

        # TCP connections
        try:
            r = subprocess.run(["ss", "-tnp"], capture_output=True, text=True, timeout=3)
            lines = r.stdout.splitlines()[1:]
            result["conn_count"] = len(lines)
            for line in lines[:20]:
                parts = line.split()
                if len(parts) < 5: continue
                pm = _re.search(r'comm="([^"]+)"', line)
                result["connections"].append({
                    "state": parts[0], "local": parts[3],
                    "remote": parts[4], "proc": pm.group(1) if pm else "",
                })
        except Exception:
            pass
        try:
            r = subprocess.run(["ss", "-unp"], capture_output=True, text=True, timeout=3)
            result["udp_count"] = max(0, len(r.stdout.splitlines()) - 1)
        except Exception:
            pass

        self._json(result)

    def _nexus_ncm_action(self):
        """POST /api/nexus/ncm/action — whitelisted network control actions."""
        import subprocess, time, glob as _glob
        try:
            length = int(self.headers.get("Content-Length", 0))
            body   = json.loads(self.rfile.read(length))
        except Exception:
            return self._json({"ok": False, "error": "invalid JSON"}, 400)

        action  = str(body.get("action",  "")).strip()
        param   = str(body.get("param",   "")).strip()
        wg_conf = str(body.get("wg_conf", "")).strip()  # specific WG conf to bring up

        VALID_SVCS  = {"tor", "i2pd", "privoxy", "wireguard", "openvpn", "dnscrypt"}
        VALID_DIAGS = {"ping", "dns", "connections", "route-fix", "wifi-scan"}
        # wifi-scan needs CAP_NET_ADMIN — inject to terminal instead of subprocess
        TERMINAL_DIAGS = {"wifi-scan"}
        NCM_LIB  = Path.home() / "git" / "nexus-connection-manager" / "lib"
        vpn_dir  = Path(os.environ.get("NCM_VPN_DIR", str(Path.home() / "vault")))

        def _running(proc):
            return subprocess.run(["pgrep", "-x", proc], capture_output=True).returncode == 0

        def _doas(*cmd, timeout=20):
            for pfx in (["doas", "-n"], ["doas"]):
                try:
                    r = subprocess.run(list(pfx) + list(cmd),
                                       capture_output=True, text=True, timeout=timeout)
                    out = (r.stdout + r.stderr).strip()
                    if "tty" in out.lower() or "password" in out.lower(): continue
                    return r.returncode == 0, out
                except FileNotFoundError: continue
                except subprocess.TimeoutExpired: return False, "timed out"
                except Exception as e: return False, str(e)
            return False, "doas requires TTY — add: permit nopass :wheel as root cmd <cmd>"

        if action == "toggle_svc":
            if param not in VALID_SVCS:
                return self._json({"ok": False, "error": f"unknown service: {param}"}, 400)

            # All service toggles return the exact command for terminal execution.
            # No doas from the web server — user runs it interactively in xterm.js.
            try:
                SVC_RC = {"tor": "tor", "i2pd": "i2pd", "privoxy": "privoxy",
                          "dnscrypt": "dnscrypt-proxy"}
                if param in SVC_RC:
                    proc_name = {"tor":"tor","i2pd":"i2pd","privoxy":"privoxy",
                                 "dnscrypt":"dnscrypt-proxy"}[param]
                    op  = "stop" if _running(proc_name) else "start"
                    cmd = f"doas rc-service {SVC_RC[param]} {op}"

                elif param == "wireguard":
                    r = subprocess.run(["wg", "show", "interfaces"],
                                       capture_output=True, text=True, timeout=3)
                    if r.stdout.strip():
                        iface = r.stdout.strip().split()[0]
                        cmd = f"doas wg-quick down {iface}"
                    else:
                        _wg_map = {}
                        for _p in sorted(Path("/etc/wireguard").glob("*.conf")):
                            _wg_map[_p.stem] = str(_p)
                        for _p in sorted(vpn_dir.glob("*.conf")):
                            _wg_map[_p.stem] = str(_p)
                        chosen_name = wg_conf if wg_conf and wg_conf in _wg_map \
                                      else (sorted(_wg_map.keys())[0] if _wg_map else "")
                        chosen_path = _wg_map.get(chosen_name, "")
                        cmd = f"doas wg-quick up {chosen_path}" if chosen_path \
                              else "echo 'No WireGuard conf found in vault or /etc/wireguard/'"

                elif param == "openvpn":
                    if _running("openvpn"):
                        cmd = "doas pkill -x openvpn"
                    else:
                        _ov_map = {_p.stem: str(_p) for _p in sorted(vpn_dir.glob("*.ovpn"))}
                        chosen_name = wg_conf if wg_conf and wg_conf in _ov_map \
                                      else (sorted(_ov_map.keys())[0] if _ov_map else "")
                        chosen_path = _ov_map.get(chosen_name, "")
                        cmd = f"doas openvpn --config {chosen_path} --daemon" \
                              if chosen_path else f"echo 'No .ovpn files found in {vpn_dir}'"

                return self._json({"ok": False, "use_terminal": True, "cmd": cmd,
                                   "hint": "Run in the NCM terminal (doas auth required)"})
            except Exception as e:
                return self._json({"ok": False, "error": str(e)})

        elif action == "diag":
            if param not in VALID_DIAGS:
                return self._json({"ok": False, "error": f"unknown diagnostic: {param}"}, 400)
            # Some diags need root (CAP_NET_ADMIN) — send to terminal instead
            if param in TERMINAL_DIAGS:
                cmd = f"doas sh {NCM_LIB}/ncm_diag.sh {param}"
                return self._json({"ok": True, "use_terminal": True, "cmd": cmd,
                                   "hint": f"{param} needs root — running in terminal"})
            script = NCM_LIB / "ncm_diag.sh"
            if not script.is_file():
                return self._json({"ok": False, "error": "ncm_diag.sh not found"}, 500)
            try:
                r = subprocess.run([str(script), param],
                                   capture_output=True, text=True, timeout=30,
                                   stdin=subprocess.DEVNULL,
                                   env={**os.environ, "NCM_NO_PAUSE": "1"})
                return self._json({"ok": r.returncode == 0,
                                   "output": (r.stdout + r.stderr).strip()})
            except Exception as e:
                return self._json({"ok": False, "error": str(e)}, 500)

        else:
            return self._json({"ok": False, "error": f"unknown action: {action}"}, 400)

    def _ws_recv(self):
        """Read one WebSocket frame from self.connection. Returns payload bytes or None."""
        import struct

        def _read(n):
            buf = b""
            while len(buf) < n:
                try:   chunk = self.connection.recv(n - len(buf))
                except Exception: return None
                if not chunk: return None
                buf += chunk
            return buf

        hdr = _read(2)
        if not hdr: return None
        b0, b1 = hdr[0], hdr[1]
        opcode = b0 & 0x0f
        if opcode == 8: return None  # CLOSE
        masked = bool(b1 & 0x80)
        plen   = b1 & 0x7f
        if plen == 126:
            ext = _read(2);   plen = struct.unpack("!H", ext)[0] if ext else 0
        elif plen == 127:
            ext = _read(8);   plen = struct.unpack("!Q", ext)[0] if ext else 0
        if opcode == 9:  # PING — reply with PONG
            payload = _read(plen) if plen else b""
            try: self.connection.sendall(bytes([0x8a, len(payload)]) + payload)
            except Exception: pass
            return b""
        mask_key = _read(4) if masked else b""
        if masked and not mask_key: return None
        payload  = _read(plen) if plen else b""
        if plen and payload is None: return None
        if masked:
            payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
        return payload

    def _ncm_terminal_ws(self):
        """Upgrade to WebSocket and bridge to a PTY shell. Localhost-only."""
        import hashlib, base64, struct, pty, os as _os, threading, fcntl, termios, shutil

        # Guard 1: must come from loopback TCP
        if self.client_address[0] not in ("127.0.0.1", "::1"):
            self.send_response(403, "Forbidden")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        # Guard 2: Origin must be localhost/127.0.0.1 — blocks evil.com JS
        # Guard 1 already ensures TCP comes from loopback; this just catches
        # the case where a non-loopback socket somehow snuck past (belt+suspenders).
        origin = self.headers.get("Origin", "")
        import re as _re
        _loopback_origin = _re.compile(
            r'^https?://(localhost|127\.0\.0\.1)(:\d+)?$'
        )
        if origin and not _loopback_origin.match(origin):
            self.send_response(403, "Forbidden — Origin not allowed")
            self.send_header("Content-Length", "0")
            self.end_headers()
            log(f"[NCM terminal] rejected Origin: {origin}")
            return
        log(f"[NCM terminal] accepted from {self.client_address[0]}, origin={origin or '(none)'}")

        # WebSocket handshake
        key    = self.headers.get("Sec-WebSocket-Key", "")
        accept = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        ).decode()
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        self.wfile.flush()

        # Spawn PTY shell — use bash; fish sends unanswered terminal queries
        # (DA1, kitty protocol) and hangs waiting for responses over WS.
        # User can run `fish` from within bash if preferred.
        shell = shutil.which("bash") or shutil.which("sh") or "/bin/sh"
        shell_env = dict(_os.environ)
        shell_env["TERM"] = "xterm-256color"
        shell_env["PS1"] = r"\[\e[0;32m\]nexus\[\e[0m\]:\[\e[0;36m\]\w\[\e[0m\]\$ "
        pid, fd = pty.fork()
        if pid == 0:
            _os.execve(shell, [shell, "--norc", "--noprofile"], shell_env)
            _os._exit(1)

        # Initial terminal size
        try:
            fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        except Exception:
            pass

        conn = self.connection
        stop = threading.Event()

        def _send_bin(data):
            n = len(data)
            if n < 126:   hdr = bytes([0x82, n])
            elif n<65536: hdr = bytes([0x82, 126]) + struct.pack("!H", n)
            else:         hdr = bytes([0x82, 127]) + struct.pack("!Q", n)
            try: conn.sendall(hdr + data)
            except Exception: stop.set()

        def _pty_to_ws():
            try:
                while not stop.is_set():
                    try:
                        data = _os.read(fd, 4096)
                        if not data: break
                        _send_bin(data)
                    except OSError: break
            finally:
                stop.set()

        threading.Thread(target=_pty_to_ws, daemon=True).start()

        try:
            conn.settimeout(600)  # 10 min idle timeout
            while not stop.is_set():
                data = self._ws_recv()
                if data is None: break
                if not data: continue  # PING handled
                if data[:1] == b"{":
                    try:
                        msg = json.loads(data)
                        if msg.get("type") == "resize":
                            rows = max(1, int(msg.get("rows", 24)))
                            cols = max(1, int(msg.get("cols", 80)))
                            fcntl.ioctl(fd, termios.TIOCSWINSZ,
                                        struct.pack("HHHH", rows, cols, 0, 0))
                            continue
                    except Exception:
                        pass
                try: _os.write(fd, data)
                except OSError: break
        except Exception:
            pass
        finally:
            stop.set()
            try: conn.sendall(bytes([0x88, 0x00]))  # WS CLOSE frame
            except Exception: pass
            try: _os.kill(pid, 9)
            except ProcessLookupError: pass
            try: _os.waitpid(pid, _os.WNOHANG)
            except Exception: pass
            try: _os.close(fd)
            except Exception: pass

    def _studio_terminal_ws(self):
        """Na PH studio terminal — same PTY bridge as NCM, scoped to studio shell."""
        import hashlib, base64, struct, pty, os as _os, threading, fcntl, termios, shutil, re as _re

        if self.client_address[0] not in ("127.0.0.1", "::1"):
            self.send_response(403, "Forbidden"); self.send_header("Content-Length","0"); self.end_headers(); return
        origin = self.headers.get("Origin", "")
        _lo = _re.compile(r'^https?://(localhost|127\.0\.0\.1)(:\d+)?$')
        if origin and not _lo.match(origin):
            self.send_response(403, "Forbidden — Origin not allowed")
            self.send_header("Content-Length","0"); self.end_headers()
            log(f"[studio terminal] rejected Origin: {origin}"); return
        log(f"[studio terminal] accepted from {self.client_address[0]}")

        key    = self.headers.get("Sec-WebSocket-Key","")
        accept = base64.b64encode(
            hashlib.sha1((key+"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        ).decode()
        self.send_response(101,"Switching Protocols")
        self.send_header("Upgrade","websocket"); self.send_header("Connection","Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept); self.end_headers(); self.wfile.flush()

        shell     = shutil.which("bash") or "/bin/sh"
        shell_env = dict(_os.environ)
        shell_env["TERM"] = "xterm-256color"
        # Na PH prompt — cyan Na PH label so it's distinct from NCM
        shell_env["PS1"] = r"\[\e[0;36m\]Na PH\[\e[0m\]:\[\e[0;33m\]\w\[\e[0m\]\$ "
        # Auto-source nexus.env and cd to aether project
        shell_env["BASH_ENV"] = ""
        init_cmd  = (
            "source ~/NeXuS/nexus.env 2>/dev/null; "
            "cd ~/NeXuS/projects/nexus-aether 2>/dev/null; "
            "echo -e '\\e[0;36m  Na PH · Element 11 Production\\e[0m'; "
            "echo -e '\\e[0;90m  nexus-aether.sh help for commands\\e[0m'; echo"
        )
        pid, fd = pty.fork()
        if pid == 0:
            _os.execve(shell, [shell, "--norc", "--noprofile",
                               "-c", f"{init_cmd}; exec {shell} --norc --noprofile"],
                       shell_env)
            _os._exit(1)

        try: fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        except Exception: pass

        conn = self.connection
        stop = threading.Event()

        def _send_bin(data):
            n = len(data)
            if n < 126:   hdr = bytes([0x82, n])
            elif n<65536: hdr = bytes([0x82, 126]) + struct.pack("!H", n)
            else:         hdr = bytes([0x82, 127]) + struct.pack("!Q", n)
            try: conn.sendall(hdr + data)
            except Exception: stop.set()

        def _pty_to_ws():
            try:
                while not stop.is_set():
                    try:
                        data = _os.read(fd, 4096)
                        if not data: break
                        _send_bin(data)
                    except OSError: break
            finally: stop.set()

        threading.Thread(target=_pty_to_ws, daemon=True).start()

        try:
            conn.settimeout(600)
            while not stop.is_set():
                data = self._ws_recv()
                if data is None: break
                if not data: continue
                if data[:1] == b"{":
                    try:
                        msg = json.loads(data)
                        if msg.get("type") == "resize":
                            rows = max(1, int(msg.get("rows", 24)))
                            cols = max(1, int(msg.get("cols", 80)))
                            fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
                            continue
                    except Exception: pass
                try: _os.write(fd, data)
                except OSError: break
        except Exception: pass
        finally:
            stop.set()
            try: conn.sendall(bytes([0x88, 0x00]))
            except Exception: pass
            try: _os.kill(pid, 9)
            except ProcessLookupError: pass
            try: _os.waitpid(pid, _os.WNOHANG)
            except Exception: pass
            try: _os.close(fd)
            except Exception: pass

    def _nexus_portcheck(self):
        import socket as _sock
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        raw    = params.get("ports", params.get("port", [""]))[0]
        ports  = [int(p.strip()) for p in raw.split(",") if p.strip().isdigit()]
        result = {}
        for port in ports:
            if port < 1 or port > 65535:
                result[str(port)] = "invalid"
                continue
            try:
                with _sock.create_connection(("127.0.0.1", port), timeout=0.5):
                    result[str(port)] = "up"
            except Exception:
                result[str(port)] = "down"
        self._json(result)

    def _nexus_wiki_sync(self):
        import subprocess
        script = next((p for p in [
            Path.home() / "NeXuS" / "scripts" / "nexus-wiki-publish.sh",
            Path.home() / "scripts" / "nexus-wiki-publish.sh",
        ] if p.is_file()), None)
        if script is None:
            return self._json({"error": "nexus-wiki-publish.sh not found in NeXuS/scripts or scripts/"}, 404)
        try:
            r = subprocess.run([str(script)], capture_output=True, text=True, timeout=60)
            output = (r.stdout + r.stderr).strip()
            self._json({"ok": r.returncode == 0, "output": output, "code": r.returncode})
        except subprocess.TimeoutExpired:
            self._json({"ok": False, "output": "sync timed out after 60s"}, 504)
        except Exception as e:
            self._json({"ok": False, "output": str(e)}, 500)

    def _nexus_api_map(self):
        import socket as _sock
        env        = {**_env_dict(), **os.environ}
        fossil_dir = Path(env.get("NEXUS_FOSSIL_DIR", str(Path.home() / "museum")))
        claude_dir = Path(env.get("NEXUS_CLAUDE_DIR", str(Path.home() / "claude")))
        gh_user    = env.get("NEXUS_GITHUB_USER", "hackenstacks")

        _meta = {
            "NNCC":     ("Network Command Center", "🌐"),
            "SEARCH":   ("File Search",            "🔍"),
            "WIKI":     ("Wiki",                   "📚"),
            "CHARCARD": ("Character Cards",        "🃏"),
            "MATRIX":   ("Conduit Matrix",         "🔴"),
            "TXT":      ("Text Editor",            "📝"),
            "AICHAT":   ("AI Chat",                "🤖"),
            "FOUNDRY":  ("VM Foundry",             "🏗️"),
            "MKDOCS":   ("Docs",                   "📖"),
        }
        apps = []
        for aid, app in APP_REGISTRY.items():
            lbl  = env.get(f"NEXUS_APP_{aid}_label", "")
            icon = env.get(f"NEXUS_APP_{aid}_icon",  "")
            dl, di = _meta.get(aid, (aid.title(), "📦"))
            apps.append({"id": aid, "prefix": app["prefix"],
                         "label": lbl or dl, "icon": icon or di})
        # built-in routes not in the app registry
        reg_ids = {a["id"] for a in apps}
        for b in [
            {"id": "TIMELINE", "prefix": "/timeline",                           "label": "Living Timeline",  "icon": "📅"},
            {"id": "SERVERS",  "prefix": "/servers",                            "label": "Server Status",    "icon": "🖥️"},
            {"id": "OC",       "prefix": "/oc",                                 "label": "OpenCharacters",   "icon": "🎭"},
            {"id": "WIKI_PUB", "prefix": "https://hackenstacks.github.io/nexus/", "label": "NeXuS Wiki",    "icon": "📖"},
        ]:
            if b["id"] not in reg_ids:
                apps.append(b)

        fossils = []
        if fossil_dir.is_dir():
            for p in sorted(fossil_dir.glob("*.fossil")):
                fossils.append({"name": p.stem, "size_kb": round(p.stat().st_size / 1024)})

        exports = []
        if claude_dir.is_dir():
            pts = sorted(claude_dir.glob("*.txt"),
                         key=lambda p: p.stat().st_mtime, reverse=True)[:12]
            for p in pts:
                st = p.stat()
                exports.append({
                    "name":    p.name,
                    "date":    datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M"),
                    "size_kb": round(st.st_size / 1024),
                })

        try:    node = _sock.gethostname()
        except: node = "nexus-node"

        self._json({"apps": apps, "fossils": fossils, "exports": exports,
                    "github_user": gh_user, "node": node})

    def _map_html(self) -> bytes:
        return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NeXuS Map</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#080d08;--c1:#0c180c;--c2:#101f10;
  --bd:#1b3a1b;--gr:#22c55e;--gd:#166534;
  --tx:#dcfce7;--td:#4d7a5f;--ac:#4ade80;--re:#ef4444;
}
html,body{min-height:100%;background:var(--bg);color:var(--tx);font-family:'Courier New',Courier,monospace;font-size:13px;line-height:1.5}
a{color:var(--ac);text-decoration:none}a:hover{text-decoration:underline;color:var(--gr)}
button{font-family:inherit;cursor:pointer}

header{
  display:flex;align-items:center;justify-content:space-between;
  padding:10px 20px;background:var(--c1);border-bottom:1px solid var(--bd);
  position:sticky;top:0;z-index:20;
}
.logo{font-size:18px;color:var(--gr);font-weight:bold;letter-spacing:2px}
.logo sub{color:var(--td);font-size:10px;letter-spacing:0;vertical-align:0;margin-left:8px}
.hdr-r{display:flex;align-items:center;gap:14px}
#clock{color:var(--gd);font-size:12px}
#node-lbl{color:var(--td);font-size:11px}

.search{display:flex;align-items:center;gap:8px;padding:10px 20px;background:var(--c2);border-bottom:1px solid var(--bd);flex-wrap:wrap}
.search input{flex:1;min-width:180px;background:#070c07;border:1px solid var(--bd);color:var(--tx);padding:7px 12px;font:inherit;font-size:13px;outline:none;transition:border-color .15s}
.search input:focus{border-color:var(--gr)}
.search input::placeholder{color:var(--td)}
.btn{background:var(--gd);color:#dcfce7;border:none;padding:7px 14px;font:bold 12px 'Courier New',Courier,monospace;transition:background .15s}
.btn:hover{background:var(--gr);color:#000}
.btn-g{background:none;color:var(--ac);border:1px solid var(--bd);padding:6px 10px;font:12px 'Courier New',Courier,monospace;transition:border-color .15s,color .15s}
.btn-g:hover{border-color:var(--gr);color:var(--gr)}

.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;padding:12px 20px;max-width:1440px;margin:0 auto}
@media(max-width:860px){.grid{grid-template-columns:1fr}}
.col{display:flex;flex-direction:column;gap:12px}
.full{grid-column:1/-1}

.card{background:var(--c1);border:1px solid var(--bd)}
.card-h{display:flex;align-items:center;justify-content:space-between;padding:7px 12px;border-bottom:1px solid var(--bd);background:var(--c2)}
.card-h h2{font-size:12px;font-weight:bold;color:var(--gr);letter-spacing:1px}
.card-h small{color:var(--td);font-size:11px}

.apps-g{display:grid;grid-template-columns:repeat(auto-fill,minmax(115px,1fr));gap:8px;padding:10px 12px}
.app-t{
  display:flex;flex-direction:column;align-items:center;justify-content:center;
  padding:14px 8px 10px;text-align:center;background:var(--c2);border:1px solid var(--bd);
  transition:border-color .15s,background .15s;color:var(--tx);
  min-height:80px;text-decoration:none;
}
.app-t:hover{border-color:var(--gr);background:#122012;text-decoration:none;color:var(--tx)}
.app-t:hover .an{color:var(--gr)}
.ai{font-size:26px;line-height:1;margin-bottom:5px}
.an{font-size:11px;color:var(--td);transition:color .15s}
.ap{font-size:10px;color:var(--gd);margin-top:2px}

ul.lst{list-style:none}
ul.lst li{display:flex;align-items:center;justify-content:space-between;padding:6px 12px;border-bottom:1px solid var(--bd);transition:background .1s}
ul.lst li:last-child{border-bottom:none}
ul.lst li:hover{background:var(--c2)}
.in{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--tx)}
.im{flex-shrink:0;margin-left:8px;color:var(--td);font-size:11px;white-space:nowrap}
.tag{background:#0a200a;color:var(--gd);font-size:10px;padding:1px 5px}
.lo{color:var(--td);font-size:12px;padding:10px 12px}
.er{color:var(--re);font-size:12px;padding:10px 12px}

.feed-add{display:flex;gap:6px;padding:8px 12px;border-top:1px solid var(--bd)}
.feed-add input{flex:1;background:#070c07;border:1px solid var(--bd);color:var(--tx);padding:5px 8px;font:inherit;font-size:12px;outline:none}
.feed-add input:focus{border-color:var(--gr)}

#ai-btn{
  position:fixed;bottom:18px;right:18px;z-index:50;
  background:var(--gd);color:#dcfce7;border:none;padding:10px 16px;
  font:bold 13px 'Courier New',Courier,monospace;
  box-shadow:0 0 16px rgba(34,197,94,.25);transition:background .15s;
}
#ai-btn:hover{background:var(--gr);color:#000}

#ai-panel{
  position:fixed;right:-420px;top:0;width:400px;height:100vh;
  background:var(--c1);border-left:1px solid var(--bd);
  display:flex;flex-direction:column;z-index:100;
  transition:right .25s ease;box-shadow:-4px 0 24px rgba(0,0,0,.6);
}
#ai-panel.open{right:0}
#ai-ph{display:flex;justify-content:space-between;align-items:center;padding:10px 14px;border-bottom:1px solid var(--bd);background:var(--c2);color:var(--gr);font-weight:bold;font-size:13px}
#ai-ph button{background:none;border:none;color:var(--td);font-size:17px;cursor:pointer}
#ai-ph button:hover{color:var(--tx)}
.ai-prov{display:flex;align-items:center;gap:6px;padding:6px 12px;border-bottom:1px solid var(--bd)}
.ai-prov span{color:var(--td);font-size:11px;white-space:nowrap}
.ai-prov select{flex:1;background:#070c07;border:1px solid var(--bd);color:var(--tx);font:11px 'Courier New',Courier,monospace;padding:4px 6px;outline:none}
#ai-msgs{flex:1;overflow-y:auto;padding:10px;display:flex;flex-direction:column;gap:8px}
.mb{padding:8px 10px;font-size:12px;line-height:1.5;max-width:93%;white-space:pre-wrap;word-break:break-word;border:1px solid var(--bd)}
.mb.u{background:#0f2210;color:var(--tx);align-self:flex-end}
.mb.a{background:var(--c2);color:var(--tx);align-self:flex-start}
#ai-inp{display:flex;gap:6px;padding:8px;border-top:1px solid var(--bd);background:var(--c2)}
#ai-ta{flex:1;background:#070c07;border:1px solid var(--bd);color:var(--tx);padding:7px;font:12px 'Courier New',Courier,monospace;outline:none;resize:none;min-height:56px}
#ai-ta:focus{border-color:var(--gr)}
.ai-btns{display:flex;flex-direction:column;gap:4px}

::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--bd)}
</style>
</head>
<body>

<header>
  <div class="logo">⬡ NeXuS <sub>Map</sub></div>
  <div class="hdr-r">
    <span id="node-lbl"></span>
    <span id="clock"></span>
  </div>
</header>

<div class="search">
  <input id="sq" type="text" placeholder="🔍  Search all of NeXuS…" onkeydown="if(event.key==='Enter')doSearch()">
  <button class="btn" onclick="doSearch()">SEARCH</button>
  <button class="btn-g" onclick="window.open('/search','_blank')">Search App</button>
  <button class="btn-g" onclick="window.open('/timeline','_blank')">Timeline</button>
  <button class="btn-g" onclick="window.open('/servers','_blank')">Servers</button>
  <button class="btn-g" onclick="window.open('/governor/','_blank')">⚡ Governor</button>
  <button class="btn-g" onclick="window.open('/publish/','_blank')">📡 Publish</button>
  <button class="btn-g" onclick="window.open('/social/','_blank')">🐌 Social</button>
  <button class="btn-g" onclick="window.open('/files','_blank')">📁 Files</button>
  <button class="btn-g" id="sync-btn" onclick="syncWiki()">📚 Sync Wiki</button>
</div>
<div id="toast" style="display:none;position:fixed;top:14px;right:14px;z-index:300;max-width:420px;background:var(--c1);border:1px solid var(--bd);padding:12px 16px;font-size:12px;box-shadow:0 4px 20px rgba(0,0,0,.6);white-space:pre-wrap;word-break:break-word;max-height:60vh;overflow-y:auto"></div>

<div class="grid">

  <div class="card full">
    <div class="card-h"><h2>⚡ APPS</h2><small id="apps-ct"></small></div>
    <div class="apps-g" id="apps-g"><p class="lo">Loading…</p></div>
  </div>

  <div class="col">
    <div class="card">
      <div class="card-h"><h2>🪨 FOSSIL REPOS</h2><small id="foss-ct"></small></div>
      <ul class="lst" id="foss-l"><li class="lo">Loading…</li></ul>
    </div>
    <div class="card">
      <div class="card-h"><h2>📄 LATEST EXPORTS</h2><small>session logs · ~/claude/</small></div>
      <ul class="lst" id="exp-l"><li class="lo">Loading…</li></ul>
    </div>
    <div class="card">
      <div class="card-h"><h2>📡 RSS / FEEDS</h2><small id="feeds-ct"></small></div>
      <ul class="lst" id="feeds-l"></ul>
      <div class="feed-add">
        <input type="text" id="feed-url" placeholder="https://example.com/feed.xml" onkeydown="if(event.key==='Enter')addFeed()">
        <button class="btn" style="font-size:11px;padding:5px 8px" onclick="addFeed()">+ Add</button>
      </div>
    </div>
  </div>

  <div class="col">
    <div class="card">
      <div class="card-h"><h2>🐙 GITHUB</h2><small id="gh-lbl">hackenstacks</small></div>
      <ul class="lst" id="gh-l"><li class="lo">Loading…</li></ul>
    </div>
    <div class="card">
      <div class="card-h"><h2>📰 HACKER NEWS</h2><small>top stories</small></div>
      <ul class="lst" id="hn-l"><li class="lo">Loading…</li></ul>
    </div>
  </div>

</div>

<button id="ai-btn" onclick="toggleAI()">⚡ AI</button>
<div id="ai-panel">
  <div id="ai-ph">
    <span>⚡ NeXuS AI</span>
    <button onclick="toggleAI()">✕</button>
  </div>
  <div class="ai-prov">
    <span>Provider:</span>
    <select id="ai-prov">
      <option value="ollama">Ollama (local)</option>
      <option value="aichat">aichat</option>
      <option value="aihorde">AI Horde</option>
      <option value="groq">Groq</option>
      <option value="mistral">Mistral</option>
      <option value="openrouter">OpenRouter</option>
    </select>
  </div>
  <div id="ai-msgs"></div>
  <div id="ai-inp">
    <textarea id="ai-ta" placeholder="Ask NeXuS AI…&#10;Enter = send   Shift+Enter = newline" onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();sendAI()}"></textarea>
    <div class="ai-btns">
      <button class="btn" onclick="sendAI()">Send</button>
      <button class="btn-g" onclick="clearAI()" style="padding:5px 8px;font-size:11px">Clear</button>
    </div>
  </div>
</div>

<script>
'use strict';

// ── CLOCK
(function tick(){
  var el=document.getElementById('clock');
  if(el) el.textContent=new Date().toLocaleTimeString('en-GB',{hour12:false});
  setTimeout(tick,1000);
})();

// ── SEARCH
function doSearch(){
  var q=document.getElementById('sq').value.trim();
  if(!q) return;
  window.open('/search?q='+encodeURIComponent(q),'_blank');
}

// ── ESCAPE (XSS safe)
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function safeUrl(u){return /^https?:\\/\\//.test(u)?u:'#';}

// ── LOAD MAP DATA FROM SERVER
var _ghUser='hackenstacks';
async function loadMap(){
  try{
    var d=await fetch('/api/nexus/map').then(r=>r.json());
    _ghUser=d.github_user||'hackenstacks';
    if(d.node) document.getElementById('node-lbl').textContent='⬡ '+d.node;
    document.getElementById('gh-lbl').textContent=_ghUser;
    renderApps(d.apps||[]);
    renderFossils(d.fossils||[]);
    renderExports(d.exports||[]);
  }catch(e){
    document.getElementById('apps-g').innerHTML='<p class="er">Map API unavailable: '+esc(String(e))+'</p>';
  }
  loadGH(_ghUser);
  loadHN();
}

// ── APPS GRID
function renderApps(apps){
  var g=document.getElementById('apps-g');
  var ct=document.getElementById('apps-ct');
  if(!apps.length){g.innerHTML='<p class="lo">No apps registered — add NEXUS_APP_* vars to nexus.env</p>';return;}
  ct.textContent=apps.length+' apps';
  g.innerHTML=apps.map(function(a){
    return '<a class="app-t" href="'+esc(a.prefix||'#')+'" target="_blank" rel="noopener">'
      +'<div class="ai">'+esc(a.icon||'📦')+'</div>'
      +'<div style="font-size:12px;font-weight:bold">'+esc(a.label||a.id)+'</div>'
      +'<div class="ap">'+esc(a.prefix||'')+'</div>'
      +'</a>';
  }).join('');
}

// ── FOSSIL REPOS
function renderFossils(fossils){
  var el=document.getElementById('foss-l');
  var ct=document.getElementById('foss-ct');
  if(!fossils.length){el.innerHTML='<li class="lo">No .fossil files in NEXUS_FOSSIL_DIR (~museum/)</li>';return;}
  ct.textContent=fossils.length+' repos';
  el.innerHTML=fossils.map(function(f){
    return '<li><span class="in">🪨 '+esc(f.name)+'</span><span class="im">'+f.size_kb+'K</span></li>';
  }).join('');
}

// ── EXPORT FILES
function renderExports(exps){
  var el=document.getElementById('exp-l');
  if(!exps.length){el.innerHTML='<li class="lo">No .txt exports found</li>';return;}
  el.innerHTML=exps.map(function(e){
    return '<li title="'+esc(e.name)+'"><span class="in">📄 '+esc(e.date)+'</span><span class="im">'+e.size_kb+'K</span></li>';
  }).join('');
}

// ── GITHUB
async function loadGH(user){
  var el=document.getElementById('gh-l');
  try{
    var repos=await fetch('https://api.github.com/users/'+encodeURIComponent(user)+'/repos?sort=updated&per_page=10').then(function(r){
      if(!r.ok) throw new Error('HTTP '+r.status);
      return r.json();
    });
    if(!repos.length){el.innerHTML='<li class="lo">No public repos</li>';return;}
    el.innerHTML=repos.map(function(r){
      var lang=r.language?'<span class="tag">'+esc(r.language)+'</span>':'';
      var stars=r.stargazers_count?'★'+r.stargazers_count+' ':'';
      return '<li><a class="in" href="'+esc(r.html_url)+'" target="_blank" rel="noopener">'+esc(r.name)+'</a>'
        +'<span class="im">'+stars+lang+'</span></li>';
    }).join('');
  }catch(e){
    el.innerHTML='<li class="er">GitHub unavailable (offline or rate-limited)</li>';
  }
}

// ── HACKER NEWS (Algolia)
async function loadHN(){
  var el=document.getElementById('hn-l');
  try{
    var d=await fetch('https://hn.algolia.com/api/v1/search?tags=front_page&hitsPerPage=12').then(function(r){
      if(!r.ok) throw new Error('HTTP '+r.status);
      return r.json();
    });
    var hits=d.hits||[];
    if(!hits.length){el.innerHTML='<li class="lo">No stories</li>';return;}
    el.innerHTML=hits.map(function(h){
      var url=h.url||'https://news.ycombinator.com/item?id='+h.objectID;
      return '<li><a class="in" href="'+esc(url)+'" target="_blank" rel="noopener" title="'+esc(h.title)+'">'+esc(h.title)+'</a>'
        +'<span class="im">'+(h.points||0)+'▲</span></li>';
    }).join('');
  }catch(e){
    el.innerHTML='<li class="er">HN unavailable (offline?)</li>';
  }
}

// ── RSS FEEDS (localStorage)
function loadFeeds(){
  var feeds=JSON.parse(localStorage.getItem('nexus_feeds')||'[]');
  var el=document.getElementById('feeds-l');
  var ct=document.getElementById('feeds-ct');
  ct.textContent=feeds.length?feeds.length+' saved':'';
  if(!feeds.length){
    el.innerHTML='<li class="lo">Paste an RSS URL below to save it</li>';
    return;
  }
  el.innerHTML=feeds.map(function(f,i){
    var label=f.replace(/^https?:\\/\\//, '').slice(0,54);
    return '<li><a class="in" href="'+esc(safeUrl(f))+'" target="_blank" rel="noopener">'+esc(label)+'</a>'
      +'<span class="im"><button class="btn-g" style="font-size:10px;padding:1px 5px" onclick="rmFeed('+i+')">✕</button></span></li>';
  }).join('');
}
function addFeed(){
  var inp=document.getElementById('feed-url');
  var url=inp.value.trim();
  if(!url.startsWith('http')){inp.focus();return;}
  var feeds=JSON.parse(localStorage.getItem('nexus_feeds')||'[]');
  if(!feeds.includes(url)) feeds.push(url);
  localStorage.setItem('nexus_feeds',JSON.stringify(feeds));
  inp.value='';loadFeeds();
}
function rmFeed(i){
  var feeds=JSON.parse(localStorage.getItem('nexus_feeds')||'[]');
  feeds.splice(i,1);
  localStorage.setItem('nexus_feeds',JSON.stringify(feeds));
  loadFeeds();
}

// ── AI SLIDE-OUT PANEL
var _aiOpen=false;
function toggleAI(){
  _aiOpen=!_aiOpen;
  document.getElementById('ai-panel').classList.toggle('open',_aiOpen);
  document.getElementById('ai-btn').textContent=_aiOpen?'✕ Close':'⚡ AI';
}
function clearAI(){document.getElementById('ai-msgs').innerHTML='';}

async function sendAI(){
  var ta=document.getElementById('ai-ta');
  var msg=ta.value.trim();
  if(!msg) return;
  var prov=document.getElementById('ai-prov').value;
  var msgs=document.getElementById('ai-msgs');

  var ub=document.createElement('div');
  ub.className='mb u';ub.textContent=msg;msgs.appendChild(ub);ta.value='';

  var ab=document.createElement('div');
  ab.className='mb a';ab.textContent='…';msgs.appendChild(ab);
  msgs.scrollTop=msgs.scrollHeight;

  try{
    var body={provider:prov,messages:[{role:'user',content:msg}],stream:false};
    if(prov==='ollama') body.model='llama3.2';
    var r=await fetch('/api/llm',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    if(!r.ok){
      var e=await r.json().catch(function(){return {error:'HTTP '+r.status};});
      ab.textContent='Error: '+(e.error||r.status);
      return;
    }
    var d=await r.json();
    ab.textContent=d.choices&&d.choices[0]&&d.choices[0].message?d.choices[0].message.content
      :d.response||JSON.stringify(d,null,2);
  }catch(e){
    ab.textContent='Error: '+e.message;
  }
  msgs.scrollTop=msgs.scrollHeight;
}

// ── WIKI SYNC
function showToast(msg,ok){
  var t=document.getElementById('toast');
  t.style.borderColor=ok?'var(--gr)':'var(--re)';
  t.style.color=ok?'var(--tx)':'var(--re)';
  t.textContent=msg;
  t.style.display='block';
  if(ok) setTimeout(function(){t.style.display='none';},8000);
}
async function syncWiki(){
  var btn=document.getElementById('sync-btn');
  btn.textContent='⏳ Syncing…';btn.disabled=true;
  showToast('nexus-wiki: syncing…',true);
  try{
    var r=await fetch('/api/nexus/wiki-sync',{method:'POST'});
    var d=await r.json();
    btn.textContent='📚 Sync Wiki';btn.disabled=false;
    showToast((d.ok?'✓ ':'✗ ')+(d.output||'done'),d.ok);
  }catch(e){
    btn.textContent='📚 Sync Wiki';btn.disabled=false;
    showToast('Sync failed: '+e.message,false);
  }
}

// ── INIT
loadMap();
loadFeeds();
</script>
</body>
</html>""".encode("utf-8")

    def _timeline_render(self, md):
        """Inline markdown → NeXuS-themed HTML. No external deps."""
        import re

        def inline(text):
            # images first — rewrite relative paths to /timeline/images/
            text = re.sub(r'!\[([^\]]*)\]\(images/([^)]+)\)',
                          lambda m: f'<img src="/timeline/images/{m.group(2)}" alt="{html.escape(m.group(1))}">', text)
            text = re.sub(r'!\[([^\]]*)\]\(([^)]+)\)',
                          lambda m: f'<img src="{m.group(2)}" alt="{html.escape(m.group(1))}">', text)
            # links
            text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)',
                          lambda m: f'<a href="{m.group(2)}">{m.group(1)}</a>', text)
            # bold
            text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
            # inline code
            text = re.sub(r'`([^`]+)`', lambda m: f'<code>{html.escape(m.group(1))}</code>', text)
            # italic
            text = re.sub(r'\*(.+?)\*', r'<em>\1</em>', text)
            return text

        lines = md.split("\n")
        out = []
        in_code = False
        in_list = False
        in_table = False
        in_blockquote = False

        def close_list():
            nonlocal in_list
            if in_list:
                out.append("</ul>")
                in_list = False

        def close_table():
            nonlocal in_table
            if in_table:
                out.append("</tbody></table>")
                in_table = False

        for line in lines:
            # fenced code blocks
            if line.startswith("```"):
                close_list(); close_table()
                if in_code:
                    out.append("</code></pre>")
                    in_code = False
                else:
                    lang = html.escape(line[3:].strip() or "")
                    out.append(f'<pre><code class="lang-{lang}">')
                    in_code = True
                continue
            if in_code:
                out.append(html.escape(line))
                continue

            # blockquote
            if line.startswith("> "):
                close_list(); close_table()
                out.append(f'<blockquote>{inline(line[2:])}</blockquote>')
                continue

            # table rows
            if "|" in line and line.strip().startswith("|"):
                cells = [c.strip() for c in line.strip().strip("|").split("|")]
                if all(re.match(r'^[-: ]+$', c) for c in cells):
                    continue  # separator row
                close_list()
                if not in_table:
                    out.append('<table><thead>')
                    out.append("<tr>" + "".join(f"<th>{inline(c)}</th>" for c in cells) + "</tr>")
                    out.append("</thead><tbody>")
                    in_table = True
                else:
                    out.append("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in cells) + "</tr>")
                continue
            else:
                close_table()

            # headers
            m = re.match(r'^(#{1,4})\s+(.*)', line)
            if m:
                close_list()
                level = len(m.group(1))
                text = inline(m.group(2))
                slug = re.sub(r'[^\w-]', '-', re.sub(r'[^\w\s-]', '', m.group(2).lower())).strip('-')
                out.append(f'<h{level} id="{slug}">{text}</h{level}>')
                continue

            # horizontal rule
            if re.match(r'^[-*_]{3,}\s*$', line):
                close_list()
                out.append('<hr>')
                continue

            # unordered list
            if re.match(r'^[-*] ', line):
                if not in_list:
                    out.append("<ul>")
                    in_list = True
                out.append(f'<li>{inline(line[2:])}</li>')
                continue
            else:
                close_list()

            # blank line
            if not line.strip():
                out.append('')
                continue

            # paragraph
            out.append(f'<p>{inline(line)}</p>')

        close_list(); close_table()
        if in_code:
            out.append("</code></pre>")

        body = "\n".join(out)
        return (
            '<!DOCTYPE html><html lang="en"><head>'
            '<meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>NeXuS Living Timeline</title>'
            '<style>'
            ':root{--g:#39ff14;--c:#00e5ff;--a:#ffb300;--r:#ff4444;--bg:#070b07;--s:#0d130d;--br:#1a3a1a}'
            'body{background:var(--bg);color:#b8e8b8;font-family:"JetBrains Mono","Fira Code",monospace;'
            'max-width:980px;margin:0 auto;padding:2rem 1.5rem;line-height:1.75}'
            'h1{color:var(--g);font-size:1.9rem;text-shadow:0 0 24px var(--g);border-bottom:1px solid var(--br);padding-bottom:.4rem}'
            'h2{color:var(--c);border-bottom:1px solid #0a2a2a;padding-bottom:.3rem}'
            'h3{color:var(--a);border-bottom:1px solid #2a1a00;padding-bottom:.2rem}'
            'h4{color:#c890f0}'
            'a{color:var(--c);text-decoration:none}a:hover{text-shadow:0 0 8px var(--c)}'
            'pre{background:var(--s);border:1px solid var(--br);border-radius:6px;'
            'padding:1rem;overflow-x:auto;font-size:.85rem;line-height:1.5}'
            'code{color:var(--g);font-family:inherit;font-size:.9em}'
            'pre code{color:#90c890}'
            'img{max-width:100%;border:1px solid var(--br);border-radius:6px;margin:1rem 0;display:block}'
            'hr{border:none;border-top:1px solid var(--br);margin:2.5rem 0}'
            'blockquote{border-left:3px solid var(--g);margin:1rem 0 1rem 0;padding:.5rem 1rem;'
            'color:#70a870;background:var(--s);border-radius:0 4px 4px 0;font-style:italic}'
            'table{border-collapse:collapse;width:100%;margin:1rem 0}'
            'th{background:var(--s);color:var(--g);border:1px solid var(--br);padding:.5rem .75rem;text-align:left}'
            'td{border:1px solid var(--br);padding:.4rem .75rem}'
            'ul{margin:.5rem 0;padding-left:1.5rem}li{margin:.3rem 0}'
            'strong{color:#d0ffd0}em{color:#90d890}'
            '.nav{position:sticky;top:0;background:rgba(7,11,7,.96);border-bottom:1px solid var(--br);'
            'padding:.6rem 0;margin:-2rem -1.5rem 2rem;padding-left:1.5rem;backdrop-filter:blur(6px);z-index:10}'
            '.nav a{margin-right:1.5rem;color:var(--g);font-size:.82rem}'
            'footer{margin-top:4rem;padding-top:1rem;border-top:1px solid var(--br);color:#406040;font-size:.8rem}'
            '</style></head><body>'
            '<div class="nav">'
            '<a href="/">← NeXuS Home</a>'
            '<a href="/servers">⚙ Servers</a>'
            '<a href="/timeline">📜 Timeline</a>'
            '<a href="/governor/">⚡ Governor</a>'
            '</div>'
            + body +
            '<footer><p>Sane · Simple · Secure · Stealthy · Beautiful · Sustainable</p>'
            '<p>The table outlasts every king. meWEwowow 💥</p></footer>'
            '</body></html>'
        )

    def _md_page(self, title, body_html):
        return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title>
<link rel="stylesheet" href="/static/hljs/styles/tokyo-night-dark.min.css">
<style>
:root{{--bg:#1a1b26;--bg2:#16161e;--fg:#a9b1d6;--dim:#565f89;--blue:#7aa2f7;--green:#9ece6a;--yellow:#e0af68;--red:#f7768e;--border:#292e42}}
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--fg);font:15px/1.7 'JetBrains Mono','Fira Mono',ui-monospace,monospace;max-width:860px;margin:0 auto;padding:2.5rem 2rem 4rem}}
h1,h2,h3,h4{{color:var(--blue);font-weight:700;margin:2rem 0 .6rem;letter-spacing:-.01em}}
h1{{font-size:2rem;border-bottom:1px solid var(--border);padding-bottom:.5rem}}
h2{{font-size:1.4rem}}
h3{{font-size:1.15rem;color:var(--yellow)}}
h4{{font-size:1rem;color:var(--green)}}
p{{margin:.7rem 0}}
a{{color:var(--blue);text-decoration:none}}
a:hover{{text-decoration:underline;color:var(--green)}}
ul,ol{{margin:.7rem 0 .7rem 1.5rem}}
li{{margin:.2rem 0}}
blockquote{{border-left:3px solid var(--blue);margin:1rem 0;padding:.5rem 1rem;background:var(--bg2);color:var(--dim);font-style:italic}}
code{{background:var(--bg2);color:var(--green);padding:.1em .4em;border-radius:3px;font-size:.92em}}
pre{{background:var(--bg2)!important;border:1px solid var(--border);border-radius:4px;padding:1rem 1.25rem;overflow-x:auto;margin:1rem 0;font-size:.88em;line-height:1.5}}
pre code{{background:none;padding:0;color:inherit;font-size:inherit;border-radius:0}}
table{{border-collapse:collapse;width:100%;margin:1rem 0;font-size:.9em}}
th,td{{border:1px solid var(--border);padding:.45rem .75rem;text-align:left}}
th{{background:var(--bg2);color:var(--yellow);font-weight:600}}
tr:hover td{{background:var(--bg2)}}
img{{max-width:100%;border-radius:4px;margin:.5rem 0}}
hr{{border:none;border-top:1px solid var(--border);margin:2rem 0}}
strong{{color:#c0caf5;font-weight:700}}
em{{color:var(--dim);font-style:italic}}
</style>
</head>
<body>
{body_html}
<script src="/static/hljs/highlight.min.js"></script>
<script>
document.querySelectorAll('pre code[class]').forEach(el=>{{
  el.className=el.className.replace(/\\blang-(\\S+)/,'language-$1');
}});
hljs.highlightAll();
</script>
</body>
</html>"""

    def _serve_static(self, path):
        target, _spa = self._resolve(path)
        if target is None:
            return self._json({"error": "forbidden or not found"}, 404)
        if target.is_dir():                          # a dir with no index.html -> landing list
            return self._landing(target, path)
        try:
            data = target.read_bytes()
        except OSError:
            return self._json({"error": "500"}, 500)
        # Render .md files as styled HTML with highlight.js
        if target.suffix.lower() == ".md":
            md_text = data.decode("utf-8", errors="replace")
            body = self._timeline_render(md_text)
            return self._bytes(self._md_page(target.name, body).encode("utf-8"), "text/html")
        ctype = MIME_TYPES.get(target.suffix.lower(), "application/octet-stream")
        # Extensionless files — sniff first bytes to detect JavaScript bundles
        if not target.suffix and ctype == "application/octet-stream":
            peek = data[:300]
            js_sigs = (b"(function", b"!function", b"var ", b"let ", b"const ",
                       b'"use strict"', b"'use strict'", b"//", b"/*", b"export ")
            if any(peek.lstrip().startswith(s) for s in js_sigs):
                ctype = "application/javascript"
        # Inject fetch interceptor into OpenCharacters HTML so API calls route through proxy
        if path.startswith("/oc/") and "html" in ctype:
            html_str = data.decode("utf-8", errors="replace")
            data = html_str.replace("<head>", "<head>\n" + self._OC_INJECT, 1).encode("utf-8")
        self._bytes(data, ctype)

    def _landing(self, directory, path):
        """Minimal 'drop a folder in' index: list subfolders/apps under this dir."""
        base = path if path.endswith("/") else path + "/"
        items = []
        for entry in sorted(directory.iterdir(), key=lambda p: (p.is_file(), p.name.lower())):
            name = entry.name + ("/" if entry.is_dir() else "")
            items.append(f'<li><a href="{html.escape(base + name)}">{html.escape(name)}</a></li>')
        page = (
            "<!doctype html><meta charset=utf-8><title>NeXuS Web</title>"
            "<style>body{background:#0b0f14;color:#c8e1ff;font:16px/1.6 system-ui,monospace;"
            "max-width:720px;margin:6vh auto;padding:0 1.2rem}h1{color:#7fdfff}"
            "a{color:#9fe0ff;text-decoration:none}a:hover{text-decoration:underline}"
            "li{margin:.2rem 0}code{color:#8fffbf}</style>"
            "<h1>🔐 NeXuS Web Server</h1>"
            f"<p>Serving <code>{html.escape(str(ROOT))}</code>. "
            "Drop an app folder in the root and it appears here. "
            "All apps share the <code>/api/*</code> key-injecting proxy.</p>"
            f"<ul>{''.join(items) or '<li><em>(empty)</em></li>'}</ul>"
        )
        self._bytes(page.encode("utf-8"), "text/html")


ENV_FILENAMES = (".local.env", ".env")           # recognised project-local secret files
GITIGNORE_PATTERNS = [".local.env", ".env", "*.local.env", "*.env", "*.key", "*.pem", "nexus.env"]


def discover_local_env(explicit, root):
    """Ordered list of project-local env files (first found wins per key).
    Kept OUTSIDE the browser's reach — these are never served (see is_secret_path).
    Search dirs: CWD, script dir, and the web root's PARENT (project dir when serving dist/);
    filenames: .local.env then .env. The root itself is intentionally NOT searched —
    secrets don't belong in a docroot. An explicit --env path is honoured first."""
    candidates = []
    if explicit:
        candidates.append(Path(explicit))
    for d in (Path.cwd(), BASE_DIR, root.parent):
        for fn in ENV_FILENAMES:
            candidates.append(d / fn)
    seen, found = set(), []
    for c in candidates:
        c = c.resolve()
        if c in seen:
            continue
        seen.add(c)
        if c.is_file():
            found.append(c)
    return found


def ensure_gitignore(env_files):
    """Safety net: whenever a secret env file is found, make sure a .gitignore in that same
    folder excludes it (and sibling secret patterns). Append-only + idempotent — we never
    overwrite an existing .gitignore, only add missing lines. Stops an accidental `git add`."""
    for parent in {f.parent for f in env_files}:
        gi = parent / ".gitignore"
        try:
            existing = gi.read_text(encoding="utf-8") if gi.is_file() else ""
        except OSError:
            existing = ""
        have = {ln.strip() for ln in existing.splitlines()}
        add = [p for p in GITIGNORE_PATTERNS if p not in have]
        if not add:
            continue
        block = ("" if existing.endswith("\n") or not existing else "\n") \
            + "\n# NeXuS: never commit secrets (auto-added by nexus_web_server)\n" \
            + "\n".join(add) + "\n"
        try:
            with gi.open("a", encoding="utf-8") as fh:
                fh.write(block)
            log(f"🛡️  {'created' if not existing else 'updated'} {gi} (+{len(add)} secret patterns)")
        except OSError as e:
            log(f"⚠️  could not write {gi}: {e}")


def main():
    global ROOT, LOCAL_ENV_FILES, APP_REGISTRY
    ap = argparse.ArgumentParser(description="NeXuS portable HTTPS web server")
    ap.add_argument("--root", default=str(BASE_DIR / "dist"),
                    help="web root directory to serve (default: ./dist)")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--cert", default=None, help="TLS cert PEM (default: ./cert.pem)")
    ap.add_argument("--key",  default=None, help="TLS key PEM (default: ./key.pem)")
    ap.add_argument("--env",  default=None,
                    help="explicit .local.env path (overrides nexus.env; auto-discovered otherwise)")
    args = ap.parse_args()

    ROOT = Path(args.root).resolve()
    if not ROOT.is_dir():
        sys.exit(f"❌ web root not found: {ROOT}")

    LOCAL_ENV_FILES = discover_local_env(args.env, ROOT)
    if LOCAL_ENV_FILES:
        ensure_gitignore(LOCAL_ENV_FILES)            # auto-protect found secrets from git
    for f in LOCAL_ENV_FILES:
        try:
            if f.stat().st_mode & 0o077:
                log(f"⚠️  {f} is {oct(f.stat().st_mode & 0o777)} — secrets should be chmod 600 (run: chmod 600 {f})")
        except OSError:
            pass

    cert = Path(args.cert) if args.cert else BASE_DIR / "cert.pem"
    key  = Path(args.key)  if args.key  else BASE_DIR / "key.pem"
    if not (cert.is_file() and key.is_file()):
        log(f"🔐 No TLS cert found — generating self-signed cert at {cert} …")
        import subprocess as _sp
        _sp.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key), "-out", str(cert),
            "-days", "3650", "-nodes",
            "-subj", "/CN=localhost",
            "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
        ], check=True, capture_output=True)
        key.chmod(0o600)
        log(f"✅ Cert generated ({cert.name}, {key.name}) — import cert.pem into browser once to trust it")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    APP_REGISTRY = _build_app_registry()
    _install_gateway_proxy()

    keyed = keyed_providers()
    print("\n╔══════════════════════════════════════════════════════════════╗")
    print("║   🔐 NeXuS WEB SERVER — portable HTTPS (Python, no npm)      ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    log(f"✅ HTTPS https://localhost:{args.port}   root={ROOT}")
    src = " → ".join(["process-env"] + [str(f) for f in LOCAL_ENV_FILES] + [str(SECRETS_DIR / 'nexus.env')])
    log(f"🗝️  secret precedence: {src}")
    log("🔑 provider keys: " + ", ".join(f"{k}={'yes' if v else 'no'}" for k, v in keyed.items()))
    if APP_REGISTRY:
        log("📦 registered apps: " + "  ".join(f"{a['prefix']}→{'static+' if a['static'] else ''}{a['backend'] or 'static'}" for a in APP_REGISTRY.values()))
    log("🛑 Ctrl+C to stop")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log("🛑 shutting down")
        httpd.shutdown()


if __name__ == "__main__":
    main()
