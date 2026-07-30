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
SECRETS_DIR = Path(os.environ.get("HOME", "")) / ".config/nexus/secrets"

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
    "aihorde":      {"label": "AI Horde (keyless)","base_url": "https://aihorde.net/api/v2",
                     "key_env": None,                   "requires_key": False, "kind": "chat+image"},
}
DEFAULTS = {"main": "aihorde", "image": "pollinations", "embedding": "local"}

POLLI_BASE = "https://gen.pollinations.ai"
UA = "nexus-web-server"
LLM_PATH_RE = re.compile(r"^/api/llm/([A-Za-z0-9_.-]+)/(?:v1/)?chat/completions/?$")

# ── Charcard backend (nexus_png2_editor.py Flask app) ────────────────────────
CHARCARD_BACKEND = os.environ.get("CHARCARD_URL", "http://127.0.0.1:7420")
CHARCARD_PREFIX  = "/charcard"


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
    def _send(self, code, ctype, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode("utf-8")
        self._send(code, "application/json",
                   {"Content-Length": str(len(body)), "Cache-Control": "no-store"})
        self.wfile.write(body)

    def _bytes(self, data, ctype, cache="no-store", code=200):
        self._send(code, ctype, {"Content-Length": str(len(data)), "Cache-Control": cache})
        self.wfile.write(data)

    # ── routing ───────────────────────────────────────────────────────────────
    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
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
        if path.startswith("/api/"):
            return self._json({"error": f"unknown API route {path}"}, 404)
        if path.startswith(CHARCARD_PREFIX):
            return self._charcard_proxy()
        if path in ("/oc/", "/oc/index.html"):
            self._send(302, "text/plain", {"Location": "/oc/play.html"})
            return
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
        if path.startswith(CHARCARD_PREFIX):
            return self._charcard_proxy()
        return self._json({"error": f"unknown API route {path}"}, 404)

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
        base = (payload.pop("base_url", None) or prov["base_url"]).rstrip("/")
        url = f"{base}/chat/completions"
        headers = {"Content-Type": "application/json", "User-Agent": UA}
        if prov["requires_key"]:
            key = load_secret(prov["key_env"])
            if not key:
                return self._json({"error": f"{prov['label']} needs a key: set {prov['key_env']} in nexus.env"}, 502)
            headers["Authorization"] = f"Bearer {key}"

        body = json.dumps(payload).encode("utf-8")
        log(f"[PROXY] llm {pid} -> {url} (stream={bool(payload.get('stream'))})")
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

    # Script injected into OpenCharacters HTML to intercept API calls → proxy
    _OC_INJECT = (
        '<script>/* NeXuS proxy — routes AI calls through local key-injecting proxy */\n'
        '(function(){\n'
        '  var BASE=window.location.origin;\n'
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
        '})();\n'
        '</script>'
    )

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
        ctype = MIME_TYPES.get(target.suffix.lower(), "application/octet-stream")
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
    global ROOT, LOCAL_ENV_FILES
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
        sys.exit(f"❌ TLS cert/key not found ({cert}, {key}). Pass --cert/--key.")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    keyed = keyed_providers()
    print("\n╔══════════════════════════════════════════════════════════════╗")
    print("║   🔐 NeXuS WEB SERVER — portable HTTPS (Python, no npm)      ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    log(f"✅ HTTPS https://localhost:{args.port}   root={ROOT}")
    src = " → ".join(["process-env"] + [str(f) for f in LOCAL_ENV_FILES] + [str(SECRETS_DIR / 'nexus.env')])
    log(f"🗝️  secret precedence: {src}")
    log("🔑 provider keys: " + ", ".join(f"{k}={'yes' if v else 'no'}" for k, v in keyed.items()))
    log("🛑 Ctrl+C to stop")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log("🛑 shutting down")
        httpd.shutdown()


if __name__ == "__main__":
    main()
