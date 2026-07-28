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
        "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https:; "
        "connect-src 'self' https: http://localhost:*; font-src 'self' data:;"
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


def load_secret(name):
    """Read a secret from nexus.env (KEY=value); legacy pollinations.key fallback."""
    if not name:
        return None
    try:
        for line in (SECRETS_DIR / "nexus.env").read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            if k.strip() == name:
                return v.strip().strip('"').strip("'")
    except OSError:
        pass
    if name == "POLLINATIONS_API_KEY":
        try:
            return (SECRETS_DIR / "pollinations.key").read_text(encoding="utf-8").strip()
        except OSError:
            pass
    return None


def keyed_providers():
    return {pid: ((not p["requires_key"]) or bool(load_secret(p["key_env"])))
            for pid, p in PROVIDERS.items()}


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
        if path == "/api/pollinations/image":
            return self._pollinations_image()
        if path.startswith("/api/"):
            return self._json({"error": f"unknown API route {path}"}, 404)
        return self._serve_static(path)

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/llm":
            return self._llm_proxy(provider_from_url=None)
        m = LLM_PATH_RE.match(path)
        if m:
            return self._llm_proxy(provider_from_url=m.group(1))
        return self._json({"error": f"unknown API route {path}"}, 404)

    def do_OPTIONS(self):
        self._send(204, "text/plain", {
            "Access-Control-Allow-Origin": "'self'",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
        })

    # ── registry ──────────────────────────────────────────────────────────────
    def _registry(self):
        keyed = keyed_providers()
        providers = {pid: {"id": pid, "label": p["label"], "kind": p["kind"],
                           "requires_key": p["requires_key"], "key_present": keyed[pid],
                           "proxied": True}
                     for pid, p in PROVIDERS.items()}
        return {"providers": providers, "defaults": DEFAULTS}

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
        prov = PROVIDERS.get(pid or "")
        if not prov:
            return self._json({"error": f"unknown provider '{pid}'", "known": list(PROVIDERS)}, 400)
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

    # ── static files with per-app SPA fallback ────────────────────────────────
    def _resolve(self, path):
        """Map a URL path to a file under ROOT. Returns (Path|None, is_spa_fallback)."""
        rel = urllib.parse.unquote(path).lstrip("/")
        target = (ROOT / rel).resolve()
        root_r = ROOT.resolve()
        if not (target == root_r or str(target).startswith(str(root_r) + os.sep)):
            return None, False                       # traversal blocked
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
        self._bytes(data, MIME_TYPES.get(target.suffix.lower(), "application/octet-stream"))

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


def main():
    global ROOT
    ap = argparse.ArgumentParser(description="NeXuS portable HTTPS web server")
    ap.add_argument("--root", default=str(BASE_DIR / "dist"),
                    help="web root directory to serve (default: ./dist)")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--cert", default=None, help="TLS cert PEM (default: ./cert.pem)")
    ap.add_argument("--key",  default=None, help="TLS key PEM (default: ./key.pem)")
    args = ap.parse_args()

    ROOT = Path(args.root).resolve()
    if not ROOT.is_dir():
        sys.exit(f"❌ web root not found: {ROOT}")

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
    log("🔑 provider keys: " + ", ".join(f"{k}={'yes' if v else 'no'}" for k, v in keyed.items()))
    log("🛑 Ctrl+C to stop")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log("🛑 shutting down")
        httpd.shutdown()


if __name__ == "__main__":
    main()
