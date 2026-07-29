# NeXuS Web Server

A **portable, one-file HTTPS host + universal AI API proxy** — pure Python stdlib, no pip, no npm, no node.

**Sane · Simple · Secure · Sustainable**

---

## What it does

Two cleanly separated jobs in one ~600-line Python file:

**A) Static host** — serves any directory over HTTPS. Drop an app's `dist/` folder in and it's served. Multi-app roots, per-app SPA fallback, auto-generated landing page.

**B) AI proxy** — one shared `/api/*` backend that injects your API keys **server-side** from a local secrets file. Every app under the root shares it. The browser never sees an `sk_` key.

```
Browser  →  /api/llm/mistral/v1/chat/completions
                    ↓
           nexus_web_server.py
           (injects Authorization: Bearer sk_… from nexus.env)
                    ↓
           api.mistral.ai
```

> **Rule Zero:** No API key ever touches the browser, the bundle, or the logs.

---

## Requirements

- Python ≥ 3.8 (stdlib only — nothing to install)
- `cert.pem` + `key.pem` (self-signed is fine)
- Keys file: `~/.config/nexus/secrets/nexus.env` or a `.local.env` beside your app

---

## Quick start

```bash
# 1. Clone
git clone https://github.com/hackenstacks/nexus-web-server
cd nexus-web-server

# 2. Generate a self-signed cert (one time)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem \
  -days 365 -nodes -subj "/CN=localhost"

# 3. Add your keys
cp .local.env.example .local.env
$EDITOR .local.env        # add POLLINATIONS_API_KEY, MISTRAL_API_KEY, etc.
chmod 600 .local.env

# 4. Run
python3 nexus_web_server.py --root ./your-app/dist --port 8443 \
  --cert cert.pem --key key.pem
```

Open `https://localhost:8443` — accept the self-signed cert once.

---

## Multi-app setup

Serve several apps from one port — no restart needed to add one:

```bash
mkdir ~/nexus-web
ln -sfn ~/your-app/dist          ~/nexus-web/myapp
ln -sfn ~/another-app/dist       ~/nexus-web/another
ln -sfn ~/static-site            ~/nexus-web/docs

python3 nexus_web_server.py --root ~/nexus-web --port 8443 \
  --cert cert.pem --key key.pem
```

Landing page at `/` lists all apps. Each at `/myapp/`, `/another/`, `/docs/`.

**Add an app without restarting:**
```bash
ln -sfn ~/new-app/dist ~/nexus-web/new-app
# live immediately
```

---

## Wiring a Vite+React app to the proxy

Use the included wire script — it auto-detects app type, patches the entry file, sets the relative base path, builds, and symlinks:

```bash
# Wire any Vite+React app (detects type, patches, builds, links):
./nexus-proxy-wire.sh /path/to/your-app [app-name]

# Or from the Manager UI at https://localhost:8443/manager/
```

What it does:
1. Copies `nexusProxy.ts` fetch-interceptor into the app's `services/`
2. Installs `installNexusProxy()` at the top of the entry file
3. Adds `base: './'` to `vite.config.ts` (required for subpath serving)
4. Runs `npm install` + `npm run build`
5. Symlinks `dist/` into the web root

For static HTML apps it just symlinks the directory directly.

---

## Manager UI

A built-in dashboard at `https://localhost:8443/manager/`:

- **Provider cards** — live status of all configured providers (keyed / free / no key)
- **App cards** — all served apps with Open ↗ links
- **Wire panel** — paste a directory path, hit Wire, watch the console output

To enable it, create the manager directory:
```bash
mkdir -p ~/nexus-web/manager
cp manager/index.html ~/nexus-web/manager/
```

---

## API routes

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/api/health` | Liveness + provider key status |
| GET | `/api/providers` | Provider registry (no secrets — booleans only) |
| GET | `/api/models/text` | Pollinations text model list |
| GET | `/api/models/image` | Pollinations image model list |
| GET | `/api/models/provider/{id}` | Live model list for any provider |
| GET | `/api/pollinations/image?prompt=…` | Image proxy — key injected, streams JPEG |
| GET | `/api/apps` | Lists sub-apps in the web root |
| POST | `/api/llm` | Chat proxy — body: `{ "provider": "…", …openai }` |
| POST | `/api/llm/{provider}/v1/chat/completions` | Vanilla OpenAI body (provider in URL) |
| POST | `/api/wire` | Run nexus-proxy-wire.sh on a given directory |
| `*` | `/*` | Static file under root (SPA fallback) |

---

## Adding providers

**No code changes needed.** Add any OpenAI-compatible provider via `.local.env`:

```ini
# .local.env
PROVIDER_DEEPSEEK_BASE_URL=https://api.deepseek.com/v1
PROVIDER_DEEPSEEK_API_KEY=sk-your-key
PROVIDER_DEEPSEEK_KIND=chat
PROVIDER_DEEPSEEK_LABEL=DeepSeek

PROVIDER_MYTOOL_BASE_URL=http://localhost:8000/v1
# no API_KEY = keyless
PROVIDER_MYTOOL_LABEL=My Local Tool
```

The provider appears instantly in `/api/providers` and is callable at `/api/llm/deepseek/…` — no restart needed.

---

## Built-in providers

| ID | Label | Kind | Key required |
|----|-------|------|-------------|
| `pollinations` | Pollinations.ai | chat + image | yes |
| `openai` | OpenAI | chat + image | yes |
| `mistral` | Mistral | chat | yes |
| `groq` | Groq | chat | yes |
| `openrouter` | OpenRouter | chat | yes |
| `aihorde` | AI Horde | chat + image | no (keyless) |
| `ollama` | Ollama (local) | chat | no |
| `aichat` | aichat (local) | chat | no |

---

## Secrets — how they're managed

Keys resolve in this order (first wins):

```
process env  →  .local.env (project)  →  ~/.config/nexus/secrets/nexus.env  →  legacy pollinations.key
```

The server protects secrets three ways:
- **Never served** — the static handler 404s any `.env`/`.key`/`.pem`/dotfile, even inside the web root
- **Never git-committed** — on startup, auto-appends secret patterns to `.gitignore` (idempotent)
- **Never logged or returned** — `/api/providers` exposes only `key_present: true/false`

```bash
# Global keys file
mkdir -p ~/.config/nexus/secrets
cat > ~/.config/nexus/secrets/nexus.env << 'EOF'
POLLINATIONS_API_KEY=sk_…
MISTRAL_API_KEY=…
GROQ_API_KEY=gsk_…
EOF
chmod 600 ~/.config/nexus/secrets/nexus.env
```

---

## Using from any OpenAI-compatible client

Point the client's custom endpoint at this proxy — it will receive your keyed request server-side:

```
https://localhost:8443/api/llm/pollinations/v1/chat/completions
https://localhost:8443/api/llm/mistral/v1/chat/completions
https://localhost:8443/api/llm/groq/v1/chat/completions
```

Leave the API key field blank in the client — the proxy handles it.

---

## Wiring your own app (manual)

If `nexus-proxy-wire.sh` doesn't cover your app type:

1. Copy `nexusProxy.ts` into your app's `services/` directory
2. Add to your entry file (before any other imports):
   ```typescript
   import { installNexusProxy } from './services/nexusProxy';
   installNexusProxy();
   ```
3. Add `base: './'` to your `vite.config.ts` (required for subpath serving)
4. Build and symlink `dist/` into the web root

The fetch interceptor rewrites calls to known cloud hosts (`gen.pollinations.ai`, `api.mistral.ai`, `api.groq.com`, etc.) to same-origin `/api/llm/<provider>` and strips the `Authorization` header. Transparent to the app — same method, same body, same streaming.

---

## Full documentation

See [`docs/nexus-web-server_HELP.md`](docs/nexus-web-server_HELP.md) for the complete reference including all CLI flags, troubleshooting, self-test commands, and security model.

---

*Part of the NeXuS sovereign computing stack — [github.com/hackenstacks](https://github.com/hackenstacks)*
