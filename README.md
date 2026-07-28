# NeXuS Web Server

A **portable, versatile HTTPS host** in one pure-Python-stdlib file — no node, no npm, no pip.
Built to the NeXuS ethos: **Sane · Simple · Secure · Sustainable**.

It does two things, and keeps them cleanly separate:

- **A) STATIC** — serves a web *root* directory. Drop an app folder in; it's served.
  Per-app SPA fallback; a landing index when the root holds several apps.
- **B) PROXY** — one shared `/api/*` backend that injects API keys **server-side** from
  `~/.config/nexus/secrets/nexus.env`, so **no app in the browser ever holds an `sk_` key**
  (NeXuS Rule Zero). Every app under the root shares this one key-injecting engine.

> The whole idea: *files are swappable; the proxy is the valuable shared engine.*
> To host your own app, put it under the root and point its `fetch()` calls at `/api/*`.

## Run

```bash
python3 nexus_web_server.py                       # root = ./dist  (single app at /)
python3 nexus_web_server.py --root ~/nexus-web    # multi-app:  /chargen/  /oc/  ...
python3 nexus_web_server.py --root . --port 8443 --cert cert.pem --key key.pem
```

Requires `cert.pem` / `key.pem` (self-signed is fine) — pass `--cert`/`--key` or place them
next to the script.

## Routes

| Method | Route | Purpose |
|--------|-------|---------|
| GET | `/api/health` | liveness + which providers have keys |
| GET | `/api/providers` | sanitized provider registry (**no secrets**) |
| GET | `/api/models/image` · `/api/models/text` | keyless Pollinations model lists (passthrough) |
| GET | `/api/pollinations/image?prompt=&model=&width=&height=` | image proxy, key injected, streams JPEG |
| POST | `/api/llm` | OpenAI-compatible text proxy — body `{ "provider": "...", ...openai }` |
| POST | `/api/llm/{provider}/v1/chat/completions` | same, **vanilla OpenAI body** (provider in URL) — for OpenCharacters & any "custom endpoint" client |
| GET | `*` | static file under root (SPA fallback) |

## Providers

Declared in one registry in the script; keys resolved by name from `nexus.env`.
Keyless: `aihorde`, `ollama`, `aichat`. Key-required (proxied): `pollinations`, `openai`,
`mistral`, `groq`, `openrouter`. Add your own by adding a line to `PROVIDERS`.

## Using it from another app (e.g. OpenCharacters)

OpenCharacters supports custom OpenAI-compatible endpoints. Point one at this proxy:

```json5
{ name: "gpt-5.4", endpointUrl: "https://localhost:8443/api/llm/pollinations/v1/chat/completions",
  apiKey: "unused", maxSequenceLength: 8192, type: "chat-completion" }
```

The browser sends no key; the server injects it from `nexus.env`.

## Secrets

Keys live **only** in `~/.config/nexus/secrets/nexus.env` (chmod 600, gitignored), e.g.:

```
POLLINATIONS_API_KEY=sk_...
OPENAI_API_KEY=sk_...
```

Never hardcode a key in an app bundle, a character card, or this repo.
