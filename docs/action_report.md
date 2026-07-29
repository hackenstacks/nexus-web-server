# nexus-web-server - Action Report

**Project:** /home/user/Projects/nexus-web-server
**Created:** 2026-07-28

---


## NeXuS Web Server v1 — portable HTTPS host + shared proxy (2026-07-28 18:31)

Status: ✅ TESTED

What: New standalone project — a one-file pure-Python-stdlib HTTPS server that serves any web-root dir AND provides one shared /api/* key-injecting proxy. Own Fossil repo (~/museum/nexus-web-server.fossil, checkout ~/Projects/nexus-web-server, commit 7a158386c2).

Why: Every char-gen fork inherited the Google AI-Studio 'process.env.API_KEY' single-key pattern (keys in the browser, one provider, nothing proxied). Anon wanted ONE sovereign entry point (nexus.env), multi-endpoint support, and a server 'others can use' — portable/versatile, Sane·Simple·Secure·Sustainable. Node/npm retired for production serving.

How: Two cleanly-split jobs — (A) STATIC: serve --root; per-app SPA fallback (nearest index.html up the tree); landing index lists apps when root holds several. (B) PROXY: keys resolved by name from ~/.config/nexus/secrets/nexus.env, injected server-side so no browser app holds an sk_. Routes: /api/health, /api/providers (sanitized registry, keyed vs keyless classes), /api/models/{image,text} keyless passthrough, /api/pollinations/image (streamed, key injected), /api/llm (body-style {provider,...}), /api/llm/{provider}/v1/chat/completions (VANILLA OpenAI body — for OpenCharacters & any custom-endpoint client). Providers: pollinations/openai/mistral/groq/openrouter (key-required, proxied) + aihorde/ollama/aichat (keyless). Add a provider = one line in PROVIDERS.

Files: nexus_web_server.py (~300 lines, stdlib only), README.md. Fossil ignore-glob excludes *.pem/nexus.env/*.log/__pycache__.

Testing: VERIFIED — SPA at / (AI Nexus); /api/health 200; /api/providers correct (pollinations/aichat/ollama/aihorde ready); image proxy 200 JPEG 256x256; /api/models/image 68 models; body- and path-style /api/llm both returned live Pollinations text ('sovereign'/'portable'); multi-app root: landing lists /chargen//oc/, per-app serving + per-app SPA fallback confirmed. One transient upstream 502 (Pollinations read-timeout) recovered on retry.

Dependencies: python3 (3.14 here; needs 3.8+ for walrus); cert.pem/key.pem (self-signed ok); ~/.config/nexus/secrets/nexus.env for any key-required provider.

---


## Universal API server: dynamic providers + per-provider live models + secure .local.env (2026-07-28 21:52)

Status: ✅ TESTED (server); 🔵 in-progress (browser UI B)

What: Grew NeXuS Web Server into a universal API server. Env-declared providers (PROVIDER_<ID>_BASE_URL/_API_KEY/_KIND/_LABEL) register on the fly; added /api/models/provider/{id} for live per-provider model lists; layered secure .local.env (precedence, never-served, auto-.gitignore, chmod-600 warn); CSP worker-src blob: fix.

Why: One sovereign egress for ALL providers, keys server-side, and 'drop a provider in the env file' — no code. Feeds the app's fresh-models + provider-dropdown goal (B).

How: discover_providers() merges built-ins + env scan; _provider_models() GETs {base_url}/models with injected key and normalizes ids. load_secret() precedence process-env>.local.env>nexus.env>legacy. is_secret_path() denylist for static. ensure_gitignore() append-only on startup.

Files: nexus_web_server.py (EDITED, models endpoint + CSP UNCOMMITTED; .local.env + dynamic committed 2783886d0b), .local.env.example, docs/nexus-web-server_HELP.md (100% requirements), docs/action_report.md.

Testing: 12 providers READY after loading Anon's keys; live /models mistral 60 / google 57 / cerebras 3 / deepseek 2 / pollinations 157; .local.env override + /.local.env 404 + auto-.gitignore verified; dynamic myllm/opengw earlier.

Dependencies: python3>=3.8 stdlib only; cert/key; nexus.env/.local.env for keyed providers.

---


## Added /api/models/provider/{id} + HELP route (2026-07-28 22:29)

Status: ✅ TESTED

What: New GET /api/models/provider/{id} returns live /models for ANY provider (normalized ids), powering the app's server-driven model dropdowns. HELP routes table updated.

Why: 'Fresh API models' per provider, not just Pollinations.

How: _provider_models() looks up base_url+key, GETs {base_url}/models, normalizes {data:[{id}]}/bare-list. Pollinations delegates to /text/models.

Files: nexus_web_server.py (UNCOMMITTED), docs/nexus-web-server_HELP.md.

Testing: mistral 60, groq 15, google 57, cerebras 3, deepseek 2, pollinations 157.

---


## Multi-app web root: chargen + foundry + oc under ~/nexus-web/ (2026-07-29 00:25)

**Status:** ✅ TESTED — all three apps serve 200, proxy 13 providers ready

**What:** Extended the NeXuS Web Server to serve multiple apps from one HTTPS port via a `~/nexus-web/` root with symlinked app sub-directories.

**Why:** Single port, single cert, single key injection point — add an app with one symlink, no config or server restart needed.

**How:**
- Created `~/nexus-web/` with three symlinks: `chargen → adv-ai-nexus/.../dist`, `foundry → NeXuS-AI-Foundry-v-9 - 1/dist`, `oc → OpenCharacters-0.0.5/`
- Fixed server traversal check: `_resolve()` was calling `.resolve()` (follows symlinks) BEFORE the ROOT containment check, so symlinks outside ROOT were blocked. Fix: use `os.path.normpath` for containment (catches `../` traversal without following symlinks), then `.resolve()` after for actual file ops.
- Added `base: './'` to both vite configs (foundry + chargen) so asset URLs are relative and work from any subpath.
- Wired NeXuS-AI-Foundry-v-9 with `nexusProxy.ts` interceptor: copied to `services/`, installed in `index.tsx` before React mount.
- Updated `nexus-api-proxy.sh` ROOT from chargen/dist to `$HOME/nexus-web`.

**Files:**
- `~/Projects/nexus-web-server/nexus_web_server.py` — symlink fix in `_resolve()` (fossil ea1509a9)
- `~/Projects/NeXuS-AI-Foundry-v-9 - 1/services/nexusProxy.ts` — new
- `~/Projects/NeXuS-AI-Foundry-v-9 - 1/index.tsx` — installNexusProxy() first
- `~/Projects/NeXuS-AI-Foundry-v-9 - 1/vite.config.ts` — base: './'
- `~/Projects/adv-ai-nexus/.../vite.config.ts` — base: './' (fossil 7cdb1eed)
- `~/scripts/nexus-api-proxy.sh` — ROOT=~/nexus-web
- `~/nexus-web/` — new root dir with chargen/, foundry/, oc/ symlinks

**Testing:** curl confirmed 200 for /, /chargen/, /foundry/, /oc/play.html, /api/health. 13 providers ready.

**URLs:**
- https://localhost:8443/ — landing page (lists all apps)
- https://localhost:8443/chargen/ — char-gen (A.I.M.E home)
- https://localhost:8443/foundry/ — NeXuS-AI-Foundry (de-googled, proxy-wired)
- https://localhost:8443/oc/play.html — OpenCharacters

---


## Foundry Settings: proxy-driven provider dropdowns (2026-07-29 00:55)

**Status:** ✅ TESTED — builds clean, served at /foundry/, GitHub pushed

**What:** NeXuS-AI-Foundry Settings page now auto-populates provider dropdowns from the proxy, with a Custom fallback for any unlisted endpoint.

**Why:** Unified the foundry with the same sovereign key model as char-gen — no API keys in the browser, no hardcoded provider lists.

**How:**
- On mount: GET /api/providers → if online, populate dropdown with ✓/○ providers; if offline, show badge + custom fields
- Per feature: select proxy provider → endpoint auto-set to /api/llm/{id}/v1/chat/completions, models auto-fetched from /api/models/provider/{id}, key fields hidden, info line shows wired endpoint
- Custom / Unlisted option: shows endpoint text input + API key input (manual entry, works without proxy)
- Nothing selected / proxy offline: custom fields always visible so the app works standalone
- Proxy status badge in section header: ⚡ proxy live / ○ proxy offline / … connecting
- selectedProvider state initialised from saved endpoint URLs on load (regex /api/llm/{id}/ → detects proxy providers, else → 'custom')

**Files:**
- ~/Projects/NeXuS-AI-Foundry-v-9 - 1/features/Settings.tsx
**Fossil:** 9f3c8bd8 | **GitHub:** hackenstacks/nexus-ai-foundry (private, main branch)

---


## Wire script + Manager UI dashboard (2026-07-29 01:12)

**Status:** ✅ TESTED — /api/apps lists 5 apps, /manager/ serves 200, wire script executable

**What:** Three new components that bring all proxy-managed apps together under one control surface.

**nexus-proxy-wire.sh** (~120 lines, ~/scripts/):
- Detects app type: vite+react (has vite.config.ts) vs static HTML vs unknown
- Vite+React: copies nexusProxy.ts, patches index.tsx (installNexusProxy before React), adds base: './' to vite.config, npm installs if needed, builds, symlinks dist/ to ~/nexus-web/<name>/
- Static: symlinks dir directly
- Idempotent — re-run safe, skips already-done steps
- Python used for patching (regex insert, not fragile awk/sed)

**nexus_web_server.py additions:**
- GET /api/apps — lists ROOT subdirs: {name, path, symlink, has_index, url}
- POST /api/wire — validates path (absolute, must be dir) + name (alphanum+dash), runs wire script, returns {success, output, returncode}; 180s timeout; input sanitized (no shell injection)

**~/nexus-web/manager/index.html** (pure HTML/CSS/JS, no build):
- Dark NeXuS theme, sticky header with proxy status badge (live/offline/connecting)
- Providers section: card grid from /api/providers showing ✓ ready / ○ no key
- Apps section: card grid from /api/apps with name, url, path, live status, Open ↗ link; filters out manager itself
- Wire panel: path + name inputs, Wire button → POST /api/wire → terminal-style console output; auto-refresh apps list on success
- Auto-refreshes every 30s; strips ANSI codes from wire output

**Files:**
- ~/scripts/nexus-proxy-wire.sh (new, chmod +x)
- ~/Projects/nexus-web-server/nexus_web_server.py (fossil ed15fd48)
- ~/nexus-web/manager/index.html (new)

**URLs:**
- https://localhost:8443/manager/ — the dashboard
- https://localhost:8443/api/apps — app list JSON
- POST https://localhost:8443/api/wire — trigger wire script

---


## Session wrap: ai-forge Code Review mode + all apps live (2026-07-29 02:10)

**Status:** ✅ TESTED (proxy/manager/apps) | 🔵 DESIGNED (forge code review — built, needs Mistral test)

**What:** Full proxy layer operational. 5 apps at :8443. ai-forge rebuilt with proxy settings + structured Code Review mode.

**Files changed this session:**
- ~/Projects/nexus-web-server/nexus_web_server.py
- ~/nexus-web/manager/index.html
- ~/scripts/nexus-proxy-wire.sh
- ~/Projects/ai-forge/components/{CodeInput,ReviewOutput,SettingsModal,ChatView,Header}.tsx
- ~/Projects/ai-forge/services/llmService.ts
- ~/Projects/ai-forge/App.tsx
- ~/Projects/NeXuS-AI-Foundry-v-9 - 1/features/Settings.tsx

**Tomorrow:** Test Code Review with Mistral, confirm workspace injection, archive beta dir

---

