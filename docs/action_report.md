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

