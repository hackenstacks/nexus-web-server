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

