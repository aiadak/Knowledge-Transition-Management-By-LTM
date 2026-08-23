# API Key Governance — setup

The workbench ships with a real, server-enforced proxy-key gateway. Until you
configure it, the **API Key Governance** agent runs in **in-browser demo mode**
(fully clickable — mint keys, approve/deny devices, meter usage — but state
lives in the browser). Do the four steps below to make it **server-enforced**:
the gateway then verifies every proxy key + device before forwarding, and your
real Anthropic key never leaves the server.

Nothing here changes how the workbench itself calls the model — the first-party
app sends no proxy key and keeps working exactly as before.

## What it does (server mode)

- You (owner) sign in with a password.
- You mint a **JWT proxy key** per person, with an expiry.
- When that person's device first calls the API, the gateway sees an **unknown
  device and blocks it (403)** — it appears in your dashboard as *pending*.
- You click **Allow**; that device can now use the service. You can **Deny** or
  **Revoke** at any time.
- Every call is **metered per key** (calls + input/output tokens).
- Your real `ANTHROPIC_API_KEY` is only ever used server-side, after the checks.

## Files (already in this deploy)

- `api/claude.js` — the governed streaming gateway (verifies key + device, meters).
- `api/admin.js` — owner console API (login, mint, approve/deny, revoke, list).
- `api/_gov.js`  — shared JWT (HMAC-SHA256) + KV helpers. No npm dependencies.

## Step 1 — Add a Vercel KV (Upstash Redis) store

Vercel dashboard → your project → **Storage** → **Create Database** → **KV**
(Upstash Redis). Connect it to the project. This automatically adds the env
vars `KV_REST_API_URL` and `KV_REST_API_TOKEN`. (A free Upstash database used
directly works too — just set those two vars yourself.)

## Step 2 — Set the two secrets

Project → **Settings → Environment Variables**, add:

- `ADMIN_PASSWORD` — the owner password you'll sign in with.
- `PROXY_JWT_SECRET` — any long random string (used to sign/verify keys). E.g.
  run `openssl rand -hex 32` and paste the result.

(`ANTHROPIC_API_KEY` should already be set from the original deploy.)

## Step 3 — Redeploy

Trigger a redeploy so the new env vars and functions take effect.

## Step 4 — Use it

Open the **API Key Governance** agent. It should now show **SERVER-ENFORCED ·
KV ON**. Sign in with `ADMIN_PASSWORD`, mint a key for someone, and share it.
Their first call is blocked until you Allow their device. Use **Test as
teammate** to demo the block → allow → metered flow end-to-end.

## How a teammate uses their key

They send it as a bearer token to your deployment's `/api/claude`, with a
device fingerprint header, e.g.:

```
curl -X POST https://YOUR-APP.vercel.app/api/claude \
  -H "authorization: Bearer <THE_PROXY_KEY>" \
  -H "x-device-fp: <stable-device-id>" \
  -H "content-type: application/json" \
  -d '{"model":"claude-haiku-4-5-20251001","max_tokens":64,"messages":[{"role":"user","content":"hi"}]}'
```

Or inject the proxy key as an environment variable in their tool/VDI session —
the real Anthropic key is never distributed. First call → 403 "device pending"
until you approve it in the dashboard.

## Notes

- The proxy key is a JWT — it carries the person, a unique id, and an expiry,
  signed with `PROXY_JWT_SECRET`. Revocation and per-device approval are checked
  against KV on every request, so revoking is immediate.
- Token metering scans the streamed response for usage and writes it to the key
  record — visible per person in the dashboard.
- Device fingerprint: the client sends `x-device-fp`; if absent, the server
  derives a stable id from the user-agent + IP.
