// /api/claude.js — governed streaming gateway to the Anthropic Messages API.
//
// The real ANTHROPIC_API_KEY lives only here (env var) and never reaches a
// browser. Two kinds of caller:
//   1. First-party owner app  — no Authorization header → passes through as
//      before (nothing changes for the workbench itself).
//   2. Proxy-key holder       — sends "Authorization: Bearer <proxy JWT>" plus
//      an "x-device-fp" fingerprint. The gateway verifies the JWT, checks the
//      device is approved (and the key not revoked) in KV, forwards the call,
//      and meters the tokens used — all without exposing the real key.
//
// No npm dependencies: global fetch + Node crypto (via ./_gov).

const crypto = require("crypto");
let G = null; try { G = require("./_gov"); } catch (e) { G = null; }

function errJSON(res, code, obj) {
  res.status(code);
  res.setHeader("content-type", "application/json");
  res.send(JSON.stringify(obj));
}
function deviceFp(req) {
  const h = req.headers["x-device-fp"];
  if (h) return String(h).slice(0, 64);
  const ua = req.headers["user-agent"] || "";
  const ip = (req.headers["x-forwarded-for"] || "").split(",")[0] || "";
  return "srv_" + crypto.createHash("sha256").update(ua + "|" + ip).digest("hex").slice(0, 20);
}

module.exports = async (req, res) => {
  if (req.method !== "POST") return errJSON(res, 405, { error: "POST only" });

  const key = process.env.ANTHROPIC_API_KEY;
  if (!key) return errJSON(res, 200, { error: "ANTHROPIC_API_KEY is not set on this deployment. Add it in Vercel → Settings → Environment Variables, then redeploy." });

  const SECRET = process.env.PROXY_JWT_SECRET || "";
  const token = G ? G.bearer(req) : "";
  const governed = !!(token && SECRET && G);   // a proxy key was presented and the server can check it

  // ---- governance checks for proxy-key holders ----
  let rec = null, fp = null, kvOn = false;
  if (governed) {
    const claims = G.verifyJWT(token, SECRET);
    if (!claims || claims.aud !== "proxy") return errJSON(res, 401, { error: "invalid_or_expired_key", message: "This access key is invalid or has expired. Ask the owner for a new one." });
    fp = deviceFp(req);
    kvOn = G.kvConfigured();
    if (kvOn) {
      try {
        rec = await G.getKey(claims.jti);
        if (!rec) return errJSON(res, 403, { error: "revoked", message: "This key is not recognised (revoked or removed)." });
        if (rec.revoked) return errJSON(res, 403, { error: "revoked", message: "This access key has been revoked by the owner." });
        const dev = rec.devices[fp];
        if (!dev) {
          rec.devices[fp] = { status: "pending", firstSeen: Date.now(), lastSeen: Date.now(), ua: (req.headers["user-agent"] || "").slice(0, 120) };
          await G.putKey(rec);
          return errJSON(res, 403, { error: "device_pending", message: "New device detected. The owner must approve this device before it can use the service." });
        }
        if (dev.status !== "approved") {
          return errJSON(res, 403, { error: "device_" + dev.status, message: dev.status === "denied" ? "This device was denied by the owner." : "This device is awaiting owner approval." });
        }
      } catch (e) {
        return errJSON(res, 200, { error: "governance_unavailable", message: "Access store unreachable: " + (e.message || e) });
      }
    }
    // If KV is off but the JWT is valid, we allow (stateless key) — no metering.
  }

  let body = req.body;
  if (typeof body === "string") { try { body = JSON.parse(body); } catch { body = {}; } }
  body = body || {};

  try {
    const upstream = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "content-type": "application/json", "x-api-key": key, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model: body.model, max_tokens: body.max_tokens, system: body.system, messages: body.messages, stream: true }),
    });

    if (!upstream.ok || !upstream.body) {
      const t = await upstream.text();
      res.status(upstream.status || 502);
      res.setHeader("content-type", "application/json");
      res.send(t || JSON.stringify({ error: "upstream error " + upstream.status }));
      return;
    }

    res.status(200);
    res.setHeader("content-type", "text/event-stream; charset=utf-8");
    res.setHeader("cache-control", "no-cache, no-transform");
    res.setHeader("connection", "keep-alive");
    if (typeof res.flushHeaders === "function") res.flushHeaders();

    const reader = upstream.body.getReader();
    const dec = new TextDecoder();
    let scan = "", inTok = 0, outTok = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      res.write(Buffer.from(value));
      if (typeof res.flush === "function") res.flush();
      if (governed && kvOn) {                 // meter tokens by scanning a copy of the stream
        scan += dec.decode(value, { stream: true });
        let nl;
        while ((nl = scan.indexOf("\n")) >= 0) {
          const line = scan.slice(0, nl).trim(); scan = scan.slice(nl + 1);
          if (line.indexOf("data:") !== 0) continue;
          const d = line.slice(5).trim(); if (!d || d === "[DONE]") continue;
          let ev; try { ev = JSON.parse(d); } catch (e) { continue; }
          if (ev.type === "message_start" && ev.message && ev.message.usage) inTok = ev.message.usage.input_tokens || inTok;
          else if (ev.type === "message_delta" && ev.usage && ev.usage.output_tokens != null) outTok = ev.usage.output_tokens;
        }
      }
    }
    res.end();

    // Persist usage for this proxy key (best-effort; never blocks the response).
    if (governed && kvOn && rec) {
      try {
        rec.usage = rec.usage || { calls: 0, inTok: 0, outTok: 0 };
        rec.usage.calls += 1; rec.usage.inTok += inTok; rec.usage.outTok += outTok;
        if (rec.devices[fp]) rec.devices[fp].lastSeen = Date.now();
        await G.putKey(rec);
      } catch (e) {}
    }
  } catch (err) {
    const msg = "Proxy failed: " + (err && err.message ? err.message : String(err));
    if (!res.headersSent) { res.status(200); res.setHeader("content-type", "application/json"); res.send(JSON.stringify({ error: msg })); }
    else { try { res.end(); } catch (e) {} }
  }
};
