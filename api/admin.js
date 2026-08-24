// /api/admin.js — owner console for API-key governance.
// The owner logs in with ADMIN_PASSWORD and receives a short-lived admin JWT.
// With that token the owner mints proxy keys, approves/denies devices, revokes
// keys, and reads per-key usage. State lives in KV (Upstash REST). No real
// Anthropic key is ever handled here.
//
// Env: ADMIN_PASSWORD, PROXY_JWT_SECRET, KV_REST_API_URL, KV_REST_API_TOKEN.

const G = require("./_gov");
const crypto = require("crypto");

function json(res, code, obj) {
  res.status(code);
  res.setHeader("content-type", "application/json");
  res.send(JSON.stringify(obj));
}
function newJti() { return crypto.randomBytes(9).toString("hex"); }

module.exports = async (req, res) => {
  if (req.method !== "POST") return json(res, 405, { error: "POST only" });

  const SECRET = process.env.PROXY_JWT_SECRET || "";
  const PW = process.env.ADMIN_PASSWORD || "";
  const configured = !!(SECRET && PW);
  const kv = G.kvConfigured();
  const body = G.readBody(req);
  const action = body.action || "";

  // The dashboard calls this first: if the server isn't set up, it drops to the
  // in-browser demo mode instead of erroring.
  if (action === "config") return json(res, 200, { configured, kv });

  if (!configured) {
    return json(res, 200, { configured: false, kv, error: "Server governance not configured. Set ADMIN_PASSWORD and PROXY_JWT_SECRET (and add Vercel KV) to enable server-enforced mode." });
  }

  // ---- public: a teammate requests access (no admin token) ----
  // Creates a pending proxy key bound to their device. It does nothing until
  // the owner approves the device in the console. Returns the token so the
  // requester can poll and, once approved, use it.
  if (action === "request") {
    if (!kv) return json(res, 200, { kv: false, error: "Access store not attached yet." });
    const person = String(body.name || "").trim().slice(0, 60) || "Guest";
    const fp = String(body.fp || "").slice(0, 64);
    if (!fp) return json(res, 400, { error: "missing device fingerprint" });
    const days = 30;
    const jti = newJti();
    const token = G.signJWT({ aud: "proxy", sub: person, jti }, SECRET, days * 86400);
    const rec = { jti, person, createdAt: Date.now(), expEpoch: Math.floor(Date.now() / 1000) + days * 86400, revoked: false, selfService: true,
      devices: { [fp]: { status: "pending", firstSeen: Date.now(), lastSeen: Date.now(), ua: (req.headers["user-agent"] || "").slice(0, 120) } },
      usage: { calls: 0, inTok: 0, outTok: 0 } };
    await G.putKey(rec);
    return json(res, 200, { ok: true, jti, token, status: "pending", person });
  }

  // ---- public: a requester polls their approval status ----
  if (action === "mystatus") {
    if (!kv) return json(res, 200, { kv: false, status: "unknown" });
    const rec = await G.getKey(String(body.jti || ""));
    if (!rec) return json(res, 200, { status: "unknown" });
    const dev = rec.devices[String(body.fp || "")];
    const status = rec.revoked ? "revoked" : (dev ? dev.status : "pending");
    return json(res, 200, { status, person: rec.person, usage: rec.usage });
  }

  // ---- login: password -> admin session token ----
  if (action === "login") {
    const ok = typeof body.password === "string" &&
      body.password.length === PW.length &&
      crypto.timingSafeEqual(Buffer.from(body.password), Buffer.from(PW));
    if (!ok) return json(res, 401, { error: "Wrong password." });
    const token = G.signJWT({ aud: "admin" }, SECRET, 60 * 60 * 8); // 8h
    return json(res, 200, { ok: true, token, kv });
  }

  // ---- everything else requires a valid admin token ----
  const admin = G.verifyJWT(G.bearer(req), SECRET);
  if (!admin || admin.aud !== "admin") return json(res, 401, { error: "Not authorised — log in again." });
  if (!kv) return json(res, 200, { kv: false, error: "Vercel KV is not attached, so approvals and usage cannot persist. Attach a KV store to enable this." });

  try {
    if (action === "list") {
      const keys = await G.listKeys();
      return json(res, 200, { kv: true, keys });
    }

    if (action === "mint") {
      const person = String(body.person || "").trim() || "Unnamed";
      const days = Math.max(1, Math.min(365, parseInt(body.days, 10) || 30));
      const jti = newJti();
      const token = G.signJWT({ aud: "proxy", sub: person, jti }, SECRET, days * 86400);
      const rec = { jti, person, createdAt: Date.now(), expEpoch: Math.floor(Date.now() / 1000) + days * 86400, revoked: false, devices: {}, usage: { calls: 0, inTok: 0, outTok: 0 } };
      await G.putKey(rec);
      // The token is returned ONCE — the owner copies it to the teammate.
      return json(res, 200, { ok: true, jti, person, days, token });
    }

    if (action === "approve" || action === "deny") {
      const rec = await G.getKey(body.jti);
      if (!rec) return json(res, 404, { error: "Key not found." });
      const fp = String(body.fp || "");
      if (!rec.devices[fp]) rec.devices[fp] = { firstSeen: Date.now() };
      rec.devices[fp].status = action === "approve" ? "approved" : "denied";
      rec.devices[fp].decidedAt = Date.now();
      await G.putKey(rec);
      return json(res, 200, { ok: true, keys: await G.listKeys() });
    }

    if (action === "revoke" || action === "unrevoke") {
      const rec = await G.getKey(body.jti);
      if (!rec) return json(res, 404, { error: "Key not found." });
      rec.revoked = action === "revoke";
      await G.putKey(rec);
      return json(res, 200, { ok: true, keys: await G.listKeys() });
    }

    return json(res, 400, { error: "Unknown action: " + action });
  } catch (err) {
    return json(res, 200, { error: "Admin op failed: " + (err && err.message ? err.message : String(err)) });
  }
};
