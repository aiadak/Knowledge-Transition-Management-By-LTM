// /api/_gov.js — shared governance helpers for the API-key gateway.
// Underscore-prefixed, so Vercel does NOT expose it as a route.
// No npm dependencies: JWT via Node's crypto, KV via the Upstash REST API
// (the same env vars Vercel KV provisions: KV_REST_API_URL / KV_REST_API_TOKEN).

const crypto = require("crypto");

/* ---------------- JWT (HS256) ---------------- */
function b64url(buf) {
  return Buffer.from(buf).toString("base64").replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function b64urlJSON(o) { return b64url(JSON.stringify(o)); }

function signJWT(payload, secret, expSeconds) {
  const now = Math.floor(Date.now() / 1000);
  const body = Object.assign({ iat: now }, expSeconds ? { exp: now + expSeconds } : {}, payload);
  const data = b64urlJSON({ alg: "HS256", typ: "JWT" }) + "." + b64urlJSON(body);
  const sig = b64url(crypto.createHmac("sha256", secret).update(data).digest());
  return data + "." + sig;
}
function verifyJWT(token, secret) {
  if (!token || !secret) return null;
  const parts = String(token).split(".");
  if (parts.length !== 3) return null;
  const data = parts[0] + "." + parts[1];
  const expected = b64url(crypto.createHmac("sha256", secret).update(data).digest());
  const a = Buffer.from(parts[2]), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  let payload;
  try { payload = JSON.parse(Buffer.from(parts[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString()); }
  catch (e) { return null; }
  if (payload.exp && Math.floor(Date.now() / 1000) > payload.exp) return null;
  return payload;
}

/* ---------------- KV (Upstash REST) ---------------- */
// Accept either naming convention: Vercel KV (KV_REST_API_*) or the native
// Upstash Marketplace integration (UPSTASH_REDIS_REST_*). Whichever Vercel
// injects, the gateway finds it.
function kvUrl() { return process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL || ""; }
function kvTok() { return process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN || ""; }
function kvConfigured() {
  return !!(kvUrl() && kvTok());
}
async function kvCmd(args) {
  const url = kvUrl(), tok = kvTok();
  if (!url || !tok) throw new Error("KV not configured");
  const r = await fetch(url.replace(/\/$/, ""), {
    method: "POST",
    headers: { Authorization: "Bearer " + tok, "content-type": "application/json" },
    body: JSON.stringify(args),
  });
  const j = await r.json();
  if (j && j.error) throw new Error("KV error: " + j.error);
  return j ? j.result : null;
}
async function kvGetJSON(key) {
  const v = await kvCmd(["GET", key]);
  if (v == null) return null;
  try { return JSON.parse(v); } catch (e) { return null; }
}
async function kvSetJSON(key, val) { return kvCmd(["SET", key, JSON.stringify(val)]); }
async function kvDel(key) { return kvCmd(["DEL", key]); }

/* ---------------- Key records ---------------- */
const IDX = "kt:index";                 // JSON array of jtis
const KREC = (jti) => "kt:key:" + jti;   // one record per proxy key

async function listKeys() {
  const idx = (await kvGetJSON(IDX)) || [];
  const out = [];
  for (const jti of idx) { const r = await kvGetJSON(KREC(jti)); if (r) out.push(r); }
  return out;
}
async function getKey(jti) { return kvGetJSON(KREC(jti)); }
async function putKey(rec) {
  await kvSetJSON(KREC(rec.jti), rec);
  const idx = (await kvGetJSON(IDX)) || [];
  if (!idx.includes(rec.jti)) { idx.push(rec.jti); await kvSetJSON(IDX, idx); }
  return rec;
}

/* ---------------- helpers ---------------- */
function readBody(req) {
  let b = req.body;
  if (typeof b === "string") { try { b = JSON.parse(b); } catch (e) { b = {}; } }
  return b || {};
}
function bearer(req) {
  const h = req.headers["authorization"] || req.headers["Authorization"] || "";
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return m ? m[1].trim() : "";
}

module.exports = {
  signJWT, verifyJWT, kvConfigured, kvCmd, kvGetJSON, kvSetJSON, kvDel,
  listKeys, getKey, putKey, readBody, bearer,
};
