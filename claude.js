// /api/claude.js — server-side proxy to the Anthropic Messages API.
// The API key is read from the ANTHROPIC_API_KEY environment variable and is
// never sent to the browser. The front end POSTs { model, max_tokens, system,
// messages } here; this forwards it to Anthropic and returns the raw response.
//
// No npm dependencies: uses the global fetch built into Vercel's Node runtime.

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    res.status(405).json({ error: "POST only" });
    return;
  }
  const key = process.env.ANTHROPIC_API_KEY;
  if (!key) {
    res.status(200).json({ error: "ANTHROPIC_API_KEY is not set on this deployment. Add it in Vercel → Settings → Environment Variables, then redeploy." });
    return;
  }

  let body = req.body;
  if (typeof body === "string") { try { body = JSON.parse(body); } catch { body = {}; } }
  body = body || {};

  try {
    const r = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": key,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: body.model,
        max_tokens: body.max_tokens,
        system: body.system,
        messages: body.messages,
      }),
    });
    const text = await r.text();
    res.status(r.status);
    res.setHeader("content-type", "application/json");
    res.send(text); // pass Anthropic's JSON (or error) straight through
  } catch (err) {
    res.status(200).json({ error: "Proxy failed: " + (err && err.message ? err.message : String(err)) });
  }
};
