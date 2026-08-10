// /api/claude.js — streaming server-side proxy to the Anthropic Messages API.
// The API key is read from the ANTHROPIC_API_KEY environment variable and is
// never sent to the browser. We request a streamed response from Anthropic and
// pipe the SSE bytes straight to the client, so the connection is never idle —
// this avoids the gateway 504 that a slow, buffered (non-streamed) call hits.
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
    const upstream = await fetch("https://api.anthropic.com/v1/messages", {
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
        stream: true, // stream so the connection stays active
      }),
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
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      res.write(Buffer.from(value));
      if (typeof res.flush === "function") res.flush();
    }
    res.end();
  } catch (err) {
    const msg = "Proxy failed: " + (err && err.message ? err.message : String(err));
    if (!res.headersSent) {
      res.status(200);
      res.setHeader("content-type", "application/json");
      res.send(JSON.stringify({ error: msg }));
    } else {
      try { res.end(); } catch (e) {}
    }
  }
};
