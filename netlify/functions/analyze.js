// Netlify serverless function: proxies analysis requests to Google Gemini.
//
// The browser sends a fully formed Gemini request body. This function adds the
// API key from the server environment so a visitor does not need one of their
// own, then returns the raw Gemini response.
//
// Set GEMINI_API_KEY in the Netlify site environment variables.
// Endpoint once deployed: https://<your-site>.netlify.app/.netlify/functions/analyze

const MODEL = "gemini-3.8-flash";

const JSON_HEADERS = {
  "Content-Type": "application/json",
  "Cache-Control": "no-store",
};

export const handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return {
      statusCode: 405,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: "method_not_allowed" }),
    };
  }

  const key = process.env.GEMINI_API_KEY;
  if (!key) {
    // The browser treats this as "no server key" and falls back to a key the
    // reviewer supplied locally, so this is a normal state, not a failure.
    return {
      statusCode: 501,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: "no_key" }),
    };
  }

  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch (err) {
    return {
      statusCode: 400,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: "bad_request", detail: "Body was not valid JSON." }),
    };
  }

  if (!body.contents) {
    return {
      statusCode: 400,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: "bad_request", detail: "Missing contents." }),
    };
  }

  const upstream =
    "https://generativelanguage.googleapis.com/v1beta/models/" +
    MODEL +
    ":generateContent";

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 25000);

    const res = await fetch(upstream, {
      method: "POST",
      signal: controller.signal,
      headers: {
        "Content-Type": "application/json",
        "x-goog-api-key": key,
      },
      body: JSON.stringify(body),
    });
    clearTimeout(timeout);

    const text = await res.text();
    if (!res.ok) {
      let detail = "Gemini returned " + res.status + ".";
      try {
        const parsed = JSON.parse(text);
        if (parsed.error && parsed.error.message) detail = parsed.error.message;
      } catch (err) {
        /* keep the generic message */
      }
      return {
        statusCode: 502,
        headers: JSON_HEADERS,
        body: JSON.stringify({ error: "upstream_error", detail }),
      };
    }

    return { statusCode: 200, headers: JSON_HEADERS, body: text };
  } catch (err) {
    return {
      statusCode: 504,
      headers: JSON_HEADERS,
      body: JSON.stringify({
        error: "request_failed",
        detail: "The analysis request timed out or could not be completed.",
      }),
    };
  }
};
