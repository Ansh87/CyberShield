// Netlify serverless function: proxies the live CISA KEV feed.
// Servers are not bound by browser CORS rules, so this fetches the real
// CISA catalog and re-serves it to the app with an Access-Control-Allow-Origin
// header that the browser will accept.
//
// Endpoint once deployed: https://<your-site>.netlify.app/.netlify/functions/kev

export const handler = async () => {
  const UPSTREAM =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

  const CORS = {
    "Access-Control-Allow-Origin": "*",
    "Content-Type": "application/json",
    // cache at the edge for 1 hour so we don't refetch on every visit
    "Cache-Control": "public, max-age=3600",
  };

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 9000);

    const res = await fetch(UPSTREAM, {
      signal: controller.signal,
      headers: { "User-Agent": "CyberShield-AI-Prototype/1.0" },
    });
    clearTimeout(timeout);

    if (!res.ok) {
      return {
        statusCode: 502,
        headers: CORS,
        body: JSON.stringify({ error: "upstream_error", status: res.status }),
      };
    }

    const data = await res.json();

    // Full catalog for lookup; trimmed list for display.
    const vulns = Array.isArray(data.vulnerabilities) ? data.vulnerabilities : [];
    const recent = vulns.slice(-40).reverse().map((v) => ({
      cveID: v.cveID,
      vendorProject: v.vendorProject,
      product: v.product,
      vulnerabilityName: v.vulnerabilityName,
      dateAdded: v.dateAdded,
    }));

    // Full list of every CVE ID in the catalog — used for CVE matching in the app
    // (display stays trimmed, matching uses the whole catalog).
    const allCveIds = vulns.map((v) => v.cveID);

    return {
      statusCode: 200,
      headers: CORS,
      body: JSON.stringify({
        source: "cisa-kev-live",
        count: vulns.length,
        catalogVersion: data.catalogVersion || null,
        dateReleased: data.dateReleased || null,
        vulnerabilities: recent,
        allCveIds: allCveIds,
      }),
    };
  } catch (err) {
    return {
      statusCode: 504,
      headers: CORS,
      body: JSON.stringify({ error: "fetch_failed", detail: String(err) }),
    };
  }
};
