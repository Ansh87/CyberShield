# CyberShield

Cyber-physical threat intelligence. A security tool that reads telemetry, classifies the threat with a language model, and then scores what that threat would actually do in the real world to the specific system under review.

A vulnerability scanner gives a laptop and a factory controller the same severity number for the same flaw. That is the wrong place to stop. Severity is not consequence. Prompt injection against a chatbot is a data leak. The same class of manipulation against an agent wired to a physical actuator is a safety incident. CyberShield is the layer that asks what happens in the real world if this is exploited on this system.

Built by Ansh Saini, South Brunswick High School, New Jersey. This is a student prototype.

## How it works

The work is split deliberately between the model and the code.

**Google Gemini decides what the threat is.** It reads the telemetry and returns structured findings, each with a severity, a confidence, a mapping to public taxonomies such as MITRE ATT&CK, MITRE ATLAS, and the OWASP Top 10 for LLM applications, and the verbatim fragments of the telemetry that the classification rests on. It also returns projected impacts, split into physical and digital, and a set of recommended actions ordered by urgency.

**The code decides how much it matters.** The risk score is not a model output. It is a fixed weighted formula over five factors:

| Factor | Weight | Source |
| --- | --- | --- |
| Physical safety relevance | 0.28 | model, gated on whether the asset can cause physical harm |
| Threat severity | 0.25 | model |
| Asset criticality | 0.22 | asset baseline, adjustable |
| Autonomy level | 0.15 | asset baseline, adjustable |
| Exposure | 0.10 | asset baseline, adjustable |

The result is then reduced by how much human oversight exists. Manual override multiplies the score by 0.82, human review by 0.91, no oversight by 1.0.

Keeping the arithmetic deterministic means the same finding on the same asset always scores the same, and the weighting can be inspected and argued with rather than taken on faith.

The Intel tab lists the most recent additions to the catalog fifteen at a time. The button pages forward through them, and wrapping past the end refetches.

**CVE identifiers are checked against live data.** Any CVE found in the telemetry is cross referenced against the CISA catalog of vulnerabilities confirmed as exploited in the wild, fetched at runtime.

## Project structure

```
index.html                    markup only
styles.css                    all styling
app.js                        application logic, asset model, scoring, rendering
netlify/
  functions/
    analyze.js                proxies Gemini, holds the API key server side
    kev.js                    proxies the CISA vulnerability feed past CORS
netlify.toml                  publish directory and functions directory
```

No framework, no build step, no package manager. Three files in the browser and two serverless functions.

## Why there are serverless functions

**analyze.js** exists so the Gemini API key lives in the server environment and never reaches the browser. A visitor can open the live site and run an analysis without configuring anything. The browser sends a fully formed Gemini request body, the function attaches the key, and the raw response comes back.

**kev.js** exists because the CISA feed does not send CORS headers, so a browser cannot fetch it directly. A server can. The function also returns the full list of CVE identifiers in the catalog, separately from the trimmed list shown on screen, so cross referencing checks the whole catalog while the display stays small.

## Deploying

The app requires the Gemini function to work. It will load without it, but analysis will report that the service is not available.

1. Get an API key from [Google AI Studio](https://aistudio.google.com/apikey).
2. Deploy this directory to Netlify, either by connecting the repository or by dragging the folder onto Netlify Drop.
3. In the site dashboard, go to **Site configuration, Environment variables, Add a variable** and add:
   - Key: `GEMINI_API_KEY`
   - Value: your key
   - Scopes: Functions must be included
   - Deploy contexts: All
4. Optionally add a second variable, `GEMINI_MODEL`, to change which model is used without editing any code. Leave it unset to use the built in default. Any Gemini model id that supports `generateContent` works, for example `gemini-3.5-flash`, `gemini-3.8-flash` or `gemini-2.5-flash`.
5. Redeploy. Functions read environment variables at deploy time, so a variable does nothing until you do. Use **Deploys, Trigger deploy, Clear cache and deploy site**.

## Checking what is deployed

Open `https://YOUR-SITE.netlify.app/status` in a browser. It reports which model this deployment will use, where that setting came from, and whether a key is present. It never returns the key itself.

```json
{
  "service": "cybershield-analyze",
  "model": "gemini-3.5-flash",
  "defaultModel": "gemini-3.5-flash",
  "modelSource": "built in default",
  "keyConfigured": true,
  "ready": true
}
```

If `ready` is false, the key is missing, misspelled, or you have not redeployed since setting it.

That endpoint reports what the deployment intends to use. To confirm what actually served a request, read the `modelVersion` field that Gemini returns:

```bash
curl -s -X POST https://YOUR-SITE.netlify.app/.netlify/functions/analyze -H "Content-Type: application/json" -d '{"contents":[{"role":"user","parts":[{"text":"reply with the single word ok"}]}]}' | grep -o '"modelVersion":"[^"]*"'
```

The same value is recorded in every exported report, so a report always names the engine that produced it.

## Running locally

A plain static server will serve the page but not the functions, so analysis will not work and the vulnerability feed will fall back to a small offline sample. To run the whole thing, use the Netlify CLI:

```bash
npm install -g netlify-cli
```

Create a `.env` file in the project root:

```
GEMINI_API_KEY=your-key-here
```

Then:

```bash
netlify dev
```

Add `.env` to your `.gitignore` before committing anything. The key must never be in the repository, in `netlify.toml`, or in any file served to the browser.

## Security design

The tool ingests untrusted data by design, which makes it part of its own attack surface.

**Prompt injection.** Telemetry is wrapped in tags and the system instruction states that everything inside is untrusted evidence, that no instruction found in it may be acted on, and that an injection attempt should be reported as a finding rather than followed. One of the built in samples is a log containing an instruction override aimed directly at the classifier.

**Output escaping.** Model output flows into the DOM, so every string returned by Gemini passes through an escape function before it is rendered. This was tested by pushing an image tag with an onerror payload through a stubbed model response and confirming it rendered as literal text.

**Key handling.** The API key exists only in the Netlify server environment. There is no key field in the interface and no client side storage of credentials.

**Input warning.** The interface states that telemetry is sent to Google for analysis and that passwords, private keys, customer data, and production secrets should not be pasted in.

## Known limitations

This is a prototype and the limitations are real.

The input is a text box that a person pastes prose into. Everything downstream is only as good as what goes in. Real detection would ingest structured formats such as Suricata or Zeek output, Windows event logs, and OpenTelemetry traces, and would use Sigma rules rather than relying on a model to infer everything.

There is no measured false positive rate. The tool has not been run against a benign corpus or public datasets, so there are no precision and recall figures to report.

Classification is a language model reading text. It can be wrong, it can miss things, and it can be confidently wrong. Every finding needs a human to confirm it.

The scope is broad, covering nine asset types from personal computers to smart city systems. No single tool credibly covers that range in depth.

## Roadmap

- Structured ingestion: Suricata and Zeek output, Windows event logs, OpenTelemetry agent traces, Sigma rule support
- Physics based checks: implied velocity from position deltas, so navigation spoofing is caught by kinematics rather than language
- Validation against public datasets such as CICIDS2017, UNSW-NB15, and TON_IoT, reporting precision and recall against a benign corpus
- EPSS exploitation probability and SBOM ingestion alongside the CISA catalog
- Narrowing to one domain and going deep, most likely AI agent security

## Disclaimer

This prototype is for educational, research, and decision support purposes only. It does not remove malware, guarantee containment, or replace qualified cybersecurity, vendor, or incident response guidance. Classification is produced by a language model and can be wrong. All findings require human verification.
