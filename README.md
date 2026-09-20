# ThreatLens

AI-powered defensive threat intelligence dashboard built with Streamlit.
Checks an IP address, domain, or URL against **VirusTotal** and **WHOIS**,
then sends the collected evidence to **Gemini** for a structured,
evidence-based verdict.

## 1. Install dependencies

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## 2. Get API keys

- **VirusTotal**: create a free account at https://www.virustotal.com/gui/join-us,
  then find your API key under your profile ("API Key" in account settings).
  Free-tier keys have low rate limits (roughly 4 requests/minute) -- the app
  handles rate-limit errors gracefully.
- **Gemini**: create a key at https://aistudio.google.com/apikey (Google AI Studio).

## 3. Configure secrets

Choose ONE of the two methods below (Streamlit secrets is recommended when
running via `streamlit run`).

**Option A -- Streamlit secrets (recommended)**

```bash
mkdir -p .streamlit
cp secrets.toml.example .streamlit/secrets.toml
# then edit .streamlit/secrets.toml and paste in your real keys
```

**Option B -- Environment variables / .env**

```bash
cp .env.example .env
# then edit .env and paste in your real keys
```

If using `.env`, load it before running (e.g. `export $(cat .env | xargs)` on
macOS/Linux, or use a tool like `python-dotenv` in your own shell setup).
Either method works -- `sources.py` checks Streamlit secrets first, then
falls back to environment variables.

**Never commit `.env` or `.streamlit/secrets.toml` to version control.**

## 4. Run the app

```bash
streamlit run app.py
```

Then open the URL Streamlit prints (typically http://localhost:8501).

## 5. Example inputs

- `8.8.8.8` -- detected as an IP
- `example.com` -- detected as a domain
- `https://example.com/path` -- detected as a URL

## Architecture

- **`app.py`** -- Streamlit UI and orchestration only. It loops generically
  over `SOURCE_REGISTRY` to collect results, calls Gemini, parses the
  response, and renders everything. It contains no source-specific
  (`if source == "VirusTotal"`) logic.
- **`sources.py`** -- all source-specific logic:
  - `detect_ioc_type()` -- classifies input as ip / domain / url / invalid.
  - `get_virustotal()`, `get_whois()` -- each returns the same structure:
    `{"source": ..., "success": ..., "data": ..., "error": ...}`.
  - `SOURCE_REGISTRY` -- maps a display name to its function. This is the
    single source of truth `app.py` iterates over.
  - `build_gemini_prompt()`, `call_gemini()`, `parse_gemini_response()` --
    construct the analysis prompt, call the Gemini API, and safely parse
    its JSON response (falling back to a safe "Unknown" result if parsing
    fails).

## Adding a third source later (e.g. AbuseIPDB, Shodan, URLScan)

1. In `sources.py`, write a new function with the signature
   `get_newsource(ioc: str, ioc_type: str) -> dict`, returning the same
   `{"source", "success", "data", "error"}` structure as the existing
   sources (use the `make_result()` helper).
2. Add one line to `SOURCE_REGISTRY`:
   ```python
   SOURCE_REGISTRY = {
       "VirusTotal": get_virustotal,
       "WHOIS": get_whois,
       "NewSource": get_newsource,
   }
   ```

That's it -- `app.py` automatically picks it up in the source loop, the
status display, the raw-data expanders, and the Gemini prompt. No changes
to `app.py` are required.

## Security notes

- API keys are read only from Streamlit secrets or environment variables --
  never hardcoded, never logged, never sent to Gemini, never shown in the UI.
- The AI verdict is clearly labeled "ThreatLens AI Risk Score" and is never
  presented as an official score from VirusTotal or any other source.
- Raw source data is always shown in expandable sections so you can verify
  the AI's summary against the underlying evidence.
- The app never executes user input or shell commands, and all API/network/
  parsing failures are caught and shown as Streamlit warnings/errors rather
  than crashing the app.
