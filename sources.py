"""
sources.py
----------
This module contains ALL source-specific logic for ThreatLens:

- IOC (Indicator of Compromise) type detection
- Intelligence source functions (VirusTotal, WHOIS)
- The SOURCE_REGISTRY, which is the single source of truth for which
  sources exist and how to call them
- Gemini prompt construction, API calling, and response parsing

app.py never contains source-specific logic. Every source function
returns the SAME structure, so app.py and the Gemini prompt builder
can treat every source generically. To add a new source later:

    1. Write a new function here that returns the standard result dict.
    2. Add one line to SOURCE_REGISTRY.

That's it -- no changes to app.py are required.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from typing import Any, Callable
from urllib.parse import urlparse

import requests

try:
    import whois as pywhois  # python-whois
except ImportError:  # pragma: no cover - handled at runtime with a clear error
    pywhois = None


# ---------------------------------------------------------------------------
# Configuration / secrets access
# ---------------------------------------------------------------------------

VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3"
REQUEST_TIMEOUT_SECONDS = 15


def get_secret(key: str) -> str | None:
    """
    Retrieve a secret (API key) safely.

    Checks Streamlit secrets first (if running inside Streamlit and secrets
    are configured), then falls back to environment variables. Never logs
    or exposes the value.
    """
    try:
        import streamlit as st  # imported lazily to avoid hard dependency issues

        if key in st.secrets:
            return st.secrets[key]
    except Exception:
        # st.secrets raises if no secrets.toml exists at all -- that's fine,
        # we just fall back to environment variables.
        pass

    return os.environ.get(key)


# ---------------------------------------------------------------------------
# Standard result structure
# ---------------------------------------------------------------------------

def make_result(source: str, success: bool, data: Any = None, error: str | None = None) -> dict:
    """Build the standard, consistent result structure every source returns."""
    return {
        "source": source,
        "success": success,
        "data": data,
        "error": error,
    }


# ---------------------------------------------------------------------------
# IOC detection
# ---------------------------------------------------------------------------

# A reasonably strict domain regex: labels of letters/digits/hyphens,
# separated by dots, ending in a plausible TLD.
_DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
)


def detect_ioc_type(value: str) -> str:
    """
    Determine whether the given input is an "ip", "domain", "url", or "invalid".

    This makes no dangerous assumptions -- if the input doesn't clearly
    match one of the known patterns, it is marked invalid rather than
    guessed at.
    """
    if not value or not value.strip():
        return "invalid"

    candidate = value.strip()

    # URL: has a scheme (http/https) or looks like one was intended.
    if "://" in candidate:
        parsed = urlparse(candidate)
        if parsed.scheme in ("http", "https") and parsed.netloc:
            return "url"
        return "invalid"

    # IP address (v4 or v6)
    try:
        ipaddress.ip_address(candidate)
        return "ip"
    except ValueError:
        pass

    # Domain
    if _DOMAIN_REGEX.match(candidate):
        return "domain"

    return "invalid"


def extract_domain_or_ip_for_whois(ioc: str, ioc_type: str) -> str | None:
    """Normalize a URL/domain/IP down to a bare domain (or IP) for WHOIS lookups."""
    if ioc_type == "url":
        parsed = urlparse(ioc)
        return parsed.hostname
    if ioc_type in ("domain", "ip"):
        return ioc
    return None


# ---------------------------------------------------------------------------
# VirusTotal source
# ---------------------------------------------------------------------------

def _vt_headers() -> dict | None:
    api_key = get_secret("VIRUSTOTAL_API_KEY")
    if not api_key:
        return None
    return {"x-apikey": api_key}


def _vt_endpoint_for(ioc: str, ioc_type: str) -> str | None:
    """Build the correct VirusTotal API endpoint depending on IOC type."""
    if ioc_type == "ip":
        return f"{VIRUSTOTAL_API_URL}/ip_addresses/{ioc}"
    if ioc_type == "domain":
        return f"{VIRUSTOTAL_API_URL}/domains/{ioc}"
    if ioc_type == "url":
        # VirusTotal identifies URLs by a URL-safe base64 id (no padding).
        import base64

        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
        return f"{VIRUSTOTAL_API_URL}/urls/{url_id}"
    return None


def _vt_extract_summary(payload: dict) -> dict:
    """Pull out the useful fields from a VirusTotal API response."""
    attributes = payload.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    results = attributes.get("last_analysis_results", {}) or {}

    # Only keep vendor verdicts that flagged something, to keep the payload small.
    flagged_vendors = {
        vendor: verdict.get("category")
        for vendor, verdict in results.items()
        if verdict.get("category") in ("malicious", "suspicious")
    }

    return {
        "malicious_count": stats.get("malicious", 0),
        "suspicious_count": stats.get("suspicious", 0),
        "harmless_count": stats.get("harmless", 0),
        "undetected_count": stats.get("undetected", 0),
        "reputation": attributes.get("reputation"),
        "last_analysis_date": attributes.get("last_analysis_date"),
        "categories": attributes.get("categories"),
        "flagged_vendors": flagged_vendors,
    }


def get_virustotal(ioc: str, ioc_type: str) -> dict:
    """
    Query VirusTotal for the given IOC (IP, domain, or URL).

    Returns the standard result structure. Never raises -- all failure
    modes (missing key, rate limit, timeout, network error, malformed
    response) are caught and returned as a graceful error result.
    """
    source_name = "VirusTotal"

    headers = _vt_headers()
    if headers is None:
        return make_result(
            source_name, False, None,
            "VirusTotal API key is not configured. Set VIRUSTOTAL_API_KEY."
        )

    endpoint = _vt_endpoint_for(ioc, ioc_type)
    if endpoint is None:
        return make_result(
            source_name, False, None,
            f"VirusTotal does not support IOC type '{ioc_type}'."
        )

    try:
        response = requests.get(endpoint, headers=headers, timeout=REQUEST_TIMEOUT_SECONDS)
    except requests.exceptions.Timeout:
        return make_result(source_name, False, None, "VirusTotal request timed out.")
    except requests.exceptions.ConnectionError:
        return make_result(source_name, False, None, "Could not connect to VirusTotal.")
    except requests.exceptions.RequestException as exc:
        return make_result(source_name, False, None, f"VirusTotal request failed: {exc}")

    if response.status_code == 401:
        return make_result(source_name, False, None, "VirusTotal API key is invalid.")
    if response.status_code == 429:
        return make_result(source_name, False, None, "VirusTotal rate limit exceeded.")
    if response.status_code == 404:
        return make_result(
            source_name, True,
            {"note": "IOC not found in VirusTotal's database (no prior analysis on file)."},
            None,
        )
    if not response.ok:
        return make_result(
            source_name, False, None,
            f"VirusTotal returned an unexpected status code: {response.status_code}",
        )

    try:
        payload = response.json()
        summary = _vt_extract_summary(payload)
    except (ValueError, KeyError, TypeError) as exc:
        return make_result(source_name, False, None, f"Could not parse VirusTotal response: {exc}")

    return make_result(source_name, True, summary, None)


# ---------------------------------------------------------------------------
# WHOIS source
# ---------------------------------------------------------------------------

def _stringify(value: Any) -> Any:
    """Convert datetimes/lists of datetimes into JSON-friendly strings."""
    if isinstance(value, list):
        return [_stringify(v) for v in value]
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return value


def get_whois(ioc: str, ioc_type: str) -> dict:
    """
    Perform a WHOIS lookup for the given IOC.

    WHOIS is only meaningful for domains (and, for URLs, the domain
    extracted from them). For IP addresses, WHOIS-style registry data is
    a different lookup entirely, so we return a clear, non-crashing
    explanatory result rather than pretending to support it.
    """
    source_name = "WHOIS"

    if pywhois is None:
        return make_result(
            source_name, False, None,
            "The 'python-whois' package is not installed."
        )

    target = extract_domain_or_ip_for_whois(ioc, ioc_type)
    if target is None:
        return make_result(source_name, False, None, "No valid domain could be determined for WHOIS.")

    if ioc_type == "ip":
        return make_result(
            source_name, True,
            {"note": "WHOIS domain registration lookup does not apply to IP addresses."},
            None,
        )

    try:
        record = pywhois.whois(target)
    except Exception as exc:  # python-whois can raise various error types
        return make_result(source_name, False, None, f"WHOIS lookup failed: {exc}")

    if not record or not getattr(record, "domain_name", None):
        return make_result(
            source_name, True,
            {"note": "No WHOIS data was found for this domain."},
            None,
        )

    data = {
        "domain_name": _stringify(record.domain_name),
        "registrar": _stringify(getattr(record, "registrar", None)),
        "creation_date": _stringify(getattr(record, "creation_date", None)),
        "expiration_date": _stringify(getattr(record, "expiration_date", None)),
        "updated_date": _stringify(getattr(record, "updated_date", None)),
        "name_servers": _stringify(getattr(record, "name_servers", None)),
        "status": _stringify(getattr(record, "status", None)),
        # Registrant org/country only -- avoid exposing personal data that
        # most registries redact anyway, and only surface what's public.
        "registrant_org": _stringify(getattr(record, "org", None)),
        "registrant_country": _stringify(getattr(record, "country", None)),
    }

    return make_result(source_name, True, data, None)


# ---------------------------------------------------------------------------
# SOURCE REGISTRY -- the single source of truth
# ---------------------------------------------------------------------------
# Every entry maps a display name to a callable with signature
# (ioc: str, ioc_type: str) -> dict (standard result structure).
#
# To add a new source (e.g. AbuseIPDB, Shodan, URLScan):
#   1. Write get_abuseipdb(ioc, ioc_type) -> dict here, following the same
#      make_result(...) pattern used above.
#   2. Add "AbuseIPDB": get_abuseipdb to the dict below.
# app.py's orchestration loop requires no changes at all.

SOURCE_REGISTRY: dict[str, Callable[[str, str], dict]] = {
    "VirusTotal": get_virustotal,
    "WHOIS": get_whois,
}


# ---------------------------------------------------------------------------
# Gemini prompt construction, calling, and parsing
# ---------------------------------------------------------------------------

_KNOWLEDGE_LEVEL_INSTRUCTIONS = {
    "Beginner": (
        "Explain your findings in simple, plain language suitable for someone "
        "with little to no cybersecurity background. Avoid jargon, or briefly "
        "define any technical term you must use."
    ),
    "Intermediate": (
        "Use standard cybersecurity terminology with moderate explanation, "
        "suitable for someone who understands general IT/security concepts."
    ),
    "Expert": (
        "Provide a concise, technical analysis using precise security "
        "terminology, indicators, and evidence. Assume the reader is an "
        "experienced security analyst -- do not over-explain basic concepts."
    ),
}


def build_gemini_prompt(
    ioc: str,
    ioc_type: str,
    knowledge_level: str,
    source_results: dict[str, dict],
) -> str:
    """
    Build the full prompt sent to Gemini for analysis.

    The prompt embeds only the collected source data (never secrets) and
    strict instructions so Gemini acts as an analysis layer over real
    evidence, not a source of truth itself.
    """
    level_instruction = _KNOWLEDGE_LEVEL_INSTRUCTIONS.get(
        knowledge_level, _KNOWLEDGE_LEVEL_INSTRUCTIONS["Intermediate"]
    )

    # Serialize source results (data + errors) as JSON for the model.
    evidence_json = json.dumps(source_results, indent=2, default=str)

    prompt = f"""You are a defensive cybersecurity threat intelligence analyst.

You must base your assessment ONLY on the supplied source data below.
Do not fabricate missing information. If evidence is insufficient to
reach a confident conclusion, say so and use "Unknown" as the verdict.

INDICATOR OF COMPROMISE (IOC): {ioc}
IOC TYPE: {ioc_type}

SOURCE DATA (JSON, one entry per intelligence source; a source with
"success": false or "error" set means that source did NOT return usable
evidence -- do not treat its absence as suspicious by itself):

{evidence_json}

INSTRUCTIONS:
1. Analyze only the evidence supplied above. Do not invent detections,
   registrar details, or dates that are not present in the data.
2. If sources disagree or contradict each other, explicitly mention the
   contradiction in your summary or key findings.
3. If a source failed or is missing data, mention that evidence is
   incomplete rather than treating the gap as a red flag.
4. {level_instruction}
5. Clearly separate observed facts (from the source data) from your own
   interpretation of what those facts mean.
6. Provide a practical, defensive recommendation (e.g. monitor, block,
   investigate further, no action needed) -- never an offensive action.
7. If the evidence is too thin to support any verdict, use "Unknown".

RESPONSE FORMAT:
Return ONLY valid JSON, with no markdown code fences, no preamble, and no
trailing commentary, matching exactly this schema:

{{
    "verdict": "Safe | Suspicious | Malicious | Unknown",
    "risk_score": 0,
    "summary": "Short explanation of the overall assessment",
    "key_findings": ["finding 1", "finding 2"],
    "recommendation": "Recommended defensive action"
}}

Rules for the JSON:
- "verdict" must be exactly one of: Safe, Suspicious, Malicious, Unknown.
- "risk_score" must be an integer from 0 to 100 (0 = no risk indicated,
  100 = strong evidence of malicious activity). Use 0 when verdict is
  "Unknown" and there is truly no signal either way.
- "summary" must explain the reasoning in 2-4 sentences.
- "key_findings" must be a list of short, evidence-based bullet strings.
- "recommendation" must be a concise, practical, defensive action.
"""
    return prompt


def _extract_json_object(text: str) -> str:
    """Strip markdown code fences and surrounding text, isolating the JSON object."""
    cleaned = text.strip()
    cleaned = re.sub(r"^```(?:json)?", "", cleaned.strip(), flags=re.IGNORECASE).strip()
    cleaned = re.sub(r"```$", "", cleaned.strip()).strip()

    # If there's still leading/trailing prose, grab the outermost { ... }.
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        return cleaned[start : end + 1]
    return cleaned


def call_gemini(prompt: str) -> dict:
    """
    Call the Gemini API with the given prompt.

    Returns {"success": True, "text": "..."} or {"success": False, "error": "..."}.
    Never raises -- all failures are caught and reported gracefully.
    """
    api_key = get_secret("GEMINI_API_KEY")
    if not api_key:
        return {"success": False, "error": "Gemini API key is not configured. Set GEMINI_API_KEY.", "text": None}

    try:
        from google import genai
    except ImportError:
        return {
            "success": False,
            "error": "The 'google-genai' package is not installed.",
            "text": None,
        }

    try:
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
        )
        text = getattr(response, "text", None)
        if not text:
            return {"success": False, "error": "Gemini returned an empty response.", "text": None}
        return {"success": True, "error": None, "text": text}
    except Exception as exc:  # broad catch: any SDK/network error must not crash the app
        return {"success": False, "error": f"Gemini API call failed: {exc}", "text": None}


def parse_gemini_response(raw_text: str) -> dict:
    """
    Safely parse Gemini's JSON response into the expected schema.

    Always returns a dict with the full expected keys, filling in safe
    defaults ("Unknown" / 0 / empty) if parsing fails or fields are missing
    or invalid, so the UI never crashes on a malformed AI response.
    """
    fallback = {
        "verdict": "Unknown",
        "risk_score": 0,
        "summary": "The AI response could not be parsed. Please review the raw source data manually.",
        "key_findings": [],
        "recommendation": "Manually review the raw source data below before taking action.",
        "parse_error": None,
    }

    if not raw_text:
        fallback["parse_error"] = "Empty response from Gemini."
        return fallback

    json_text = _extract_json_object(raw_text)

    try:
        parsed = json.loads(json_text)
    except json.JSONDecodeError as exc:
        fallback["parse_error"] = f"Invalid JSON from Gemini: {exc}"
        return fallback

    valid_verdicts = {"Safe", "Suspicious", "Malicious", "Unknown"}
    verdict = parsed.get("verdict")
    if verdict not in valid_verdicts:
        verdict = "Unknown"

    risk_score = parsed.get("risk_score", 0)
    try:
        risk_score = int(risk_score)
        if not (0 <= risk_score <= 100):
            risk_score = 0
    except (TypeError, ValueError):
        risk_score = 0

    summary = parsed.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        summary = "No summary was provided."

    key_findings = parsed.get("key_findings")
    if not isinstance(key_findings, list):
        key_findings = []
    key_findings = [str(item) for item in key_findings]

    recommendation = parsed.get("recommendation")
    if not isinstance(recommendation, str) or not recommendation.strip():
        recommendation = "No specific recommendation was provided; review raw source data manually."

    return {
        "verdict": verdict,
        "risk_score": risk_score,
        "summary": summary,
        "key_findings": key_findings,
        "recommendation": recommendation,
        "parse_error": None,
    }
