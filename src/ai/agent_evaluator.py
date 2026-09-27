"""
src/ai/agent_evaluator.py
Gemini AI Evaluator for InternKavach — Production Multimodal Edition
──────────────────────────────────────────────────────────────────
• Multi-Model Fallback Cascade:
  CANDIDATE_MODELS = ["gemini-2.5-flash", "gemini-2.5-flash-lite", "gemini-2.0-flash", ...]
• Retry with Backoff:
  Waits 1.5 seconds upon 503 UNAVAILABLE or 429 before attempting the next candidate model.
• Returns active_model so UI displays "🟢 Live Gemini AI Active (via <working-model-name>)".
• Strict auditing of internship terms: unpaid status, lack of mentorship, certificate mills (e.g. Prodigy InfoTech).
"""
from __future__ import annotations

import io
import json
import os
import re
import time
import traceback
from pathlib import Path
from typing import Any, Dict, Optional, Union

try:
    from PIL import Image
except ImportError:
    Image = None

# ── Load .env from project root ───────────────────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parents[2] / ".env", override=True)
except ImportError:
    pass

# ── Gemini SDK ────────────────────────────────────────────────────────────────
GEMINI_AVAILABLE = False
_genai = None
_genai_types = None
try:
    from google import genai as _genai_mod
    from google.genai import types as _genai_types_mod
    _genai = _genai_mod
    _genai_types = _genai_types_mod
    GEMINI_AVAILABLE = True
except ImportError:
    pass

# Key from environment
_ENV_API_KEY: str = os.environ.get("GEMINI_API_KEY", "").strip()

# Multi-Model Fallback Cascade
# Starts with requested candidate models and automatically cascades upon 503 / 429 / 404
CANDIDATE_MODELS = [
    "gemini-2.5-flash",
    "gemini-2.5-flash-lite",
    "gemini-2.0-flash",
    "gemini-3.5-flash-lite",
    "gemini-3-flash-preview",
    "gemini-3.6-flash",
    "gemini-3.8-flash",
]


# ══════════════════════════════════════════════════════════════════════════════
# PROMPT TEMPLATES
# ══════════════════════════════════════════════════════════════════════════════

TEXT_ANALYSIS_PROMPT = """\
You are InternKavach, a senior cyber-forensics AI auditing Indian internship/job offer documents.

CONTEXT — KNOWN SCAM PATTERNS IN INDIA:
1. CERTIFICATE MILLS (e.g. Prodigy InfoTech, Oasis Infobyte, LetsGrowMore, Internshala-listed unpaid orgs):
   - Offer "virtual internships" with no stipend, no real mentorship.
   - Issue generic completion certificates after 4-8 week unpaid tasks.
   - Mass-mail thousands of identical offers. No CIN / GST / registered address.
   - Violate Indian Apprentices Act 1961 (min stipend rules) & UGC guidelines.
2. PAYMENT-DEMAND SCAMS: registration fee, security deposit, kit charges, ID card fee.
3. FAKE CORPORATE IMPERSONATION: spoofing TCS, Infosys, Amazon HR email domains.

AUDIT THE TERMS STRICTLY:
- Flag unpaid virtual internship mills that provide task lists without real mentorship.
- Check stipend legality under Indian Apprentices Act 1961.
- Identify all monetary demands, suspicious UPI IDs, IFSC codes, and Telegram channels.

Carefully analyse the document text and respond with TWO PARTS:

### Forensic Reasoning
(150-250 words of detailed forensic analysis. Cite exact sentences/phrases.
Identify if this is a certificate mill, payment scam, or corporate impersonation.
State applicable Indian laws: Apprentices Act 1961, BNS §318(4), BNS §336(3), IT Act §66D.)

{json_schema}

DOCUMENT TEXT:
---
{text}
---"""

IMAGE_ANALYSIS_PROMPT = """\
You are InternKavach, a senior cyber-forensics AI auditing Indian internship/job offer documents.

CONTEXT — KNOWN SCAM PATTERNS IN INDIA:
1. CERTIFICATE MILLS (Prodigy InfoTech, Oasis Infobyte, LetsGrowMore, YBI Foundation, etc.):
   - Mass-email identical "virtual internship" offer letters to thousands of students.
   - Unpaid or token Rs.500 stipend. Generic tasks without active senior engineering mentorship.
   - Template letters with low-resolution logos pasted over white backgrounds.
   - No CIN (Company Identification Number) or registered GST number visible.
   - Offer "completion certificate" as the only deliverable — purely resume-padding mills.
   - Violate Indian Apprentices Act 1961 minimum stipend norms and fair labour guidelines.
2. PAYMENT-DEMAND SCAMS: "registration fee", "security deposit", "kit charges", UPI IDs.
3. CORPORATE IMPERSONATION: Fake Amazon/TCS/Infosys letterheads.

YOU ARE AUDITING AN IMAGE OF A SUSPICIOUS OFFER DOCUMENT.

YOUR FORENSIC TASKS:
1. TRANSCRIBE all visible text from the image — word for word.
2. AUDIT THE INTERNSHIP TERMS:
   - Check stipend: Is it unpaid or a negligible token stipend? Flag violations of Apprentices Act 1961.
   - Check mentorship & projects: Are tasks generic or self-guided without active senior engineer mentorship?
   - Check certificate-mill hallmarks: Mass-mailing templates, Prodigy InfoTech / Oasis Infobyte style programs.
3. EXTRACT ALL ENTITIES: Company name, recipient name, role offered, stipend/duration, UPI IDs, IFSC codes.
4. CHECK VISUAL RED FLAGS: Generic template design, pixelated logos, no CIN, mass-mail language.

Respond with TWO PARTS:

### Forensic Reasoning
(150-250 words. Cite exact text you see in the image. State if it matches known Indian scam patterns.
Reference Apprentices Act 1961 and BNS/IT Act where applicable.)

{json_schema}"""

_JSON_SCHEMA = """\
Then output ONLY this JSON (no markdown fences):
{
  "threat_rating": <integer 0-100>,
  "verdict": "<CLEAN | SUSPICIOUS | SCAM>",
  "summary": "<2-3 sentence executive summary>",
  "red_flags": [
    {"flag": "<description>", "severity": "<LOW|MEDIUM|HIGH|CRITICAL>"}
  ],
  "syntax_anomalies": ["<visual/textual anomalies>"],
  "suspicious_clauses": [
    {"clause": "<exact text>", "reason": "<why suspicious>"}
  ],
  "extracted_entities": {
    "company_name": "<string or null>",
    "recipient_name": "<string or null>",
    "claimed_address": "<string or null>",
    "signatory": "<string or null>",
    "role": "<string or null>",
    "stipend": "<string or null>",
    "duration": "<string or null>",
    "monetary_demands": ["<e.g. Registration Fee: Rs.1500>"],
    "upi_ids": ["<UPI IDs found>"],
    "ifsc_codes": ["<IFSC codes found>"],
    "cin_number": "<string or null>",
    "is_certificate_mill": <true|false>
  },
  "impersonated_entity": "<company or null>",
  "scam_category": "<CERTIFICATE_MILL | PAYMENT_SCAM | IMPERSONATION | LEGITIMATE | MIXED>",
  "recommended_sections": ["<BNS/IT Act/Apprentices Act sections>"]
}"""


# ══════════════════════════════════════════════════════════════════════════════
# KEY RESOLUTION & PING HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _resolve_key(runtime_key: str = "") -> str:
    """Return the best available API key. Sidebar > .env > empty."""
    env_key = os.environ.get("GEMINI_API_KEY", "").strip()
    return runtime_key.strip() or env_key or _ENV_API_KEY


def is_gemini_configured(runtime_key: str = "") -> bool:
    """True if SDK installed and a non-empty key is available."""
    return GEMINI_AVAILABLE and bool(_resolve_key(runtime_key))


def ping_gemini(runtime_key: str = "") -> tuple[bool, str]:
    """
    Test request verifying the key against the candidate model cascade.
    Returns (success: bool, working_model_or_error_msg: str).
    """
    key = _resolve_key(runtime_key)
    if not GEMINI_AVAILABLE:
        return False, "google-genai SDK not installed"
    if not key:
        return False, "No API key provided"

    last_err = None
    try:
        client = _genai.Client(api_key=key)
    except Exception as e:
        return False, f"Client init error: {e}"

    for model in CANDIDATE_MODELS:
        try:
            resp = client.models.generate_content(
                model=model,
                contents="Reply with: OK",
                config=_genai_types.GenerateContentConfig(max_output_tokens=5),
            )
            text = _extract_response_text(resp).strip()
            if text:
                return True, model
        except Exception as exc:
            last_err = exc
            err_msg = str(exc).lower()
            if "503" in err_msg or "unavailable" in err_msg or "429" in err_msg:
                time.sleep(1.0)
                continue
            if "404" in err_msg or "not found" in err_msg or "no longer available" in err_msg:
                continue
            continue

    return False, f"API error: {last_err}"


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ══════════════════════════════════════════════════════════════════════════════

def evaluate_document(
    text: str,
    runtime_key: str = "",
) -> Dict[str, Any]:
    """
    Analyse extracted PDF text using the candidate model cascade.
    """
    key = _resolve_key(runtime_key)

    if not GEMINI_AVAILABLE:
        return _mock_analysis(text, reason="google-genai SDK not installed")

    if not key:
        return _mock_analysis(text, reason="No Gemini API key — enter one in the sidebar")

    prompt = TEXT_ANALYSIS_PROMPT.format(
        text=text[:12_000],
        json_schema=_JSON_SCHEMA,
    )
    try:
        return _call_gemini(prompt, source_tag="text", runtime_key=key)
    except Exception as exc:
        return {
            "threat_rating": 50,
            "verdict": "SUSPICIOUS",
            "summary": f"Gemini API Error: {exc}",
            "red_flags": [{"flag": f"Gemini API Error: {exc}", "severity": "HIGH"}],
            "syntax_anomalies": [],
            "suspicious_clauses": [],
            "extracted_entities": {},
            "recommended_sections": [],
            "source": "gemini_error",
            "active_model": None,
            "reasoning": f"### Gemini API Error\n\nThe live Gemini model call failed across all candidate models with the following error:\n\n```\n{exc}\n```\n\nPlease verify your API key, quotas, or network connection.",
            "error": str(exc),
        }


def evaluate_image(
    image_input: Any = None,
    image_bytes: Optional[bytes] = None,
    mime_type: str = "image/png",
    runtime_key: str = "",
) -> Dict[str, Any]:
    """
    Analyse an image directly using candidate vision models.
    Accepts:
      - PIL.Image.Image instance
      - Raw bytes or bytearray
    """
    raw_img = image_input if image_input is not None else image_bytes
    if raw_img is None:
        raise ValueError("No image provided to evaluate_image (pass a PIL Image or bytes)")

    # ── Normalize PIL Image or bytes to bytes ─────────────────────────────────
    if Image is not None and isinstance(raw_img, Image.Image):
        buf = io.BytesIO()
        img_format = "PNG" if raw_img.mode in ("RGBA", "LA", "P") else "JPEG"
        if img_format == "JPEG" and raw_img.mode != "RGB":
            raw_img = raw_img.convert("RGB")
        raw_img.save(buf, format=img_format)
        processed_bytes = buf.getvalue()
        mime_type = "image/png" if img_format == "PNG" else "image/jpeg"
    elif hasattr(raw_img, "save") and callable(getattr(raw_img, "save")):
        buf = io.BytesIO()
        raw_img.save(buf, format="PNG")
        processed_bytes = buf.getvalue()
        mime_type = "image/png"
    elif isinstance(raw_img, (bytes, bytearray)):
        processed_bytes = bytes(raw_img)
    else:
        raise TypeError(f"Expected image to be PIL.Image.Image or bytes, got {type(raw_img)}")

    key = _resolve_key(runtime_key)

    if not GEMINI_AVAILABLE:
        return _mock_analysis("", reason="google-genai SDK not installed")

    if not key:
        return _mock_analysis("", reason="No Gemini API key — enter one in the sidebar to enable vision analysis")

    prompt_text = IMAGE_ANALYSIS_PROMPT.format(json_schema=_JSON_SCHEMA)
    try:
        return _call_gemini_vision(processed_bytes, mime_type, prompt_text, runtime_key=key)
    except Exception as exc:
        return {
            "threat_rating": 50,
            "verdict": "SUSPICIOUS",
            "summary": f"Gemini Vision API Error: {exc}",
            "red_flags": [{"flag": f"Gemini Vision Error: {exc}", "severity": "HIGH"}],
            "syntax_anomalies": [],
            "suspicious_clauses": [],
            "extracted_entities": {},
            "recommended_sections": [],
            "source": "gemini_error",
            "active_model": None,
            "reasoning": f"### Gemini Vision Error\n\nThe multimodal vision call failed across all candidate models with the following error:\n\n```\n{exc}\n```\n\nPlease check your API key, plan limits, or retry in a few moments.",
            "error": str(exc),
        }


# ══════════════════════════════════════════════════════════════════════════════
# INTERNAL — MULTI-MODEL CASCADE WITH RETRY & BACKOFF
# ══════════════════════════════════════════════════════════════════════════════

def _extract_response_text(response: Any) -> str:
    """Safely extract generated text from Gemini response object or candidates."""
    if getattr(response, "text", None):
        return response.text
    if getattr(response, "candidates", None) and response.candidates:
        c = response.candidates[0]
        if getattr(c, "content", None) and getattr(c.content, "parts", None):
            texts = [getattr(p, "text", "") for p in c.content.parts if getattr(p, "text", None)]
            if texts:
                return "".join(texts)
    return ""


def _call_gemini(prompt: str, source_tag: str, runtime_key: str = "") -> Dict[str, Any]:
    """
    Text-only Gemini call cascading through CANDIDATE_MODELS with backoff on 503/429.
    """
    key = _resolve_key(runtime_key)
    client = _genai.Client(api_key=key)
    last_err = None

    for model in CANDIDATE_MODELS:
        try:
            response = client.models.generate_content(
                model=model,
                contents=prompt,
                config=_genai_types.GenerateContentConfig(
                    temperature=0.15,
                    max_output_tokens=2500,
                ),
            )
            resp_text = _extract_response_text(response)
            if resp_text:
                parsed = _parse_response(resp_text, source=f"{model}-{source_tag}")
                parsed["active_model"] = model
                return parsed
        except Exception as exc:
            last_err = exc
            err_msg = str(exc).lower()
            # If 503 UNAVAILABLE or 429, wait 1.5s then try next model
            if "503" in err_msg or "unavailable" in err_msg or "429" in err_msg or "resource_exhausted" in err_msg:
                time.sleep(1.5)
                continue
            # If 404, immediately try next model
            if "404" in err_msg or "not found" in err_msg or "no longer available" in err_msg:
                continue
            time.sleep(0.5)
            continue

    if last_err:
        raise last_err
    raise ValueError("Gemini returned an empty response across all candidate models.")


def _call_gemini_vision(
    image_bytes: bytes,
    mime_type: str,
    prompt_text: str,
    runtime_key: str = "",
) -> Dict[str, Any]:
    """
    Multimodal vision call cascading through CANDIDATE_MODELS with 1.5s backoff on 503/429.
    """
    key = _resolve_key(runtime_key)
    client = _genai.Client(api_key=key)

    image_part = _genai_types.Part.from_bytes(data=image_bytes, mime_type=mime_type)
    text_part  = _genai_types.Part.from_text(text=prompt_text)
    contents = _genai_types.Content(
        role="user",
        parts=[text_part, image_part],
    )
    last_err = None

    for model in CANDIDATE_MODELS:
        try:
            response = client.models.generate_content(
                model=model,
                contents=contents,
                config=_genai_types.GenerateContentConfig(
                    temperature=0.15,
                    max_output_tokens=2500,
                ),
            )
            resp_text = _extract_response_text(response)
            if resp_text:
                parsed = _parse_response(resp_text, source=f"{model}-vision")
                parsed["active_model"] = model
                return parsed
        except Exception as exc:
            last_err = exc
            err_msg = str(exc).lower()
            # If 503 UNAVAILABLE or 429, wait 1.5s then attempt the next model
            if "503" in err_msg or "unavailable" in err_msg or "429" in err_msg or "resource_exhausted" in err_msg:
                time.sleep(1.5)
                continue
            # If 404, immediately try next model
            if "404" in err_msg or "not found" in err_msg or "no longer available" in err_msg:
                continue
            time.sleep(0.5)
            continue

    if last_err:
        raise last_err
    raise ValueError("Gemini vision returned an empty response across all candidate models.")


def _parse_response(raw: str, source: str) -> Dict[str, Any]:
    """Extract ### Forensic Reasoning + JSON from Gemini response."""
    raw = raw.strip()

    # ── Reasoning block ───────────────────────────────────────────────────────
    reasoning = ""
    m = re.search(r"(###\s*Forensic Reasoning.*?)(\{)", raw, re.DOTALL)
    if m:
        reasoning = re.sub(r"^###\s*Forensic Reasoning\s*\n?", "", m.group(1)).strip()

    if not reasoning:
        brace_idx = raw.find("{")
        if brace_idx > 20:
            reasoning = raw[:brace_idx].strip()

    # ── JSON block ────────────────────────────────────────────────────────────
    json_match = re.search(r"(\{[\s\S]+\})", raw)
    if not json_match:
        raise ValueError(
            f"Gemini response contained no JSON block.\n"
            f"Raw response (first 800 chars):\n{raw[:800]}"
        )

    json_str = json_match.group(1)
    json_str = re.sub(r"```\s*$", "", json_str).strip()

    result = json.loads(json_str)
    result["source"]    = source
    result["reasoning"] = reasoning

    # Guarantee all expected keys exist
    result.setdefault("red_flags", [])
    result.setdefault("syntax_anomalies", [])
    result.setdefault("suspicious_clauses", [])
    result.setdefault("recommended_sections", [])
    result.setdefault("impersonated_entity", None)
    result.setdefault("scam_category", None)
    ee = result.setdefault("extracted_entities", {})
    for k in ("company_name","recipient_name","claimed_address","signatory","role",
              "stipend","duration","monetary_demands","upi_ids","ifsc_codes",
              "cin_number","is_certificate_mill"):
        ee.setdefault(k, [] if k in ("monetary_demands","upi_ids","ifsc_codes") else None)

    return result


# ══════════════════════════════════════════════════════════════════════════════
# OFFLINE HEURISTIC FALLBACK
# ══════════════════════════════════════════════════════════════════════════════

def _mock_analysis(text: str, reason: str = "") -> Dict[str, Any]:
    """Keyword-based offline analysis when Gemini is unavailable."""
    from src.forensics.syndicate import CERTIFICATE_MILLS, PAYMENT_SCAM_PHRASES

    text_lower = text.lower()
    score = 0
    red_flags: list = []
    syntax_anomalies: list = []
    suspicious_clauses: list = []
    monetary_demands: list = []
    is_cert_mill = False

    # Certificate mill check
    for mill_name, mill_info in CERTIFICATE_MILLS.items():
        if mill_name.lower() in text_lower:
            is_cert_mill = True
            score += mill_info.get("risk_score", 60)
            red_flags.append({
                "flag": f"Known certificate mill detected: {mill_name}",
                "severity": "HIGH",
            })

    # Payment scam phrases
    for phrase, bump in PAYMENT_SCAM_PHRASES.items():
        if phrase in text_lower:
            score += bump
            sev = "CRITICAL" if bump >= 20 else "HIGH" if bump >= 15 else "MEDIUM"
            red_flags.append({"flag": f"Scam phrase: '{phrase}'", "severity": sev})
            idx = text_lower.find(phrase)
            clause = text[max(0, idx - 30): min(len(text), idx + 80)].strip()
            suspicious_clauses.append({"clause": clause, "reason": f"'{phrase}' is a payment-demand trigger."})
            amt = re.search(r"(?:rs\.?|₹)\s*[\d,]+", clause.lower())
            if amt:
                monetary_demands.append(f"{phrase.title()}: {amt.group()}")

    positive = {
        "annual ctc": -10, "employee id": -8, "provident fund": -10,
        "gratuity": -8, "cin:": -12, "gst:": -8,
    }
    for p, r in positive.items():
        if p in text_lower:
            score += r

    word_count = len(text.split()) if text else 0
    if 0 < word_count < 60:
        score += 15
        syntax_anomalies.append(f"Very short ({word_count} words) for an offer letter.")

    score = max(0, min(100, score))
    verdict = "SCAM" if score >= 70 else "SUSPICIOUS" if score >= 35 else "CLEAN"

    flag_list = ", ".join(
        '"' + r["flag"].replace("Scam phrase: ", "") + '"'
        for r in red_flags[:4]
    )
    reasoning = (
        f"**[Offline Heuristic — {reason}]**\n\n"
        f"Score: **{score}/100**. "
        + (f"Certificate mill pattern detected. " if is_cert_mill else "")
        + (f"Payment-demand phrases found: {flag_list}. " if flag_list else "No high-risk phrases detected. ")
        + "Enter a valid Gemini API key in the sidebar for live AI analysis."
    )

    return {
        "threat_rating": score,
        "verdict": verdict,
        "summary": (
            "Multiple scam indicators detected. Do NOT pay anything." if score >= 70 else
            "Suspicious elements found. Verify independently." if score >= 35 else
            "No obvious red flags detected in text."
        ),
        "red_flags": red_flags,
        "syntax_anomalies": syntax_anomalies,
        "suspicious_clauses": suspicious_clauses[:5],
        "extracted_entities": {
            "company_name": None, "recipient_name": None,
            "claimed_address": None, "signatory": None,
            "role": None, "stipend": None, "duration": None,
            "monetary_demands": monetary_demands,
            "upi_ids": [], "ifsc_codes": [],
            "cin_number": None, "is_certificate_mill": is_cert_mill,
        },
        "impersonated_entity": None,
        "scam_category": "CERTIFICATE_MILL" if is_cert_mill else ("PAYMENT_SCAM" if score >= 40 else None),
        "recommended_sections": (
            ["BNS §318(4) – Cheating", "IT Act §66D", "Apprentices Act 1961"]
            if score >= 40 else []
        ),
        "source": "mock_heuristic",
        "active_model": None,
        "reasoning": reasoning,
        "offline_reason": reason,
    }
