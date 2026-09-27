"""
src/ai/document_classifier.py
Pre-flight Document Classification Gatekeeper for InternKavach
─────────────────────────────────────────────────────────────
• Audits uploaded documents before forensic pipeline execution.
• Strictly accepts:
    - Internship Offer Letters
    - Job Offer Letters
    - Appointment Letters / Employment Contracts
    - Recruitment Selection Emails / Formal Hiring Communications
    - Training & Apprenticeship Agreements
• Rejects non-recruitment documents (Resumes, IDs, Utility Bills, Syllabus, Memes, Photos).
• Multi-model fallback cascade with backoff on 503/429.
• Offline heuristic keyword fallback.
• Extensible routing structure for future pipelines (e.g. loan scams, police summons).
"""
from __future__ import annotations

import io
import json
import os
import re
import time
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

try:
    from PIL import Image
except ImportError:
    Image = None

# ── Load .env if present ──────────────────────────────────────────────────────
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

# Model cascade matching agent_evaluator
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
# EXTENSIBILITY FOUNDATION: DOCUMENT CATEGORIES & ROUTING
# ══════════════════════════════════════════════════════════════════════════════

class DocumentCategory(str, Enum):
    """Taxonomy of document types for pre-flight routing."""
    OFFER_LETTER = "Offer Letter"
    APPOINTMENT_LETTER = "Appointment Letter"
    RECRUITMENT_COMMUNICATION = "Recruitment Message / Email"
    TRAINING_AGREEMENT = "Training / Apprenticeship Agreement"
    RESUME_CV = "Resume / CV"
    IDENTITY_DOCUMENT = "College ID / Government ID"
    UTILITY_BILL = "Utility Bill / Invoice"
    ACADEMIC_DOCUMENT = "Academic Notes / Syllabus"
    CASUAL_CHAT_OR_MEME = "Casual Chat / Meme"
    RANDOM_PHOTO = "Random Photo"
    LOAN_APPROVAL_NOTICE = "Loan Approval Notice"
    POLICE_SUMMONS = "Cyber Police / Court Summons"
    OTHER_NON_RECRUITMENT = "Non-Recruitment Document"


# Routing table mapping detected category to the active forensic pipeline
PIPELINE_ROUTES: Dict[str, str] = {
    DocumentCategory.OFFER_LETTER.value: "internship_fraud_pipeline",
    DocumentCategory.APPOINTMENT_LETTER.value: "internship_fraud_pipeline",
    DocumentCategory.RECRUITMENT_COMMUNICATION.value: "internship_fraud_pipeline",
    DocumentCategory.TRAINING_AGREEMENT.value: "internship_fraud_pipeline",
    # Extensible future routes:
    DocumentCategory.LOAN_APPROVAL_NOTICE.value: "loan_fraud_pipeline",
    DocumentCategory.POLICE_SUMMONS.value: "legal_summons_pipeline",
}


def get_pipeline_route(detected_type: str) -> Optional[str]:
    """Retrieve the forensic pipeline associated with a detected document type."""
    for key, pipeline in PIPELINE_ROUTES.items():
        if key.lower() in detected_type.lower() or detected_type.lower() in key.lower():
            return pipeline
    return None


def is_recruitment_category(detected_type: str) -> bool:
    """Check if the detected document type belongs to the recruitment domain."""
    recruitment_classes = [
        "offer letter",
        "internship",
        "appointment",
        "recruitment",
        "employment",
        "training agreement",
        "job offer",
        "hiring",
    ]
    det_lower = detected_type.lower()
    return any(rc in det_lower for rc in recruitment_classes)


# ══════════════════════════════════════════════════════════════════════════════
# GATEKEEPER PROMPT
# ══════════════════════════════════════════════════════════════════════════════

CLASSIFICATION_PROMPT = """\
You are InternKavach Pre-flight Document Gatekeeper.
Your sole job is to classify the uploaded document into its category and determine if it is an
EMPLOYMENT / RECRUITMENT document intended for a candidate.

ELIGIBLE RECRUITMENT DOCUMENTS (Accept: is_recruitment_document = true):
- Internship Offer Letter
- Full-time / Part-time Job Offer Letter
- Letter of Appointment / Employment Contract
- Recruitment Selection Email / Official Hiring Message
- Training & Internship Agreement
- Internship Task/Project Assignment Letter from an employer

INELIGIBLE DOCUMENTS (Reject: is_recruitment_document = false):
- Resume / CV (applicant profile resumes are NOT offer letters)
- College Student ID Card, Aadhaar Card, PAN Card, Driver's License, Govt IDs
- Electricity Bills, Water Bills, Gas Bills, Broadband Invoices, Receipts
- Academic Syllabus, Course Curriculum, Lecture Notes, Study Material, Question Papers
- Casual WhatsApp/Telegram personal chats, memes, social media screenshots, selfies
- Random photos, landscapes, personal screenshots, artwork
- Loan notices, bank account statements, tax forms, police notices

Respond with ONLY a raw JSON object (no markdown formatting, no fences):
{
  "is_recruitment_document": true or false,
  "detected_type": "<e.g. 'Offer Letter', 'Resume / CV', 'College ID / Government ID', 'Utility Bill', 'Academic Notes', 'Casual Chat / Meme', 'Random Photo'>",
  "confidence": <float between 0.0 and 1.0>,
  "rejection_reason": "<1-2 concise sentences explaining why this document cannot be audited as an offer letter, or null if accepted>"
}"""


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC GATEKEEPER API
# ══════════════════════════════════════════════════════════════════════════════

def classify_document_type(
    file_bytes: bytes,
    mime_type: str = "application/pdf",
    api_key: str = "",
    text_content: str = "",
) -> Dict[str, Any]:
    """
    Pre-flight document classifier. Inspects file bytes and metadata to verify
    whether the document is an internship/job offer before running forensic pipelines.

    Args:
        file_bytes:   Raw bytes of the uploaded file.
        mime_type:    MIME type ("application/pdf", "image/png", "image/jpeg").
        api_key:      Optional runtime Gemini API key (sidebar or env).
        text_content: Optional pre-extracted text from the document.

    Returns:
        Dict adhering to:
        {
            "is_recruitment_document": bool,
            "detected_type": str,
            "confidence": float,
            "rejection_reason": str | None,
            "pipeline_route": str | None,
            "source": str
        }
    """
    key = api_key.strip() or os.environ.get("GEMINI_API_KEY", "").strip()

    # If Gemini is available and key is configured, use multimodal AI classification
    if GEMINI_AVAILABLE and key:
        try:
            result = _classify_with_gemini(file_bytes, mime_type, key)
            result["pipeline_route"] = get_pipeline_route(result.get("detected_type", ""))
            return result
        except Exception:
            # Fall back to heuristic on failure without crashing
            pass

    # Heuristic offline classification
    result = _heuristic_classify(file_bytes, mime_type, text_content=text_content)
    result["pipeline_route"] = get_pipeline_route(result.get("detected_type", ""))
    return result


# ══════════════════════════════════════════════════════════════════════════════
# GEMINI MULTIMODAL CLASSIFIER WITH CASCADE & BACKOFF
# ══════════════════════════════════════════════════════════════════════════════

def _classify_with_gemini(file_bytes: bytes, mime_type: str, api_key: str) -> Dict[str, Any]:
    """Classify document via Gemini candidate model cascade."""
    client = _genai.Client(api_key=api_key)

    # Normalize image or PDF part
    effective_mime = mime_type
    if "image" in mime_type:
        effective_mime = "image/png" if "png" in mime_type.lower() else "image/jpeg"
    elif "pdf" in mime_type.lower():
        effective_mime = "application/pdf"

    doc_part = _genai_types.Part.from_bytes(data=file_bytes, mime_type=effective_mime)
    text_part = _genai_types.Part.from_text(text=CLASSIFICATION_PROMPT)
    contents = _genai_types.Content(role="user", parts=[text_part, doc_part])

    last_err = None
    for model in CANDIDATE_MODELS:
        try:
            response = client.models.generate_content(
                model=model,
                contents=contents,
                config=_genai_types.GenerateContentConfig(
                    temperature=0.1,
                    max_output_tokens=600,
                ),
            )
            raw_text = _extract_text(response)
            if raw_text:
                parsed = _parse_json(raw_text)
                parsed["source"] = f"{model}-classifier"
                return parsed
        except Exception as exc:
            last_err = exc
            err_msg = str(exc).lower()
            if "503" in err_msg or "unavailable" in err_msg or "429" in err_msg:
                time.sleep(1.5)
                continue
            if "404" in err_msg or "not found" in err_msg or "no longer available" in err_msg:
                continue
            time.sleep(0.5)
            continue

    raise last_err or RuntimeError("Classification failed across all candidate models.")


def _extract_text(response: Any) -> str:
    """Extract plain text from Gemini response object."""
    if getattr(response, "text", None):
        return response.text
    if getattr(response, "candidates", None) and response.candidates:
        c = response.candidates[0]
        if getattr(c, "content", None) and getattr(c.content, "parts", None):
            texts = [getattr(p, "text", "") for p in c.content.parts if getattr(p, "text", None)]
            if texts:
                return "".join(texts)
    return ""


def _parse_json(raw_text: str) -> Dict[str, Any]:
    """Clean and parse JSON from model response."""
    cleaned = raw_text.strip()
    # Strip markdown code blocks if present
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
    cleaned = re.sub(r"\s*```$", "", cleaned)

    match = re.search(r"(\{[\s\S]+\})", cleaned)
    if match:
        data = json.loads(match.group(1))
        return {
            "is_recruitment_document": bool(data.get("is_recruitment_document", False)),
            "detected_type": str(data.get("detected_type", "Unknown Document")),
            "confidence": float(data.get("confidence", 0.85)),
            "rejection_reason": data.get("rejection_reason") if not data.get("is_recruitment_document") else None,
        }
    raise ValueError(f"No JSON found in classifier output: {raw_text[:200]}")


# ══════════════════════════════════════════════════════════════════════════════
# HEURISTIC OFFLINE CLASSIFICATION
# ══════════════════════════════════════════════════════════════════════════════

def _heuristic_classify(file_bytes: bytes, mime_type: str, text_content: str = "") -> Dict[str, Any]:
    """
    Offline heuristic classifier based on keywords, structural cues, and metadata.
    """
    extracted_text = text_content

    # If text is empty and file is PDF, extract via pypdf
    if not extracted_text and "pdf" in mime_type.lower():
        try:
            from pypdf import PdfReader
            reader = PdfReader(io.BytesIO(file_bytes))
            extracted_text = "\n".join(page.extract_text() or "" for page in reader.pages)
        except Exception:
            extracted_text = ""

    text_lower = extracted_text.lower() if extracted_text else ""

    # Recruitment keywords & patterns
    recruitment_indicators = [
        "offer letter", "internship offer", "pleased to offer", "appointment letter",
        "stipend", "internship", "employment offer", "congratulations on your selection",
        "joining date", "reporting date", "annual ctc", "terms of employment",
        "intern role", "training agreement", "we are pleased to invite", "job offer",
        "we are offering you", "selected for the role", "position of", "hiring",
        "prodigy infotech", "oasis infobyte", "letsgrowmore", "codsoft",
    ]

    # Non-recruitment categories
    resume_indicators = [
        "curriculum vitae", "resume", "career objective", "education:",
        "academic background", "work experience:", "technical skills:",
        "projects:", "hobbies:", "declaration:"
    ]
    academic_indicators = [
        "syllabus", "semester", "course curriculum", "unit i", "unit ii",
        "lecture notes", "question paper", "examination", "marksheet",
    ]
    utility_indicators = [
        "electricity bill", "water bill", "consumer no", "meter reading",
        "bill amount", "due date", "tax invoice", "subtotal", "gstin:"
    ]
    id_indicators = [
        "identity card", "student id", "enrollment no", "aadhaar", "pan card",
        "date of birth", "valid up to", "emergency contact",
    ]

    # Score each category
    recruitment_score = sum(1 for kw in recruitment_indicators if kw in text_lower)
    resume_score = sum(1 for kw in resume_indicators if kw in text_lower)
    academic_score = sum(1 for kw in academic_indicators if kw in text_lower)
    utility_score = sum(1 for kw in utility_indicators if kw in text_lower)
    id_score = sum(1 for kw in id_indicators if kw in text_lower)

    # If text is present, make heuristic decision
    if text_lower.strip():
        # Check strong non-recruitment indicators first
        if resume_score >= 3 and recruitment_score < 2:
            return {
                "is_recruitment_document": False,
                "detected_type": "Resume / CV",
                "confidence": 0.85,
                "rejection_reason": "The uploaded file appears to be a Resume/CV rather than an employment or internship offer letter.",
                "source": "heuristic",
            }
        if academic_score >= 2 and recruitment_score == 0:
            return {
                "is_recruitment_document": False,
                "detected_type": "Academic Notes / Syllabus",
                "confidence": 0.90,
                "rejection_reason": "The uploaded document contains academic syllabus or course notes, not an offer letter.",
                "source": "heuristic",
            }
        if utility_score >= 2 and recruitment_score == 0:
            return {
                "is_recruitment_document": False,
                "detected_type": "Utility Bill / Invoice",
                "confidence": 0.90,
                "rejection_reason": "The uploaded document appears to be a bill or invoice, not an employment offer.",
                "source": "heuristic",
            }
        if id_score >= 2 and recruitment_score == 0:
            return {
                "is_recruitment_document": False,
                "detected_type": "College ID / Government ID",
                "confidence": 0.85,
                "rejection_reason": "The uploaded file is an identity card rather than an internship or job offer.",
                "source": "heuristic",
            }

        # Check recruitment indicators
        if recruitment_score >= 1:
            detected = "Offer Letter" if "offer" in text_lower else "Appointment Letter"
            return {
                "is_recruitment_document": True,
                "detected_type": detected,
                "confidence": 0.80,
                "rejection_reason": None,
                "source": "heuristic",
            }

    # For images where OCR text wasn't extracted in offline mode, verify basic image validity
    if "image" in mime_type.lower():
        # Without Gemini API key, we give benefit of the doubt to image documents
        # unless identified otherwise, but advise connecting the API key for strict filtering.
        return {
            "is_recruitment_document": True,
            "detected_type": "Offer Letter (Unverified Image)",
            "confidence": 0.60,
            "rejection_reason": None,
            "source": "heuristic-permissive",
        }

    # Default reject if empty/unclassifiable
    return {
        "is_recruitment_document": False,
        "detected_type": "Non-Recruitment Document",
        "confidence": 0.70,
        "rejection_reason": "No recruitment or offer letter keywords (offer, internship, stipend, appointment) were found in this document.",
        "source": "heuristic",
    }
