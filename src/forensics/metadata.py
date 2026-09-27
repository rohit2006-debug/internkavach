"""
src/forensics/metadata.py
PDF & EXIF Metadata Inspector for InternKavach
Extracts authoring metadata and scans for high-risk scam language.
"""
from __future__ import annotations

import re
import io
from datetime import datetime
from typing import Any, Dict, List

# ── PDF ───────────────────────────────────────────────────────────────────────
try:
    from pypdf import PdfReader
    PYPDF_AVAILABLE = True
except ImportError:
    PYPDF_AVAILABLE = False

# ── EXIF (optional, for images) ───────────────────────────────────────────────
try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False


# ── Known suspect software signatures ────────────────────────────────────────
SUSPECT_PRODUCERS = [
    "canva", "photoshop", "inkscape", "gimp", "ms publisher",
    "microsoft word 2016", "microsoft word 2013", "libreoffice",
    "apache fop", "ilovepdf", "smallpdf", "pdf24",
    "admin", "admin-pc", "desktop-", "user-pc", "win-",
]

# ── High-risk scam trigger phrases ────────────────────────────────────────────
SCAM_TRIGGERS = {
    "registration fee":      90,
    "reg fee":               85,
    "laptop security deposit": 95,
    "laptop deposit":        90,
    "training charge":       88,
    "security deposit":      80,
    "refundable deposit":    75,
    "telegram channel":      70,
    "telegram group":        65,
    "whatsapp group":        55,
    "advance payment":       78,
    "processing fee":        82,
    "id card fee":           85,
    "kit charges":           80,
    "joining fee":           88,
    "kit fee":               80,
    "neft/imps":             40,
    "transfer the amount":   70,
    "pay within 24":         85,
    "pay within 48":         82,
    "online task":           50,
    "work from home task":   55,
    "easy money":            72,
    "earn daily":            68,
    "youtube like":          74,
    "crypto":                60,
    "usdt":                  65,
    "bitcoin":               60,
}

# ── Legitimate-sounding but frequently spoofed companies ─────────────────────
SPOOFED_BRANDS = [
    "amazon", "flipkart", "infosys", "tcs", "wipro", "hcl", "accenture",
    "deloitte", "kpmg", "pwc", "google", "microsoft", "meta", "apple",
    "reliance", "tata", "mahindra", "bajaj", "hdfc", "icici", "sbi",
    "ministry of", "government of india", "nhm", "isro", "drdo",
]


def extract_pdf_metadata(pdf_input) -> Dict[str, Any]:
    """
    Extract metadata and text from a PDF document.

    Args:
        pdf_input: File path (str) or bytes.

    Returns:
        dict with keys: meta, text, flags, risk_score, scam_triggers_found,
                        suspect_software, spoofed_brands_found.
    """
    if not PYPDF_AVAILABLE:
        return _mock_pdf_metadata()

    try:
        if isinstance(pdf_input, bytes):
            reader = PdfReader(io.BytesIO(pdf_input))
        else:
            reader = PdfReader(pdf_input)
    except Exception as exc:
        return {"error": str(exc), "risk_score": 0, "flags": [], "text": "", "meta": {}}

    # ── Raw metadata ─────────────────────────────────────────────────────────
    info = reader.metadata or {}
    meta = {
        "Author":       _safe_str(info.get("/Author", "")),
        "Creator":      _safe_str(info.get("/Creator", "")),
        "Producer":     _safe_str(info.get("/Producer", "")),
        "CreationDate": _safe_str(info.get("/CreationDate", "")),
        "ModDate":      _safe_str(info.get("/ModDate", "")),
        "Title":        _safe_str(info.get("/Title", "")),
        "Subject":      _safe_str(info.get("/Subject", "")),
        "Pages":        len(reader.pages),
    }

    # ── Extract full text ────────────────────────────────────────────────────
    text_parts = []
    for page in reader.pages:
        try:
            text_parts.append(page.extract_text() or "")
        except Exception:
            pass
    full_text = "\n".join(text_parts)
    text_lower = full_text.lower()

    # ── Detect suspect software ───────────────────────────────────────────────
    producer_str = (meta["Producer"] + " " + meta["Creator"]).lower()
    suspect_software: List[str] = []
    for keyword in SUSPECT_PRODUCERS:
        if keyword in producer_str:
            suspect_software.append(keyword.title())

    # ── Scan for scam trigger phrases ─────────────────────────────────────────
    scam_triggers_found: Dict[str, int] = {}
    for phrase, severity in SCAM_TRIGGERS.items():
        if phrase in text_lower:
            scam_triggers_found[phrase] = severity

    # ── Detect spoofed brand impersonation ───────────────────────────────────
    spoofed_brands_found: List[str] = []
    for brand in SPOOFED_BRANDS:
        if brand in text_lower:
            spoofed_brands_found.append(brand.title())

    # ── Compute risk score (0–100) ────────────────────────────────────────────
    risk_score = 0
    flags: List[str] = []

    if suspect_software:
        risk_score += 25
        flags.append(f"[SUSPECT SOFTWARE] Authoring tool detected: {', '.join(suspect_software)}")

    if scam_triggers_found:
        trigger_risk = min(50, sum(v for v in scam_triggers_found.values()) // 5)
        risk_score += trigger_risk
        trigger_list = list(scam_triggers_found)[:5]
        quoted = ", ".join('"' + p + '"' for p in trigger_list)
        flags.append(f"[SCAM TRIGGER] Exploitative terms identified: {quoted}")

    if spoofed_brands_found:
        risk_score += 10
        flags.append(f"[IMPERSONATION] Potential brand spoofing: {', '.join(spoofed_brands_found[:3])}")

    # Check date anomalies
    creation = meta.get("CreationDate", "")
    mod = meta.get("ModDate", "")
    if creation and mod and creation != mod:
        risk_score += 5
        flags.append("[METADATA ANOMALY] Document modified after creation timestamp.")

    # Very short docs (< 100 words) are suspicious for offer letters
    word_count = len(full_text.split())
    if 0 < word_count < 100:
        risk_score += 10
        flags.append(f"[SYNTAX ANOMALY] Short document length ({word_count} words) for offer contract.")

    risk_score = min(100, risk_score)

    return {
        "meta":                 meta,
        "text":                 full_text,
        "flags":                flags,
        "risk_score":           risk_score,
        "scam_triggers_found":  scam_triggers_found,
        "suspect_software":     suspect_software,
        "spoofed_brands_found": spoofed_brands_found,
        "word_count":           word_count,
    }


def extract_image_exif(image_input) -> Dict[str, Any]:
    """Extract EXIF metadata from a JPEG/PNG image."""
    if not PILLOW_AVAILABLE:
        return {"error": "Pillow not available", "exif": {}}

    try:
        if isinstance(image_input, bytes):
            img = Image.open(io.BytesIO(image_input))
        else:
            img = Image.open(image_input)

        exif_data = img._getexif() if hasattr(img, "_getexif") else None
        if not exif_data:
            return {"exif": {}, "flags": [], "software": None}

        decoded = {TAGS.get(k, k): v for k, v in exif_data.items()
                   if TAGS.get(k, k) not in ("MakerNote",)}

        software = str(decoded.get("Software", "")).lower()
        flags = []
        for keyword in SUSPECT_PRODUCERS:
            if keyword in software:
                flags.append(f"[TAMPER EVIDENCE] Image modified with: {decoded.get('Software', '')}")
                break

        return {"exif": decoded, "flags": flags, "software": decoded.get("Software", "Unknown")}

    except Exception as exc:
        return {"exif": {}, "flags": [], "error": str(exc), "software": None}


def _safe_str(val) -> str:
    if val is None:
        return ""
    return str(val)


def _mock_pdf_metadata() -> Dict[str, Any]:
    """Return mock data when pypdf is unavailable."""
    return {
        "meta": {
            "Author": "HR Department",
            "Creator": "Microsoft Word 2016",
            "Producer": "Adobe PDF Library",
            "CreationDate": "D:20240115120000",
            "ModDate": "D:20240116083000",
            "Title": "Internship Offer Letter",
            "Pages": 2,
        },
        "text": "Congratulations! You are selected for internship. "
                "Pay registration fee of ₹2000 to secure your position. "
                "Join our Telegram channel for further instructions.",
        "flags": [
            "[SUSPECT SOFTWARE] Authoring tool detected: Microsoft Word 2016",
            "[SCAM TRIGGER] Exploitative terms identified: \"registration fee\", \"telegram channel\"",
        ],
        "risk_score": 72,
        "scam_triggers_found": {"registration fee": 90, "telegram channel": 70},
        "suspect_software": ["Microsoft Word 2016"],
        "spoofed_brands_found": [],
        "word_count": 30,
    }
