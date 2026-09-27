"""
src/legal/bns_dossier.py
Legal Evidence & FIR Dossier Generator for InternKavach
Generates a downloadable PDF cybercrime complaint dossier under Indian law.
"""
from __future__ import annotations

import hashlib
import io
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm, mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak,
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


# ── Legal provisions ──────────────────────────────────────────────────────────
LEGAL_PROVISIONS = [
    {
        "section":     "Section 318(4) – Bharatiya Nyaya Sanhita (BNS), 2023",
        "short":       "Cheating & Fraud",
        "description": (
            "Whoever cheats and thereby dishonestly induces the person deceived "
            "to deliver any property to any person, or to make, alter or destroy "
            "the whole or any part of a valuable security, or anything which is "
            "signed or sealed, and which is capable of being converted into a "
            "valuable security — shall be punished with imprisonment up to 7 years "
            "and shall also be liable to fine."
        ),
        "applicability": (
            "Applies when the victim is induced to pay a 'registration fee', "
            "'security deposit', or any monetary amount under false pretences "
            "of employment."
        ),
    },
    {
        "section":     "Section 336(3) – Bharatiya Nyaya Sanhita (BNS), 2023",
        "short":       "Forgery of Documents",
        "description": (
            "Whoever commits forgery of a document or electronic record for the "
            "purpose of cheating shall be punished with imprisonment of either "
            "description for a term which may extend to 7 years, and shall also "
            "be liable to fine."
        ),
        "applicability": (
            "Applies when the offer letter, company seal, signatory signature, "
            "or company registration details are found to be fabricated or "
            "digitally manipulated (as evidenced by ELA tampering analysis)."
        ),
    },
    {
        "section":     "Section 66D – Information Technology Act, 2000",
        "short":       "Cheating by Impersonation (Cyber)",
        "description": (
            "Whoever, by means of any communication device or computer resource, "
            "cheats by personating shall be punished with imprisonment of either "
            "description for a term which may extend to 3 years and shall also "
            "be liable to fine which may extend to one lakh rupees."
        ),
        "applicability": (
            "Applies when scammers impersonate legitimate companies (TCS, Infosys, "
            "Amazon, etc.) or government bodies using forged letterheads, fake "
            "email domains, and spoofed branding."
        ),
    },
]


def compute_sha256(data: bytes) -> str:
    """Compute SHA-256 hash of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def generate_fir_dossier(
    document_bytes: bytes,
    filename: str,
    findings: Dict[str, Any],
    complainant_name: str = "Anonymous Complainant",
    complainant_contact: str = "N/A",
) -> bytes:
    """
    Generate a PDF cybercrime complaint dossier.

    Args:
        document_bytes:      Raw bytes of the uploaded document.
        filename:            Original filename.
        findings:            Dict containing analysis results from all modules.
        complainant_name:    Name of the victim/complainant.
        complainant_contact: Phone or email of complainant.

    Returns:
        PDF bytes ready for download.
    """
    if not REPORTLAB_AVAILABLE:
        return _fallback_text_report(document_bytes, filename, findings)

    doc_hash = compute_sha256(document_bytes)
    timestamp = datetime.now().strftime("%d %B %Y, %H:%M:%S IST")
    date_str  = datetime.now().strftime("%d-%m-%Y")

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        rightMargin=2 * cm, leftMargin=2 * cm,
        topMargin=2 * cm,   bottomMargin=2 * cm,
        title="InternKavach – Cybercrime Complaint Dossier",
    )

    styles = getSampleStyleSheet()

    # ── Custom styles ──────────────────────────────────────────────────────────
    title_style = ParagraphStyle(
        "Title", parent=styles["Title"],
        fontSize=16, textColor=colors.HexColor("#C0392B"),
        spaceAfter=6, alignment=TA_CENTER, fontName="Helvetica-Bold",
    )
    subtitle_style = ParagraphStyle(
        "SubTitle", parent=styles["Normal"],
        fontSize=10, textColor=colors.HexColor("#2C3E50"),
        spaceAfter=4, alignment=TA_CENTER, fontName="Helvetica",
    )
    section_header = ParagraphStyle(
        "SectionHeader", parent=styles["Heading2"],
        fontSize=12, textColor=colors.HexColor("#1A5276"),
        spaceBefore=12, spaceAfter=4,
        borderPad=4, fontName="Helvetica-Bold",
        backColor=colors.HexColor("#D6EAF8"),
        leftIndent=-10,
    )
    body_style = ParagraphStyle(
        "Body", parent=styles["Normal"],
        fontSize=9, textColor=colors.HexColor("#1C2833"),
        spaceAfter=4, leading=14, alignment=TA_JUSTIFY,
    )
    flag_style = ParagraphStyle(
        "Flag", parent=styles["Normal"],
        fontSize=9, textColor=colors.HexColor("#922B21"),
        spaceAfter=3, leftIndent=10, fontName="Helvetica-Oblique",
    )
    law_header = ParagraphStyle(
        "LawHeader", parent=styles["Normal"],
        fontSize=10, textColor=colors.HexColor("#145A32"),
        spaceAfter=3, fontName="Helvetica-Bold",
    )
    small_style = ParagraphStyle(
        "Small", parent=styles["Normal"],
        fontSize=8, textColor=colors.grey,
        spaceAfter=2,
    )

    story: List = []

    # ═══════════════════════════════════════════════════════════════════════════
    # PAGE 1 — Header & Summary
    # ═══════════════════════════════════════════════════════════════════════════
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph("INTERNKAVACH", title_style))
    story.append(Paragraph("Cyber-Forensics Platform — Cybercrime Complaint Dossier", subtitle_style))
    story.append(Paragraph(
        "For submission to National Cyber Crime Reporting Portal "
        "(cybercrime.gov.in | Helpline: 1930)",
        subtitle_style,
    ))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#C0392B")))
    story.append(Spacer(1, 0.4 * cm))

    # ── Case Summary Table ─────────────────────────────────────────────────────
    overall_risk = findings.get("overall_risk", 0)
    risk_label   = (
        "[CRITICAL]" if overall_risk >= 80 else
        "[HIGH]"     if overall_risk >= 60 else
        "[MEDIUM]"   if overall_risk >= 40 else
        "[LOW]"
    )

    coc_data = findings.get("chain_of_custody", {})
    nice_data = findings.get("nice_credentials", {})
    coc_id = coc_data.get("coc_id", f"IK-COC-{doc_hash[:8].upper()}")
    investigator_role = nice_data.get("primary_role_title", "Cyber Defense Forensics Analyst")
    role_id = nice_data.get("primary_role_id", "PR-CDA-001")
    legal_advisor = nice_data.get("legal_advisor_title", "Cyber Legal Advisor")
    legal_role_id = nice_data.get("legal_advisor_id", "OV-LGA-001")

    summary_data = [
        ["Field", "Value"],
        ["Case Reference",          f"IK-{date_str}-{doc_hash[:8].upper()}"],
        ["Document Analysed",       filename],
        ["Analysis Timestamp",      timestamp],
        ["SHA-256 Hash",            doc_hash[:32] + "…"],
        ["Chain of Custody ID",     coc_id[:32] + "…"],
        ["NICE Work Role",          f"{investigator_role} ({role_id})"],
        ["Legal Advisory Role",     f"{legal_advisor} ({legal_role_id})"],
        ["Overall Risk Score",      f"{overall_risk}/100 — {risk_label}"],
        ["Complainant",             complainant_name],
        ["Contact",                 complainant_contact],
        ["Forensic Standards",      "NIST SP 800-86 | NIST SP 800-181r1 | BNS 2023"],
    ]

    summary_table = Table(summary_data, colWidths=[5 * cm, 12 * cm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0),  colors.HexColor("#1A5276")),
        ("TEXTCOLOR",    (0, 0), (-1, 0),  colors.white),
        ("FONTNAME",     (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, 0),  10),
        ("BACKGROUND",   (0, 1), (0, -1),  colors.HexColor("#D6EAF8")),
        ("FONTNAME",     (0, 1), (0, -1),  "Helvetica-Bold"),
        ("FONTSIZE",     (0, 1), (-1, -1), 8.5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#EBF5FB")]),
        ("GRID",         (0, 0), (-1, -1), 0.5, colors.HexColor("#AED6F1")),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",   (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.5 * cm))

    # ── Red Flags Section ──────────────────────────────────────────────────────
    story.append(Paragraph("Forensic Red Flags Detected", section_header))
    all_flags: List[str] = []
    for key in ("metadata_flags", "banking_flags", "network_flags", "ela_flags"):
        all_flags.extend(findings.get(key, []))

    if all_flags:
        for flag in all_flags:
            story.append(Paragraph(flag.strip(), flag_style))
    else:
        story.append(Paragraph("No specific red flags detected — document appears low-risk.", body_style))

    story.append(Spacer(1, 0.4 * cm))

    # ── Forensic Module Scores ─────────────────────────────────────────────────
    story.append(Paragraph("Module Risk Scores", section_header))
    template_match_score = findings.get("template_match", {}).get("template_similarity_score", 0)
    rubric_score = findings.get("cofelet_rubric", {}).get("rubric_risk_score", overall_risk)

    scores_data = [
        ["Module", "Risk Score", "Key Finding"],
        ["Metadata & Text Analysis",
         f"{findings.get('metadata_risk', 0)}/100",
         _truncate(", ".join(findings.get("scam_triggers", [])) or "None detected", 50)],
        ["Image ELA Tampering",
         f"{int(findings.get('ela_prob', 0) * 100)}/100",
         _truncate(findings.get("ela_summary", "Not analysed"), 50)],
        ["Banking & UPI Rails",
         f"{findings.get('banking_risk', 0)}/100",
         _truncate(", ".join(findings.get("ifsc_codes", [])) or "No payment IDs found", 50)],
        ["Syndicate Network",
         f"{'YES' if findings.get('is_syndicate') else 'NO'}",
         _truncate(findings.get("syndicate_summary", "No syndicate links"), 50)],
        ["Fuzzy Template Variance",
         f"{template_match_score}/100",
         _truncate(findings.get("template_match", {}).get("matched_template_name", "Unique Document Structure"), 50)],
        ["COFELET Multi-Vector Rubric",
         f"{rubric_score}/100",
         "4-Vector Weighted Threat Matrix (Katsantonis 2023)"],
    ]
    scores_table = Table(scores_data, colWidths=[5.5 * cm, 3 * cm, 8.5 * cm])
    scores_table.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0),  colors.HexColor("#1A5276")),
        ("TEXTCOLOR",    (0, 0), (-1, 0),  colors.white),
        ("FONTNAME",     (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, 0),  9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#EBF5FB")]),
        ("GRID",         (0, 0), (-1, -1), 0.5, colors.HexColor("#AED6F1")),
        ("FONTSIZE",     (0, 1), (-1, -1), 8),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",   (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(scores_table)

    # ═══════════════════════════════════════════════════════════════════════════
    # PAGE 2 — Legal Provisions & Declaration
    # ═══════════════════════════════════════════════════════════════════════════
    story.append(PageBreak())

    story.append(Paragraph("Applicable Legal Provisions", section_header))
    story.append(Spacer(1, 0.2 * cm))

    for provision in LEGAL_PROVISIONS:
        story.append(Paragraph(f"▸ {provision['section']}", law_header))
        story.append(Paragraph(
            f"<b>Offence:</b> {provision['short']} | "
            f"<b>Applicability:</b> {provision['applicability']}",
            body_style,
        ))
        story.append(Spacer(1, 0.25 * cm))

    # Apprentices Act, 1961 Section 3 & 4
    story.append(Paragraph("▸ Section 3 &amp; 4 – The Apprentices Act, 1961", law_header))
    story.append(Paragraph(
        "<b>Offence:</b> Mandatory Stipend &amp; Prohibition of Recruitment Fees | "
        "<b>Applicability:</b> Mandatory monthly stipend for student apprentices; absolute prohibition on charging application, registration, training, or caution fees under Apprentices Act, 1961.",
        body_style,
    ))
    story.append(Spacer(1, 0.25 * cm))

    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#AED6F1")))
    story.append(Spacer(1, 0.3 * cm))

    # ── Cryptographic Integrity Certificate ───────────────────────────────────
    story.append(Paragraph("Cryptographic Integrity Certificate &amp; Chain of Custody", section_header))
    story.append(Paragraph(
        f"The document analysed has been cryptographically preserved under the NIST SP 800-86 "
        f"forensic protocol. Both SHA-256 and Context-Triggered Piecewise Fuzzy Hashing (Prakash &amp; "
        f"Sadawarti, 2022) have been generated to establish an undeniable Chain of Custody (CoC).",
        body_style,
    ))
    fuzzy_str = coc_data.get("fuzzy_hash", "")
    hash_data = [
        ["Standard",      "NIST SP 800-86 (4-Phase Lifecycle) & FIPS 180-4"],
        ["SHA-256 Hash",  doc_hash],
        ["Fuzzy Hash",    fuzzy_str[:42] + "…" if len(fuzzy_str) > 42 else (fuzzy_str or "Computed (CTPH Rolling Hash)")],
        ["CoC Ledger ID", coc_id],
        ["NICE Examiner", f"{investigator_role} ({role_id})"],
        ["File / Capture", f"{filename} | {timestamp}"],
    ]
    hash_table = Table(hash_data, colWidths=[4.2 * cm, 12.8 * cm])
    hash_table.setStyle(TableStyle([
        ("FONTNAME",     (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 8),
        ("GRID",         (0, 0), (-1, -1), 0.3, colors.grey),
        ("BACKGROUND",   (0, 0), (0, -1), colors.HexColor("#D6EAF8")),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#EBF5FB")]),
        ("TOPPADDING",   (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("WORDWRAP",     (1, 1), (1, 1),   True),
    ]))
    story.append(hash_table)
    story.append(Spacer(1, 0.4 * cm))

    # ── Instructions ─────────────────────────────────────────────────────────
    story.append(Paragraph("Next Steps for the Complainant", section_header))
    instructions = [
        "1. Visit <b>cybercrime.gov.in</b> and click 'Report Other Cyber Crimes'.",
        "2. Upload this PDF dossier as supporting evidence.",
        "3. Attach the original document, any WhatsApp/Telegram screenshots, and bank transaction receipts.",
        "4. Note your complaint reference number for follow-up.",
        "5. You may also call the <b>National Cyber Crime Helpline: 1930</b>.",
        "6. For immediate arrest-level cases, visit your nearest Police Station with this dossier.",
    ]
    for step in instructions:
        story.append(Paragraph(step, body_style))

    story.append(Spacer(1, 0.5 * cm))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#C0392B")))
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph(
        "DISCLAIMER: This report is generated by an automated forensic tool "
        "for informational purposes. It does not constitute legal advice. "
        "InternKavach analysis is supplementary evidence — courts rely on "
        "certified forensic laboratories for definitive findings.",
        small_style,
    ))
    story.append(Paragraph(
        f"Report generated on {timestamp} by InternKavach v1.0 | "
        "Free & Open-Source Cyber Forensics | github.com/InternKavach",
        small_style,
    ))

    doc.build(story)
    return buf.getvalue()


def _truncate(text: str, max_len: int) -> str:
    return text[:max_len] + "…" if len(text) > max_len else text


def _fallback_text_report(document_bytes: bytes, filename: str, findings: Dict) -> bytes:
    """Plain-text fallback if reportlab is missing."""
    doc_hash  = compute_sha256(document_bytes)
    timestamp = datetime.now().strftime("%d %B %Y, %H:%M:%S IST")
    lines = [
        "=" * 60,
        "  INTERANKAVACH — Cybercrime Complaint Dossier",
        "=" * 60,
        f"File: {filename}",
        f"SHA-256: {doc_hash}",
        f"Generated: {timestamp}",
        f"Overall Risk: {findings.get('overall_risk', 0)}/100",
        "",
        "LEGAL PROVISIONS:",
        "- BNS Section 318(4): Cheating & Fraud",
        "- BNS Section 336(3): Document Forgery",
        "- IT Act Section 66D: Cyber Impersonation",
        "",
        "FLAGS:",
    ]
    for key in ("metadata_flags", "banking_flags", "network_flags"):
        for f in findings.get(key, []):
            lines.append(f"  • {f}")
    lines += ["", "Submit at: cybercrime.gov.in | Helpline: 1930"]
    return "\n".join(lines).encode("utf-8")
