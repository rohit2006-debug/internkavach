"""
src/forensics/nist_pipeline.py
NIST SP 800-86 Forensic Ingestion Pipeline for InternKavach.
Implements the 4-Phase Digital Forensics Lifecycle:
Phase 1: Collection — Byte stream preservation, SHA-256 & MD5 hashing, session telemetry.
Phase 2: Examination — Magic-byte header verification, extension spoofing detection, metadata MAC timestamps.
Phase 3: Analysis — Multimodal clause evaluation, ELA pixel variance, banking/IFSC route math, CTPH fuzzy template similarity.
Phase 4: Reporting — COFELET dynamic rubric scoring, NICE role credentialing, certified FIR PDF synthesis.
"""
from __future__ import annotations

import hashlib
import io
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.ai.agent_evaluator import evaluate_document, evaluate_image
from src.ai.document_classifier import classify_document_type
from src.ai.rubric_engine import evaluate_cofelet_rubric
from src.forensics.banking import assess_banking_risk, resolve_banking_route
from src.forensics.ela import generate_ela_heatmap
from src.forensics.fuzzy_engine import (
    compute_piecewise_hash,
    generate_chain_of_custody,
    match_scam_templates,
)
from src.forensics.metadata import extract_image_exif, extract_pdf_metadata
from src.forensics.network import generate_syndicate_graph
from src.legal.bns_dossier import compute_sha256, generate_fir_dossier
from src.legal.nice_mapping import get_investigator_credentials, get_statutory_standards_list


# ── True Magic Byte Signatures ───────────────────────────────────────────────
MAGIC_SIGNATURES: Dict[str, bytes] = {
    "PDF": b"%PDF-",
    "PNG": b"\x89PNG\r\n\x1a\n",
    "JPEG": b"\xff\xd8\xff",
    "WINDOWS_EXE": b"MZ",
    "LINUX_ELF": b"\x7fELF",
    "SHELL_SCRIPT": b"#!",
    "PHP_SCRIPT": b"<?php",
    "HTML_SCRIPT": b"<html",
}


def inspect_magic_bytes(file_bytes: bytes, declared_ext: str) -> Dict[str, Any]:
    """
    Validates file magic bytes against declared extension (NIST SP 800-86 Sec 4.3.2).
    Detects executable or script payloads masquerading as documents.
    """
    head = file_bytes[:1024]
    detected_mime = "unknown/binary"
    detected_type = "UNKNOWN"
    is_spoofed = False
    spoof_alert = ""

    # Check known true formats
    if head.startswith(b"%PDF-") or b"%PDF-" in head[:512]:
        detected_type = "PDF"
        detected_mime = "application/pdf"
    elif head.startswith(b"\x89PNG\r\n\x1a\n"):
        detected_type = "PNG"
        detected_mime = "image/png"
    elif head.startswith(b"\xff\xd8\xff"):
        detected_type = "JPEG"
        detected_mime = "image/jpeg"
    elif head.startswith(b"MZ"):
        detected_type = "WINDOWS_EXECUTABLE"
        detected_mime = "application/x-dosexec"
        is_spoofed = True
        spoof_alert = "[CRITICAL MALWARE SPOOFING] Executable Windows binary disguised as document."
    elif head.startswith(b"\x7fELF"):
        detected_type = "LINUX_ELF_BINARY"
        detected_mime = "application/x-executable"
        is_spoofed = True
        spoof_alert = "[CRITICAL MALWARE SPOOFING] Linux ELF binary disguised as document."
    elif head.startswith(b"#!") or b"<?php" in head.lower() or b"<script" in head.lower():
        detected_type = "SCRIPT_PAYLOAD"
        detected_mime = "text/x-script"
        is_spoofed = True
        spoof_alert = "[CRITICAL SPOOFING] Executable script payload disguised as document."
    else:
        # Fallback check
        norm_ext = declared_ext.lower().replace(".", "")
        if norm_ext in {"png", "jpg", "jpeg", "pdf"}:
            detected_type = norm_ext.upper()
            detected_mime = f"application/{norm_ext}" if norm_ext == "pdf" else f"image/{norm_ext}"

    # Verify declared extension against true magic byte type
    norm_ext = declared_ext.lower().replace(".", "")
    if norm_ext == "pdf" and detected_type not in {"PDF", "UNKNOWN"}:
        is_spoofed = True
        if not spoof_alert:
            spoof_alert = f"[FILE EXTENSION SPOOFING] Declared as PDF but magic bytes indicate {detected_type}."
        else:
            spoof_alert = f"{spoof_alert} (Declared as PDF, detected {detected_type})."
    elif norm_ext in {"png", "jpg", "jpeg"} and detected_type not in {"PNG", "JPEG", "UNKNOWN"}:
        is_spoofed = True
        if not spoof_alert:
            spoof_alert = f"[FILE EXTENSION SPOOFING] Declared as image but magic bytes indicate {detected_type}."
        else:
            spoof_alert = f"{spoof_alert} (Declared as image, detected {detected_type})."

    return {
        "true_type": detected_type,
        "true_mime": detected_mime,
        "is_spoofed": is_spoofed,
        "spoof_alert": spoof_alert,
        "header_hex_preview": " ".join(f"{b:02X}" for b in file_bytes[:16]),
    }


def execute_phase1_collection(
    file_bytes: bytes,
    file_name: str,
    complainant_name: str,
    complainant_contact: str,
) -> Dict[str, Any]:
    """
    Phase 1: Collection (NIST SP 800-86 Section 3.1 & 4.2).
    Preserves raw data, client session telemetry, computes cryptographic SHA-256 and MD5.
    """
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    md5_hash = hashlib.md5(file_bytes).hexdigest()
    capture_time = datetime.now(timezone.utc).isoformat()
    session_id = str(uuid.uuid4())

    return {
        "phase": "Phase 1: Collection",
        "session_id": session_id,
        "capture_timestamp_utc": capture_time,
        "file_name": file_name,
        "file_size_bytes": len(file_bytes),
        "sha256": sha256_hash,
        "md5": md5_hash,
        "complainant_name": complainant_name,
        "complainant_contact": complainant_contact,
        "evidence_preservation": "READ_ONLY_BIT_STREAM_LOCK",
    }


def execute_phase2_examination(
    collection_data: Dict[str, Any],
    file_bytes: bytes,
) -> Dict[str, Any]:
    """
    Phase 2: Examination (NIST SP 800-86 Section 3.2 & 4.3).
    Performs true magic-byte validation, extension spoofing check, and metadata MAC timestamps.
    """
    file_name = collection_data["file_name"]
    file_ext = Path(file_name).suffix.lower()
    magic_info = inspect_magic_bytes(file_bytes, declared_ext=file_ext)

    is_pdf = file_ext == ".pdf" or magic_info["true_type"] == "PDF"
    is_image = file_ext in {".png", ".jpg", ".jpeg"} or magic_info["true_type"] in {"PNG", "JPEG"}

    if is_pdf:
        meta_result = extract_pdf_metadata(file_bytes)
        raw_text = meta_result.get("text", "")
    else:
        meta_result = extract_image_exif(file_bytes)
        raw_text = meta_result.get("text", "")
        meta_result.setdefault("risk_score", 0)
        meta_result.setdefault("flags", [])
        meta_result.setdefault("scam_triggers_found", {})

    # Extract MAC timestamps from metadata dictionary
    creation_date = meta_result.get("creation_date") or meta_result.get("created") or "Metadata Timestamp Absent"
    mod_date = meta_result.get("mod_date") or meta_result.get("modified") or "Metadata Timestamp Absent"

    return {
        "phase": "Phase 2: Examination",
        "magic_info": magic_info,
        "is_pdf": is_pdf,
        "is_image": is_image,
        "file_ext": file_ext,
        "raw_text": raw_text,
        "meta_result": meta_result,
        "timestamps": {
            "creation_time": creation_date,
            "modification_time": mod_date,
        },
    }


def execute_phase3_analysis(
    collection_data: Dict[str, Any],
    exam_data: Dict[str, Any],
    file_bytes: bytes,
    runtime_key: str = "",
) -> Dict[str, Any]:
    """
    Phase 3: Analysis (NIST SP 800-86 Section 3.3).
    Orchestrates Gemini multimodal clause evaluation, ELA pixel tampering,
    IFSC banking route math, and Prakash-Sadawarti CTPH fuzzy template similarity.
    """
    is_image = exam_data["is_image"]
    file_bytes_input = file_bytes
    file_ext = exam_data["file_ext"]
    mime = "application/pdf" if exam_data["is_pdf"] else ("image/png" if file_ext == ".png" else "image/jpeg")

    # 1. ELA Tamper Detection (Raster images only)
    ela_image_bytes: Optional[bytes] = None
    ela_prob = 0.0
    ela_summary = "N/A — Vector format or clean raster."

    if is_image:
        try:
            ela_heatmap, ela_prob = generate_ela_heatmap(file_bytes_input)
            if ela_heatmap is not None:
                buf = io.BytesIO()
                ela_heatmap.save(buf, format="PNG")
                ela_image_bytes = buf.getvalue()
            ela_summary = (
                f"Tamper anomaly probability: {ela_prob * 100:.1f}%. "
                + ("[ALERT] Significant compression gradient anomalies detected." if ela_prob > 0.5
                   else "[VERIFIED] Uniform error levels across image plane.")
            )
        except Exception as exc:
            ela_summary = f"Error during ELA analysis: {exc}"

    # 2. Multimodal AI Forensic Evaluation
    if is_image:
        ai_result = evaluate_image(
            image_bytes=file_bytes_input,
            mime_type=mime,
            runtime_key=runtime_key,
        )
    else:
        ai_result = evaluate_document(
            text=exam_data["raw_text"],
            runtime_key=runtime_key,
        )

    active_model = ai_result.get("active_model") or ai_result.get("source", "system")
    extracted = ai_result.get("extracted_entities", {})
    company_name = extracted.get("company_name") or "Unknown Entity"
    claimed_hq = extracted.get("claimed_address") or ""
    role_offered = extracted.get("role") or "Intern / Trainee"
    stipend_terms = extracted.get("stipend") or "Unspecified"
    monetary_demands = extracted.get("monetary_demands", [])

    # 3. Synthesize text for Banking & IFSC Route Analysis
    if is_image:
        text_for_banking = " ".join([
            company_name,
            claimed_hq,
            " ".join(extracted.get("upi_ids", [])),
            " ".join(extracted.get("ifsc_codes", [])),
            " ".join(monetary_demands),
        ])
    else:
        text_for_banking = exam_data["raw_text"]

    banking_result = assess_banking_risk(text_for_banking, claimed_hq=claimed_hq)
    if is_image:
        for uid in extracted.get("upi_ids", []):
            if uid not in banking_result["upi_handles"]:
                banking_result["upi_handles"].append(uid)
        for icode in extracted.get("ifsc_codes", []):
            if icode not in banking_result["ifsc_codes"]:
                banking_result["ifsc_codes"].append(icode)

    # Compute origin vs destination distance route
    map_data = resolve_banking_route(
        text=text_for_banking,
        claimed_hq=claimed_hq,
        ifsc_details=banking_result.get("ifsc_details"),
    )

    # 4. Prakash & Sadawarti (2022) Piecewise Fuzzy Hashing & Template Matching
    combined_text = (exam_data["raw_text"] or "") + " " + text_for_banking
    template_data = match_scam_templates(text=combined_text, file_bytes=file_bytes_input)

    # 5. Entity Syndicate Graph
    entities = {
        "UPI": banking_result.get("upi_handles", []),
        "IFSC": banking_result.get("ifsc_codes", []),
        "Company": [company_name] if company_name and company_name != "Unknown Entity" else [],
        "Signatory": [extracted["signatory"]] if extracted.get("signatory") else [],
    }
    graph_bytes, syndicate_flags, is_syndicate = generate_syndicate_graph(
        entities=entities,
        doc_label=collection_data["file_name"],
    )

    return {
        "phase": "Phase 3: Analysis",
        "ela_image": ela_image_bytes,
        "ela_prob": ela_prob,
        "ela_summary": ela_summary,
        "ai_result": ai_result,
        "extracted_entities": extracted,
        "company_name": company_name,
        "claimed_hq": claimed_hq,
        "role_offered": role_offered,
        "stipend_terms": stipend_terms,
        "monetary_demands": monetary_demands,
        "banking_result": banking_result,
        "map_data": map_data,
        "template_data": template_data,
        "graph_bytes": graph_bytes,
        "syndicate_flags": syndicate_flags,
        "is_syndicate": is_syndicate,
        "active_model": active_model,
    }


def execute_phase4_reporting(
    collection_data: Dict[str, Any],
    exam_data: Dict[str, Any],
    analysis_data: Dict[str, Any],
    file_bytes: bytes,
) -> Dict[str, Any]:
    """
    Phase 4: Reporting (NIST SP 800-86 Section 3.4).
    Synthesizes COFELET evaluation rubric, NICE role credentialing,
    immutable Chain of Custody ledger, and certified FIR PDF dossier.
    """
    extracted = analysis_data["extracted_entities"]
    banking_result = analysis_data["banking_result"]
    meta_result = exam_data["meta_result"]
    ela_prob = analysis_data["ela_prob"]
    template_data = analysis_data["template_data"]
    map_data = analysis_data["map_data"]
    is_syndicate = analysis_data["is_syndicate"]
    ai_result = analysis_data["ai_result"]
    file_name = collection_data["file_name"]
    magic_info = exam_data["magic_info"]

    # 1. COFELET Dynamic Evaluation Rubric
    rubric_results = evaluate_cofelet_rubric(
        extracted_entities=extracted,
        ai_result=ai_result,
        banking_result=banking_result,
        meta_result=meta_result,
        ela_prob=ela_prob,
        template_data=template_data,
        map_data=map_data,
    )

    # 2. Overall Risk Score & Verdict
    scores = [
        meta_result.get("risk_score", 0),
        int(ela_prob * 100),
        banking_result.get("risk_score", 0),
        ai_result.get("threat_rating", 0),
        rubric_results.get("rubric_risk_score", 0),
        template_data.get("template_similarity_score", 0),
        75 if is_syndicate else 0,
        50 if map_data.get("is_anomaly") else 0,
        100 if magic_info.get("is_spoofed") else 0,
    ]
    active_scores = [s for s in scores if s > 0]
    overall_risk = min(100, int(sum(active_scores) / max(1, len(active_scores))))

    ai_verdict = ai_result.get("verdict", "").upper()
    if magic_info.get("is_spoofed") or ai_verdict == "SCAM" or overall_risk >= 70 or is_syndicate:
        verdict = "HIGH RISK"
    elif ai_verdict == "SUSPICIOUS" or overall_risk >= 35 or map_data.get("is_anomaly") or template_data.get("is_template_match"):
        verdict = "SUSPICIOUS"
    else:
        verdict = "VERIFIED"

    # 3. Prakash & Sadawarti (2022) Chain of Custody (CoC) Immutable Block
    chain_of_custody = generate_chain_of_custody(
        file_bytes=file_bytes,
        file_name=file_name,
        complainant_name=collection_data["complainant_name"],
        verdict=verdict,
    )

    # 4. NICE Cybersecurity Workforce Framework (NIST SP 800-181 Rev. 1) Role Alignment
    nice_credentials = get_investigator_credentials(
        examiner_name=collection_data["complainant_name"],
    )

    # 5. Synthesize Top 3 High-Impact Executive Findings
    summary_findings: List[str] = []

    # Finding 1: File Authenticity & Magic Bytes
    if magic_info.get("is_spoofed"):
        summary_findings.append(f"[NIST SP 800-86 ALERT] {magic_info['spoof_alert']}")
    elif template_data.get("is_template_match"):
        summary_findings.append(
            f"[SYNDICATE REUSE] {template_data['template_similarity_score']}% match to {template_data['matched_template_name']}."
        )
    elif ai_result.get("red_flags"):
        summary_findings.append(f"[CONTRACT AUDIT] {ai_result['red_flags'][0].get('flag', '')}")
    else:
        summary_findings.append("[ENTITY SCAN] Contract verified with standard institutional parameters.")

    # Finding 2: Pixel Forensics / Document Integrity
    if exam_data["is_image"] and ela_prob > 0.5:
        summary_findings.append(f"[TAMPER EVIDENCE] ELA detected {int(ela_prob * 100)}% forgery probability across seals/signatures.")
    elif exam_data["is_image"]:
        summary_findings.append(f"[INTEGRITY] ELA confirms uniform pixel compression ({int(ela_prob * 100)}% variance).")
    else:
        pdf_producer = meta_result.get("producer") or meta_result.get("creator") or "Standard Document Generator"
        summary_findings.append(f"[DOCUMENT METADATA] Vector PDF generated via {pdf_producer}.")

    # Finding 3: Financial & Origin Route
    if map_data.get("is_mule"):
        summary_findings.append(f"[MULE ACCOUNT HUB] Beneficiary routed to flagged cybercrime corridor in {map_data.get('bank_city', 'India')}.")
    elif map_data.get("distance_km") and map_data.get("distance_km") > 120:
        summary_findings.append(f"[GEOGRAPHIC MISMATCH] Claimed HQ is {int(map_data['distance_km'])} km from clearing bank.")
    elif banking_result.get("upi_handles"):
        summary_findings.append(f"[PAYMENT RAILS] Extracted UPI routing handles: {', '.join(banking_result['upi_handles'][:2])}.")
    else:
        summary_findings.append("[PAYMENT RAILS] No high-risk mule account destinations detected on standard clearing rails.")

    # 6. Detailed itemized findings list
    all_findings: List[str] = []
    if magic_info.get("is_spoofed"):
        all_findings.append(f"[CRITICAL SPOOFING] {magic_info['spoof_alert']}")
    for tf in template_data.get("template_flags", []):
        all_findings.append(tf)
    for rf in ai_result.get("red_flags", []):
        all_findings.append(f"[{rf.get('severity', 'MEDIUM').upper()}] {rf.get('flag', '')}")
    for bf in banking_result.get("flags", []):
        all_findings.append(bf)
    for sf in analysis_data["syndicate_flags"]:
        all_findings.append(sf)

    # 7. Certified Legal FIR Dossier Generation
    findings_package = {
        "overall_risk": overall_risk,
        "metadata_risk": meta_result.get("risk_score", 0),
        "ela_prob": ela_prob,
        "ela_summary": analysis_data["ela_summary"],
        "banking_risk": banking_result.get("risk_score", 0),
        "is_syndicate": is_syndicate,
        "syndicate_summary": analysis_data["syndicate_flags"][0] if analysis_data["syndicate_flags"] else "No cross-document links identified",
        "ifsc_codes": banking_result.get("ifsc_codes", []),
        "scam_triggers": list(meta_result.get("scam_triggers_found", {}).keys()),
        "metadata_flags": meta_result.get("flags", []),
        "banking_flags": banking_result.get("flags", []),
        "network_flags": analysis_data["syndicate_flags"],
        "ela_flags": (["[TAMPER EVIDENCE] ELA heatmap shows pixel disparity across letterhead."] if ela_prob > 0.5 else []),
        "chain_of_custody": chain_of_custody,
        "nice_credentials": nice_credentials,
        "template_match": template_data,
        "cofelet_rubric": rubric_results,
    }

    try:
        pdf_bytes = generate_fir_dossier(
            document_bytes=file_bytes,
            filename=file_name,
            findings=findings_package,
            complainant_name=collection_data["complainant_name"],
            complainant_contact=collection_data["complainant_contact"],
        )
    except Exception:
        pdf_bytes = None

    return {
        "phase": "Phase 4: Reporting",
        "verdict": verdict,
        "risk_score": overall_risk,
        "summary": summary_findings[:3],
        "findings": all_findings,
        "pdf_bytes": pdf_bytes,
        "chain_of_custody": chain_of_custody,
        "cofelet_rubric": rubric_results,
        "nice_credentials": nice_credentials,
        "template_match": template_data,
        "findings_package": findings_package,
    }


def run_nist_pipeline(
    file_bytes: bytes,
    file_name: str = "document.pdf",
    runtime_key: str = "",
    complainant_name: str = "Authorized Forensic Investigator",
    complainant_contact: str = "cybercell.investigations@nic.in",
) -> Dict[str, Any]:
    """
    Executes the complete NIST SP 800-86 4-Phase Ingestion & Analysis Workflow.
    """
    # Phase 1: Collection
    p1 = execute_phase1_collection(
        file_bytes=file_bytes,
        file_name=file_name,
        complainant_name=complainant_name,
        complainant_contact=complainant_contact,
    )

    # Phase 2: Examination
    p2 = execute_phase2_examination(
        collection_data=p1,
        file_bytes=file_bytes,
    )

    # Phase 3: Analysis
    p3 = execute_phase3_analysis(
        collection_data=p1,
        exam_data=p2,
        file_bytes=file_bytes,
        runtime_key=runtime_key,
    )

    # Phase 4: Reporting
    p4 = execute_phase4_reporting(
        collection_data=p1,
        exam_data=p2,
        analysis_data=p3,
        file_bytes=file_bytes,
    )

    # Synthesize unified master telemetry dictionary
    return {
        # Core identification & taxonomy
        "is_recruitment_document": True,
        "detected_type": p2["magic_info"]["true_type"],
        "rejection_reason": None,
        "verdict": p4["verdict"],
        "risk_score": p4["risk_score"],
        "summary": p4["summary"],
        "findings": p4["findings"],

        # Visual Forensics & ELA
        "ela_image": p3["ela_image"],
        "ela_prob": p3["ela_prob"],
        "map_data": p3["map_data"],

        # Certified Artifacts
        "pdf_bytes": p4["pdf_bytes"],
        "chain_of_custody": p4["chain_of_custody"],
        "cofelet_rubric": p4["cofelet_rubric"],
        "nice_credentials": p4["nice_credentials"],
        "template_match": p4["template_match"],
        "magic_info": p2["magic_info"],

        # Extracted Entities & Banking
        "company_name": p3["company_name"],
        "role": p3["role_offered"],
        "stipend": p3["stipend_terms"],
        "monetary_demands": p3["monetary_demands"],
        "upi_handles": p3["banking_result"].get("upi_handles", []),
        "ifsc_codes": p3["banking_result"].get("ifsc_codes", []),
        "ifsc_details": p3["banking_result"].get("ifsc_details", {}),
        "is_syndicate": p3["is_syndicate"],
        "graph_image": p3["graph_bytes"],
        "sha256": p1["sha256"],
        "md5": p1["md5"],
        "active_model": p3["active_model"],
        "reasoning": p3["ai_result"].get("reasoning", p3["ai_result"].get("summary", "")),
        "signatory": p3["extracted_entities"].get("signatory") or "Not Specified",
        "candidate_name": p3["extracted_entities"].get("candidate_name") or "Candidate",
        "cin_number": p3["extracted_entities"].get("cin_number") or "ABSENT (Unregistered)",
        "red_flags": p3["ai_result"].get("red_flags", []),
        "syndicate_flags": p3["syndicate_flags"],

        # 4-Phase Telemetry Metadata
        "nist_lifecycle": {
            "phase_1_collection": p1,
            "phase_2_examination": {
                "magic_bytes": p2["magic_info"],
                "timestamps": p2["timestamps"],
            },
            "phase_3_analysis": {
                "model": p3["active_model"],
                "fuzzy_hash": p3["template_data"]["fuzzy_hash"],
                "template_score": p3["template_data"]["template_similarity_score"],
            },
            "phase_4_reporting": {
                "rubric_score": p4["cofelet_rubric"]["rubric_risk_score"],
                "coc_id": p4["chain_of_custody"]["coc_id"],
                "investigator_role": p4["nice_credentials"]["primary_role_id"],
            },
        },
    }
