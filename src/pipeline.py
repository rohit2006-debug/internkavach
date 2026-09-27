"""
src/pipeline.py
Executive Controller & NIST SP 800-86 Forensic Pipeline Orchestrator for InternKavach.
Integrates:
- NIST SP 800-86 4-Phase Lifecycle (Collection, Examination, Analysis, Reporting)
- Prakash & Sadawarti (2022) Piecewise Fuzzy Hashing & Immutable Chain of Custody (CoC)
- Katsantonis et al. (2023) COFELET Dynamic Evaluation Rubric & Forensic Coach Engine
- NIST SP 800-181 Rev. 1 NICE Framework Role & Credential Alignment
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.ai.document_classifier import classify_document_type
from src.forensics.nist_pipeline import run_nist_pipeline
from src.legal.bns_dossier import compute_sha256


def audit_pipeline(
    file_bytes: bytes,
    file_name: str = "document.pdf",
    runtime_key: str = "",
    complainant_name: str = "Authorized Forensic Investigator",
    complainant_contact: str = "cybercell.investigations@nic.in",
) -> Dict[str, Any]:
    """
    Executes the end-to-end cyber-forensics audit pipeline under NIST SP 800-86.
    """
    file_ext = Path(file_name).suffix.lower()
    is_pdf = file_ext == ".pdf"
    mime = "application/pdf" if is_pdf else ("image/png" if file_ext == ".png" else "image/jpeg")

    # 1. Pre-flight Gatekeeper Document Classification
    classification = classify_document_type(
        file_bytes=file_bytes,
        mime_type=mime,
        api_key=runtime_key or os.environ.get("GEMINI_API_KEY", ""),
    )

    if not classification.get("is_recruitment_document", True):
        detected_type = classification.get("detected_type", "Non-Recruitment Document")
        rejection_reason = classification.get(
            "rejection_reason",
            "Document does not match recruitment, employment, or internship criteria."
        )
        return {
            "is_recruitment_document": False,
            "detected_type": detected_type,
            "rejection_reason": rejection_reason,
            "verdict": "REJECTED",
            "risk_score": 0,
            "summary": [
                f"[GATEKEEPER REJECTED] {detected_type}",
                f"Taxonomy Confidence: {int(classification.get('confidence', 1.0) * 100)}%",
                rejection_reason,
            ],
            "findings": [rejection_reason],
            "ela_image": None,
            "ela_prob": 0.0,
            "map_data": {},
            "pdf_bytes": None,
            "company_name": "N/A",
            "role": "N/A",
            "stipend": "N/A",
            "monetary_demands": [],
            "upi_handles": [],
            "ifsc_codes": [],
            "graph_image": None,
            "sha256": compute_sha256(file_bytes),
            "active_model": "GATEKEEPER",
            "chain_of_custody": {
                "coc_id": "REJECTED-BY-GATEKEEPER",
                "timestamp_utc": "",
                "integrity_status": "REJECTED",
                "fuzzy_hash": "",
            },
            "cofelet_rubric": {
                "rubric_risk_score": 0,
                "threat_vectors": {},
                "coach_recommendations": [],
                "scenario_execution_flow": [],
            },
            "nice_credentials": {
                "primary_role_id": "PR-CDA-001",
                "primary_role_title": "Cyber Defense Analyst",
            },
            "template_match": {
                "template_similarity_score": 0,
                "matched_template_name": "Non-Recruitment Document",
                "is_template_match": False,
                "fuzzy_hash": "",
            },
            "magic_info": {},
            "nist_lifecycle": {},
        }

    # 2. Execute NIST SP 800-86 4-Phase Forensic Ingestion Engine
    result = run_nist_pipeline(
        file_bytes=file_bytes,
        file_name=file_name,
        runtime_key=runtime_key,
        complainant_name=complainant_name,
        complainant_contact=complainant_contact,
    )

    # Ensure detected_type matches gatekeeper taxonomy when available
    if classification.get("detected_type"):
        result["detected_type"] = classification["detected_type"]

    return result
