"""
src/legal/nice_mapping.py
NICE Cybersecurity Workforce Framework (NIST SP 800-181 Rev. 1) Role Alignment.
Standardizes investigator credentialing, Task/Knowledge/Skill (TKS) taxonomy,
and statutory legal counsel roles for cyber-forensics audits.
"""
from __future__ import annotations

from typing import Any, Dict, List


# ── NICE Framework Work Roles & TKS Taxonomy ──────────────────────────────────
NICE_WORK_ROLES: Dict[str, Dict[str, Any]] = {
    "PR-CDA-001": {
        "title": "Cyber Defense Analyst",
        "category": "Protect and Defend",
        "description": "Uses defensive measures and information collected from a variety of sources to identify, analyze, and report events that occur or might occur within the network in order to protect information, information systems, and networks from threats.",
        "tasks": [
            {"id": "T0028", "text": "Conduct forensic examination of digital evidence to support cybercrime investigations."},
            {"id": "T0166", "text": "Perform packet-level and document payload analysis to identify malicious intent or fraud."},
            {"id": "T0286", "text": "Document digital evidence handling procedures to ensure preservation of chain of custody."},
        ],
        "knowledge": [
            {"id": "K0020", "text": "Knowledge of digital evidence handling and chain of custody preservation procedures."},
            {"id": "K0042", "text": "Knowledge of file header formats, magic bytes, and file extension spoofing techniques."},
            {"id": "K0177", "text": "Knowledge of error level analysis (ELA) and pixel compression variance in raster graphics."},
        ],
        "skills": [
            {"id": "S0013", "text": "Skill in analyzing piecewise perceptual hashes (CTPH) to identify scam template reuse."},
            {"id": "S0074", "text": "Skill in identifying file tampering, metadata scrubbing, and software generator signatures."},
            {"id": "S0091", "text": "Skill in analyzing volatile and non-volatile digital recruitment evidence."},
        ],
    },
    "OV-LGA-001": {
        "title": "Cyber Legal Advisor",
        "category": "Oversee and Govern",
        "description": "Provides legal advice and recommendations on specialized matters relating to cyber operations, electronic evidence collection, statutory compliance, and prosecution.",
        "tasks": [
            {"id": "T0180", "text": "Provide legal counsel on statutory compliance with labor, apprenticeship, and penal statutes."},
            {"id": "T0312", "text": "Prepare admissible evidentiary complaint dossiers for law enforcement and judicial authorities."},
            {"id": "T0188", "text": "Assess criminal liability under Bharatiya Nyaya Sanhita (BNS) and Information Technology Act."},
        ],
        "knowledge": [
            {"id": "K0088", "text": "Knowledge of Bharatiya Nyaya Sanhita, 2023 (Sections 318(4) and 336(3))."},
            {"id": "K0152", "text": "Knowledge of Apprentices Act, 1961 mandatory stipend and fee prohibition provisions."},
            {"id": "K0205", "text": "Knowledge of Information Technology Act, 2000 Section 66D (Cheating by Impersonation)."},
        ],
        "skills": [
            {"id": "S0068", "text": "Skill in synthesizing technical forensic findings into legally defensible cybercrime complaint dossiers."},
            {"id": "S0084", "text": "Skill in formulating FIR referral grounds for National Cyber Crime Reporting Portal (cybercrime.gov.in)."},
        ],
    },
}


def get_investigator_credentials(
    examiner_name: str = "Authorized Forensic Investigator",
) -> Dict[str, Any]:
    """
    Returns standardized NICE Framework credential metadata for forensic reporting.
    """
    cda = NICE_WORK_ROLES["PR-CDA-001"]
    lga = NICE_WORK_ROLES["OV-LGA-001"]

    return {
        "examiner_name": examiner_name,
        "primary_role_id": "PR-CDA-001",
        "primary_role_title": cda["title"],
        "legal_advisor_id": "OV-LGA-001",
        "legal_advisor_title": lga["title"],
        "certified_framework": "NIST SP 800-181 Rev. 1 (NICE Framework)",
        "methodology_standard": "NIST SP 800-86 (Forensic Techniques in Incident Response)",
        "competencies": [
            "Digital Evidence Ingestion & Cryptographic Chain of Custody",
            "Multimodal Neural Clause Verification & Document Forensics",
            "Statutory Cyber-Labor Compliance & Criminal Procedure Harmonization",
        ],
        "tks_summary": [
            f"[{t['id']}] {t['text']}" for t in cda["tasks"] + lga["tasks"]
        ],
    }


def get_statutory_standards_list() -> List[Dict[str, str]]:
    """
    Returns the comprehensive list of federal standards and statutes enforced by InternKavach.
    """
    return [
        {
            "code": "NIST SP 800-86",
            "name": "Guide to Integrating Forensic Techniques into Incident Response",
            "focus": "4-Phase Lifecycle: Collection, Examination, Analysis, Reporting. Evidence integrity, magic-byte inspection, write-blocking.",
        },
        {
            "code": "NIST SP 800-181 Rev. 1",
            "name": "Workforce Framework for Cybersecurity (NICE Framework)",
            "focus": "Standardizes Task, Knowledge, and Skill (TKS) building blocks and Work Roles: PR-CDA-001 and OV-LGA-001.",
        },
        {
            "code": "BNS, 2023 (Sec 318(4))",
            "name": "Bharatiya Nyaya Sanhita – Cheating & Property Delivery",
            "focus": "Penalizes dishonest inducement to deliver funds under fraudulent job/internship promises. Up to 7 years imprisonment.",
        },
        {
            "code": "BNS, 2023 (Sec 336(3))",
            "name": "Bharatiya Nyaya Sanhita – Forgery of Electronic Records",
            "focus": "Penalizes fabrication or digital manipulation of contracts, company seals, and signatures. Up to 7 years imprisonment.",
        },
        {
            "code": "IT Act, 2000 (Sec 66D)",
            "name": "Information Technology Act – Cheating by Personation",
            "focus": "Penalizes fraudulent impersonation of corporate entities via computer resources and spoofed emails. Up to 3 years imprisonment.",
        },
        {
            "code": "Apprentices Act, 1961",
            "name": "Statutory Apprenticeship & Student Intern Norms (Sec 3 & 4)",
            "focus": "Mandates monthly stipends for student apprentices; absolutely prohibits levying any training, processing, or security deposits.",
        },
    ]
