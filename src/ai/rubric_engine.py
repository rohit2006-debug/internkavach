"""
src/ai/rubric_engine.py
COFELET Dynamic Evaluation Rubric & Forensic Coach Engine.
Based on research by M. N. Katsantonis et al. (2023):
"Cyber range design framework for cyber security education and training"
(Conceptual Framework for eLearning and Training - COFELET).

Evaluates recruitments across 4 multi-variable threat vectors:
1. Statutory Labor Compliance (Apprentices Act, 1961)
2. Corporate Identity Integrity (MCA CIN registration, domain validation)
3. Financial Clearing Risk (IFSC branch mismatch, UPI mule trace)
4. Document Forensic Integrity (ELA pixel variance, magic bytes, fuzzy template match)

Outputs:
- Weighted Threat Vector breakdown
- Actionable Step-by-Step "Coach Recommendations" for statutory remedies.
- COFELET Scenario Execution Flow (SEF) mapping.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


def evaluate_cofelet_rubric(
    extracted_entities: Dict[str, Any],
    ai_result: Dict[str, Any],
    banking_result: Dict[str, Any],
    meta_result: Dict[str, Any],
    ela_prob: float,
    template_data: Dict[str, Any],
    map_data: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Computes a weighted, multi-variable evaluation rubric across 4 threat vectors
    and synthesizes expert pedagogical 'Coach' remedial instructions.
    """
    company_name = extracted_entities.get("company_name", "")
    claimed_hq = extracted_entities.get("claimed_address", "")
    cin_number = extracted_entities.get("cin_number", "")
    stipend = extracted_entities.get("stipend", "")
    monetary_demands = extracted_entities.get("monetary_demands", [])
    upi_handles = banking_result.get("upi_handles", [])
    ifsc_codes = banking_result.get("ifsc_codes", [])
    template_score = template_data.get("template_similarity_score", 0)

    # ── Vector 1: Statutory Labor Compliance (Apprentices Act 1961) [Weight: 30%] ──
    labor_score = 0
    labor_flags: List[str] = []

    if monetary_demands:
        labor_score += 70
        labor_flags.append(f"Demands fee payment ({', '.join(monetary_demands)}) violating Sec 3 & 4 of Apprentices Act, 1961.")
    if "unpaid" in str(stipend).lower() or "0" in str(stipend) or "performance based" in str(stipend).lower():
        labor_score += 30
        labor_flags.append("Unpaid or condition-gated internship violates mandatory minimum stipend mandates.")
    labor_score = min(100, labor_score)

    # ── Vector 2: Corporate Identity Integrity (Weight: 25%] ──
    corp_score = 0
    corp_flags: List[str] = []

    if not cin_number or "absent" in str(cin_number).lower():
        corp_score += 45
        corp_flags.append("Missing Corporate Identification Number (CIN); entity is unregistered under MCA.")
    if any(df.lower() in str(extracted_entities).lower() for df in ["@gmail.com", "@yahoo.com", "@outlook.com", "@hotmail.com"]):
        corp_score += 35
        corp_flags.append("Recruitment conducted via free generic email provider instead of corporate domain.")
    if not company_name or company_name == "Unknown Entity":
        corp_score += 20
        corp_flags.append("Hiring entity identity is obfuscated or anonymous.")
    corp_score = min(100, corp_score)

    # ── Vector 3: Financial Clearing Risk (Weight: 25%] ──
    fin_score = 0
    fin_flags: List[str] = []

    if map_data.get("is_mule"):
        fin_score += 65
        fin_flags.append(f"Beneficiary bank branch routed to flagged cybercrime syndicate zone in {map_data.get('bank_city', 'India')}.")
    if upi_handles:
        fin_score += 30
        fin_flags.append(f"Extracted personal peer-to-peer UPI rail handles: {', '.join(upi_handles)}.")
    if map_data.get("distance_km") and map_data.get("distance_km") > 120:
        fin_score += 25
        fin_flags.append(f"Geographic mismatch of {int(map_data['distance_km'])} km between claimed HQ and clearing branch.")
    fin_score = min(100, fin_score)

    # ── Vector 4: Document Forensic Integrity (Weight: 20%] ──
    doc_score = 0
    doc_flags: List[str] = []

    if ela_prob > 0.5:
        doc_score += int(ela_prob * 60)
        doc_flags.append(f"ELA pixel compression analysis indicates digital tampering/forgery ({int(ela_prob * 100)}% probability).")
    if template_score >= 60:
        doc_score += 40
        doc_flags.append(f"Piecewise Fuzzy Hash shows {template_score}% structural alignment with known fraudulent boiler-plate templates.")
    if meta_result.get("risk_score", 0) > 30:
        doc_score += 20
        doc_flags.append("Metadata reveals non-standard authoring toolkit or suspicious creation timestamps.")
    doc_score = min(100, doc_score)

    # ── Aggregate Weighted Risk Score ──
    weighted_score = int(
        (labor_score * 0.30) +
        (corp_score * 0.25) +
        (fin_score * 0.25) +
        (doc_score * 0.20)
    )

    # ── COFELET Coach Remedial Recommendations (Dynamic Guidance) ──
    coach_remedies: List[Dict[str, str]] = []

    if labor_score >= 50:
        coach_remedies.append({
            "vector": "Statutory Labor Protection",
            "statute": "Apprentices Act, 1961 (Sec 3 & 4) & BNS 2023 Sec 318(4)",
            "guidance": "DO NOT pay any security deposit, training fee, or document verification charge. Legitimate employers in India are strictly barred by law from levying recruitment charges on students. Demand a formal apprentice engagement contract registered with the Regional Directorate of Skill Development (RDSDE).",
        })

    if corp_score >= 40:
        coach_remedies.append({
            "vector": "Corporate Entity Verification",
            "statute": "Companies Act, 2013 & MCA Regulatory Norms",
            "guidance": f"Cross-verify '{company_name}' on the official Ministry of Corporate Affairs portal (mca.gov.in). If the company lacks an active 21-digit CIN, treat communications as fraudulent impersonation.",
        })

    if fin_score >= 40:
        coach_remedies.append({
            "vector": "Financial Clearing Defense",
            "statute": "Information Technology Act 2000 (Sec 66D) & Bharatiya Nagarik Suraksha Sanhita (BNSS Sec 106)",
            "guidance": "If payments have already been executed via UPI or IMPS, immediately dial the National Cybercrime Helpline 1930 within the Golden Hour to initiate a cyber-cell freeze on the beneficiary account.",
        })

    if doc_score >= 40:
        coach_remedies.append({
            "vector": "Document Forgery Mitigation",
            "statute": "Bharatiya Nyaya Sanhita (BNS, 2023) Sec 336(3) & Indian Evidence Act Sec 65B",
            "guidance": "Export the certified FIR Dossier generated by InternKavach containing SHA-256 and CTPH fuzzy hash integrity digests, and submit it directly to your university placement cell and cybercrime.gov.in.",
        })

    # Default reassurance if all clean
    if not coach_remedies:
        coach_remedies.append({
            "vector": "Standard Verification",
            "statute": "Apprentices Act, 1961 Compliance Checklist",
            "guidance": "The document displays standard corporate recruitment syntax with no immediate financial extortion patterns detected. Maintain evidence copy in personal records.",
        })

    # ── COFELET Scenario Execution Flow (SEF) Mapping ──
    sef_stages = [
        {"step": 1, "name": "SEF-RECRUIT: Ingestion & Telemetry Capture", "status": "COMPLETED"},
        {"step": 2, "name": "SEF-LABOR: Apprenticeship Clause Compliance Check", "status": "FLAGGED" if labor_score >= 50 else "PASSED"},
        {"step": 3, "name": "SEF-CORP: MCA CIN & Corporate Domain Verification", "status": "FLAGGED" if corp_score >= 40 else "PASSED"},
        {"step": 4, "name": "SEF-CLEARING: Mule Rail & Clearing Route Tracing", "status": "FLAGGED" if fin_score >= 40 else "PASSED"},
        {"step": 5, "name": "SEF-FORENSICS: ELA & CTPH Perceptual Hashing", "status": "FLAGGED" if doc_score >= 40 else "PASSED"},
        {"step": 6, "name": "SEF-DOSSIER: Certified Legal FIR Synthesis", "status": "COMPLETED"},
    ]

    return {
        "rubric_risk_score": weighted_score,
        "threat_vectors": {
            "labor_compliance": {"score": labor_score, "weight": "30%", "flags": labor_flags},
            "corporate_identity": {"score": corp_score, "weight": "25%", "flags": corp_flags},
            "financial_risk": {"score": fin_score, "weight": "25%", "flags": fin_flags},
            "forensic_integrity": {"score": doc_score, "weight": "20%", "flags": doc_flags},
        },
        "coach_recommendations": coach_remedies,
        "scenario_execution_flow": sef_stages,
    }
