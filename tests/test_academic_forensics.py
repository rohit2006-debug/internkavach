"""
tests/test_academic_forensics.py
Unit & Integration Tests for Academic Research & Federal Standards Engines:
1. NIST SP 800-86 4-Phase Lifecycle & Magic Byte Inspection
2. Prakash & Sadawarti (2022) Piecewise Fuzzy Hashing & Chain of Custody
3. Katsantonis et al. (2023) COFELET Dynamic Evaluation Rubric
4. NIST SP 800-181 Rev. 1 NICE Framework Role Alignment
"""
import io
import pytest

from src.forensics.fuzzy_engine import (
    compute_piecewise_hash,
    compare_fuzzy_hashes,
    match_scam_templates,
    generate_chain_of_custody,
)
from src.forensics.nist_pipeline import inspect_magic_bytes, run_nist_pipeline
from src.ai.rubric_engine import evaluate_cofelet_rubric
from src.legal.nice_mapping import get_investigator_credentials, get_statutory_standards_list


class TestFuzzyEngine:
    """Tests for Prakash & Sadawarti (2022) Piecewise Fuzzy Hashing & CoC."""

    def test_piecewise_hash_deterministic(self):
        data = b"Internship Appointment Offer Letter - Trainee Engineer"
        h1 = compute_piecewise_hash(data)
        h2 = compute_piecewise_hash(data)
        assert h1 == h2
        assert ":" in h1
        parts = h1.split(":")
        assert len(parts) >= 3

    def test_fuzzy_similarity_identical(self):
        data = b"Sample internship appointment offer letter text bytes"
        h = compute_piecewise_hash(data)
        score = compare_fuzzy_hashes(h, h)
        assert score == 100.0

    def test_fuzzy_similarity_different(self):
        data1 = b"Virtual Internship Offer Letter requiring Rs 2500 security deposit"
        data2 = b"Completely unrelated culinary recipe for chocolate chip cookies"
        h1 = compute_piecewise_hash(data1)
        h2 = compute_piecewise_hash(data2)
        score = compare_fuzzy_hashes(h1, h2)
        assert score < 60.0

    def test_match_scam_templates_flags_syndicate(self):
        scam_text = (
            "Congratulations! This is an offer letter for virtual internship. "
            "Please pay registration fee and certificate charges via telegram group coordinator. "
            "Free domain support provided."
        )
        res = match_scam_templates(text=scam_text, file_bytes=scam_text.encode())
        assert res["template_similarity_score"] > 30
        assert res["matched_template_id"] == "VIRTUAL_INTERNSHIP_MASS_MAIL"

    def test_generate_chain_of_custody_structure(self):
        data = b"Evidence raw bytes content"
        coc = generate_chain_of_custody(data, "offer.pdf", "Investigator De", "HIGH RISK")
        assert "coc_id" in coc
        assert "block_signature" in coc
        assert coc["sha256"] != ""
        assert coc["md5"] != ""
        assert coc["fuzzy_hash"] != ""
        assert coc["integrity_status"] == "VERIFIED_TAMPER_EVIDENT"
        assert "PR-CDA-001" in coc["examiner_work_role"]


class TestNISTPipeline:
    """Tests for NIST SP 800-86 Magic Byte Inspection & 4-Phase Ingestion."""

    def test_magic_bytes_valid_pdf(self):
        pdf_bytes = b"%PDF-1.4\n%trailer\n%%EOF"
        info = inspect_magic_bytes(pdf_bytes, declared_ext=".pdf")
        assert info["true_type"] == "PDF"
        assert not info["is_spoofed"]

    def test_magic_bytes_valid_png(self):
        png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
        info = inspect_magic_bytes(png_bytes, declared_ext=".png")
        assert info["true_type"] == "PNG"
        assert not info["is_spoofed"]

    def test_detect_extension_spoofing_executable(self):
        # Windows executable payload disguised as PDF
        exe_bytes = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff"
        info = inspect_magic_bytes(exe_bytes, declared_ext=".pdf")
        assert info["is_spoofed"]
        assert info["true_type"] == "WINDOWS_EXECUTABLE"
        assert "MALWARE SPOOFING" in info["spoof_alert"]

    def test_run_nist_pipeline_returns_academic_telemetry(self):
        sample_doc = b"%PDF-1.4\nOffer Letter for Virtual Internship demanding Rs 1500 registration deposit via UPI"
        res = run_nist_pipeline(sample_doc, "offer.pdf", complainant_name="Det. Inspector")
        assert res["verdict"] in {"HIGH RISK", "SUSPICIOUS", "VERIFIED"}
        assert "chain_of_custody" in res
        assert "cofelet_rubric" in res
        assert "nice_credentials" in res
        assert "template_match" in res
        assert "nist_lifecycle" in res
        assert res["nist_lifecycle"]["phase_1_collection"]["evidence_preservation"] == "READ_ONLY_BIT_STREAM_LOCK"


class TestCOFELETRubric:
    """Tests for Katsantonis et al. (2023) COFELET Threat Vectors & Coach."""

    def test_rubric_evaluates_four_vectors(self):
        extracted = {
            "company_name": "Ghost Tech",
            "claimed_address": "Bengaluru",
            "cin_number": "ABSENT",
            "stipend": "Unpaid",
            "monetary_demands": ["₹2000 registration fee"],
        }
        banking = {"upi_handles": ["mule@ybl"], "ifsc_codes": ["SBIN0001234"], "risk_score": 80}
        meta = {"risk_score": 50, "flags": []}
        map_data = {"is_mule": True, "distance_km": 1500, "bank_city": "Jamtara"}
        template_data = {"template_similarity_score": 85, "is_template_match": True}

        res = evaluate_cofelet_rubric(
            extracted_entities=extracted,
            ai_result={"threat_rating": 85, "red_flags": [{"flag": "Security fee demand"}]},
            banking_result=banking,
            meta_result=meta,
            ela_prob=0.8,
            template_data=template_data,
            map_data=map_data,
        )

        vectors = res["threat_vectors"]
        assert "labor_compliance" in vectors
        assert "corporate_identity" in vectors
        assert "financial_risk" in vectors
        assert "forensic_integrity" in vectors

        assert vectors["labor_compliance"]["score"] > 50
        assert vectors["financial_risk"]["score"] > 50
        assert len(res["coach_recommendations"]) >= 3
        assert len(res["scenario_execution_flow"]) == 6


class TestNICEMapping:
    """Tests for NIST SP 800-181 Rev. 1 Role & Standard Mappings."""

    def test_get_investigator_credentials(self):
        creds = get_investigator_credentials("Officer Rohit")
        assert creds["primary_role_id"] == "PR-CDA-001"
        assert creds["legal_advisor_id"] == "OV-LGA-001"
        assert len(creds["tks_summary"]) >= 5

    def test_get_statutory_standards_list(self):
        standards = get_statutory_standards_list()
        codes = [s["code"] for s in standards]
        assert any("NIST SP 800-86" in c for c in codes)
        assert any("NIST SP 800-181" in c for c in codes)
        assert any("BNS" in c for c in codes)
        assert any("Apprentices Act" in c for c in codes)
