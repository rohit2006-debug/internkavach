"""
tests/test_forensics.py
Automated unit tests for InternKavach forensic modules.
Run with: python -m pytest tests/test_forensics.py -v
"""
from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest
from PIL import Image
import numpy as np

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))


# ═══════════════════════════════════════════════════════════════════════════════
# ELA ENGINE TESTS
# ═══════════════════════════════════════════════════════════════════════════════
class TestELAEngine:
    """Tests for src/forensics/ela.py"""

    def _make_image(self, width=200, height=200, color=(200, 200, 200)) -> bytes:
        """Create a simple solid-colour JPEG image."""
        img = Image.new("RGB", (width, height), color=color)
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=95)
        return buf.getvalue()

    def _make_tampered_image(self) -> bytes:
        """Create an image with a synthetic pasted region (high ELA artefact)."""
        arr = np.ones((200, 200, 3), dtype=np.uint8) * 200
        # Paste a block with very different compression history
        arr[50:100, 50:150] = 50   # Dark injected region
        arr[80:90, 80:120] = 255   # Bright sub-block
        img = Image.fromarray(arr, "RGB")
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=95)
        return buf.getvalue()

    def test_ela_returns_tuple(self):
        from src.forensics.ela import generate_ela_heatmap
        img_bytes = self._make_image()
        result = generate_ela_heatmap(img_bytes)
        assert isinstance(result, tuple), "Should return a tuple"
        assert len(result) == 2, "Tuple should have 2 elements"

    def test_ela_heatmap_is_pil_image(self):
        from src.forensics.ela import generate_ela_heatmap
        img_bytes = self._make_image()
        heatmap, prob = generate_ela_heatmap(img_bytes)
        assert isinstance(heatmap, Image.Image), "Heatmap should be PIL Image"
        assert heatmap.mode == "RGB", "Heatmap should be RGB"

    def test_ela_probability_range(self):
        from src.forensics.ela import generate_ela_heatmap
        img_bytes = self._make_image()
        _, prob = generate_ela_heatmap(img_bytes)
        assert 0.0 <= prob <= 1.0, f"Probability {prob} out of [0,1] range"

    def test_clean_image_low_ela(self):
        """A clean unedited image should have lower ELA than a tampered one."""
        from src.forensics.ela import generate_ela_heatmap
        clean_bytes    = self._make_image()
        tampered_bytes = self._make_tampered_image()
        _, clean_prob    = generate_ela_heatmap(clean_bytes)
        _, tampered_prob = generate_ela_heatmap(tampered_bytes)
        # We just check tampered >= clean (not a strict threshold)
        assert tampered_prob >= clean_prob, (
            f"Tampered image ({tampered_prob:.3f}) should score >= clean ({clean_prob:.3f})"
        )

    def test_ela_accepts_pil_image(self):
        from src.forensics.ela import generate_ela_heatmap
        img = Image.new("RGB", (100, 100), color=(128, 64, 32))
        heatmap, prob = generate_ela_heatmap(img)
        assert isinstance(heatmap, Image.Image)

    def test_ela_accepts_filepath(self, tmp_path):
        from src.forensics.ela import generate_ela_heatmap
        img = Image.new("RGB", (100, 100), color=(200, 100, 50))
        path = tmp_path / "test_img.jpg"
        img.save(path, format="JPEG")
        heatmap, prob = generate_ela_heatmap(str(path))
        assert isinstance(heatmap, Image.Image)
        assert 0.0 <= prob <= 1.0

    def test_ela_stats(self):
        from src.forensics.ela import ela_stats
        img_bytes = self._make_image()
        stats = ela_stats(img_bytes)
        assert "mean_error" in stats
        assert "std_error"  in stats
        assert "p99_error"  in stats
        assert "max_error"  in stats
        assert all(v >= 0 for v in stats.values())

    def test_ela_heatmap_size_matches_input(self):
        from src.forensics.ela import generate_ela_heatmap
        img_bytes = self._make_image(width=300, height=200)
        heatmap, _ = generate_ela_heatmap(img_bytes)
        assert heatmap.size == (300, 200), f"Expected (300,200), got {heatmap.size}"


# ═══════════════════════════════════════════════════════════════════════════════
# METADATA INSPECTOR TESTS
# ═══════════════════════════════════════════════════════════════════════════════
class TestMetadataInspector:
    """Tests for src/forensics/metadata.py"""

    def test_extract_scam_triggers(self):
        from src.forensics.metadata import extract_pdf_metadata, SCAM_TRIGGERS

        # Create a minimal PDF in memory
        try:
            from reportlab.platypus import SimpleDocTemplate, Paragraph
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib.pagesizes import A4

            buf = io.BytesIO()
            doc = SimpleDocTemplate(buf, pagesize=A4)
            styles = getSampleStyleSheet()
            story = [Paragraph("Pay registration fee of Rs.2000. Join our Telegram channel.", styles["Normal"])]
            doc.build(story)
            pdf_bytes = buf.getvalue()

            result = extract_pdf_metadata(pdf_bytes)
            assert result["risk_score"] > 0, "Scam PDF should have non-zero risk"
            triggers = result.get("scam_triggers_found", {})
            assert len(triggers) > 0, "Should detect at least one scam trigger"
        except ImportError:
            pytest.skip("reportlab not installed")

    def test_suspect_software_detection(self):
        from src.forensics.metadata import SUSPECT_PRODUCERS
        assert "canva" in SUSPECT_PRODUCERS
        assert "photoshop" in SUSPECT_PRODUCERS
        assert "microsoft word 2016" in SUSPECT_PRODUCERS

    def test_mock_fallback_structure(self):
        from src.forensics.metadata import _mock_pdf_metadata
        result = _mock_pdf_metadata()
        required_keys = ["meta", "text", "flags", "risk_score", "scam_triggers_found"]
        for key in required_keys:
            assert key in result, f"Mock result missing key: {key}"

    def test_image_exif_returns_dict(self):
        from src.forensics.metadata import extract_image_exif
        img = Image.new("RGB", (100, 100), color=(200, 200, 200))
        buf = io.BytesIO()
        img.save(buf, format="JPEG")
        result = extract_image_exif(buf.getvalue())
        assert isinstance(result, dict)
        assert "exif" in result


# ═══════════════════════════════════════════════════════════════════════════════
# BANKING MODULE TESTS
# ═══════════════════════════════════════════════════════════════════════════════
class TestBankingModule:
    """Tests for src/forensics/banking.py"""

    def test_ifsc_regex_extraction(self):
        from src.forensics.banking import extract_ifsc_codes
        text = "Please pay to IFSC SBIN0001234. Also see HDFC0009876 and invalid ABCD1234."
        codes = extract_ifsc_codes(text)
        assert "SBIN0001234" in codes, "Should detect SBIN0001234"
        assert "HDFC0009876" in codes, "Should detect HDFC0009876"
        assert "ABCD1234" not in codes, "Invalid code should not match"

    def test_upi_extraction(self):
        from src.forensics.banking import extract_upi_handles
        text = "Pay to fraudjobs@ybl or hiringhub@ibl. Contact hr@company.com (not UPI)."
        handles = extract_upi_handles(text)
        assert "fraudjobs@ybl" in handles
        assert "hiringhub@ibl" in handles
        # hr@company.com ends in .com so should be filtered
        assert "hr@company.com" not in handles

    def test_ifsc_lookup_returns_bank_info(self):
        from src.forensics.banking import lookup_ifsc
        result = lookup_ifsc("SBIN0001234")
        assert isinstance(result, dict)
        assert "BANK" in result
        assert "CITY" in result
        assert len(result["CITY"]) > 0, "CITY should not be empty"

    def test_mule_hub_detection(self):
        from src.forensics.banking import assess_banking_risk, MOCK_IFSC_DB
        import src.forensics.banking as bmod
        original_lookup = bmod.lookup_ifsc

        def mock_lookup(code, timeout=5):
            if code in MOCK_IFSC_DB:
                result = dict(MOCK_IFSC_DB[code])
                result["source"] = "mock"
                return result
            return original_lookup(code, timeout)

        bmod.lookup_ifsc = mock_lookup
        try:
            text = "Pay to ICIC0005555 via UPI fraudjobs@ybl"
            result = assess_banking_risk(text, claimed_hq="Bengaluru")
            assert result["risk_score"] > 30, f"Mule IFSC should trigger high risk, got {result['risk_score']}"
            assert len(result["mule_cities_detected"]) > 0, f"Should detect mule cities"
        finally:
            bmod.lookup_ifsc = original_lookup

    def test_banking_risk_structure(self):
        from src.forensics.banking import assess_banking_risk
        result = assess_banking_risk("No payment info here.")
        required = ["ifsc_codes", "upi_handles", "ifsc_details", "risk_score", "flags"]
        for key in required:
            assert key in result, f"Missing key: {key}"

    def test_ifsc_pattern_format(self):
        """Validate IFSC regex against known formats."""
        from src.forensics.banking import IFSC_PATTERN
        valid_codes = ["SBIN0001234", "HDFC0000001", "ICIC0005555", "UTIB0000009"]
        invalid_codes = ["SBI00001234", "HDFC00009", "ABCDE001234", "sbin0001234"]
        for code in valid_codes:
            assert IFSC_PATTERN.match(code), f"{code} should match IFSC pattern"
        for code in invalid_codes:
            assert not IFSC_PATTERN.match(code), f"{code} should NOT match IFSC pattern"


# ═══════════════════════════════════════════════════════════════════════════════
# SYNDICATE GRAPH TESTS
# ═══════════════════════════════════════════════════════════════════════════════
class TestSyndicateGraph:
    """Tests for src/forensics/network.py"""

    def setup_method(self):
        from src.forensics.network import clear_registry
        clear_registry()

    def test_graph_builds_correctly(self):
        from src.forensics.network import build_syndicate_graph
        entities = {
            "Company": ["TechVision Pvt Ltd"],
            "UPI":     ["fraudjobs@ybl"],
        }
        G, flags, is_syndicate = build_syndicate_graph(entities, doc_label="test_doc.pdf")
        assert G.number_of_nodes() >= 3, "Should have doc node + 2 entity nodes"
        assert is_syndicate, "Known bad actor should be flagged"

    def test_cross_document_syndicate_detection(self):
        from src.forensics.network import register_entities, build_syndicate_graph
        # First document
        register_entities("doc1.pdf", {"UPI": ["shared@ybl"]})
        # Second document with same UPI
        G, flags, is_syndicate = build_syndicate_graph(
            {"UPI": ["shared@ybl"]}, doc_label="doc2.pdf"
        )
        assert is_syndicate, "Shared entity across docs should trigger syndicate flag"

    def test_render_graph_returns_bytes(self):
        from src.forensics.network import build_syndicate_graph, render_graph
        entities = {"Company": ["TestCorp"], "Phone": ["9999999999"]}
        G, _, _ = build_syndicate_graph(entities)
        png_bytes = render_graph(G)
        assert isinstance(png_bytes, bytes), "Should return bytes"
        assert png_bytes[:4] == b'\x89PNG', "Should be a valid PNG"

    def test_empty_graph_renders(self):
        import networkx as nx
        from src.forensics.network import render_graph
        G = nx.DiGraph()
        png_bytes = render_graph(G, "Empty Graph")
        assert isinstance(png_bytes, bytes)


# ═══════════════════════════════════════════════════════════════════════════════
# LEGAL DOSSIER TESTS
# ═══════════════════════════════════════════════════════════════════════════════
class TestLegalDossier:
    """Tests for src/legal/bns_dossier.py"""

    def _mock_findings(self):
        return {
            "overall_risk": 75,
            "metadata_risk": 60,
            "ela_prob": 0.7,
            "ela_summary": "High tampering detected",
            "banking_risk": 80,
            "is_syndicate": True,
            "syndicate_summary": "Shared UPI with 2 other scam documents",
            "ifsc_codes": ["SBIN0001234"],
            "scam_triggers": ["registration fee", "telegram channel"],
            "metadata_flags": ["⚠️ Suspect software: Microsoft Word 2016"],
            "banking_flags": ["🚨 Mule hub: Jamtara"],
            "network_flags": ["🔴 Known bad actor: fraudjobs@ybl"],
            "ela_flags": ["🖼 ELA tampering detected"],
        }

    def test_sha256_hash(self):
        from src.legal.bns_dossier import compute_sha256
        data = b"Hello, InternKavach!"
        h = compute_sha256(data)
        assert len(h) == 64, "SHA-256 should be 64 hex chars"
        assert h == compute_sha256(data), "Hash should be deterministic"
        assert h != compute_sha256(b"Different data"), "Different data should produce different hash"

    def test_dossier_generates_pdf(self):
        from src.legal.bns_dossier import generate_fir_dossier
        findings = self._mock_findings()
        doc_bytes = b"Fake document content for testing"
        pdf = generate_fir_dossier(doc_bytes, "test_offer.pdf", findings)
        assert isinstance(pdf, bytes), "Should return bytes"
        # Check for PDF magic bytes or text report
        assert len(pdf) > 100, "PDF should have substantial content"

    def test_pdf_has_valid_header(self):
        from src.legal.bns_dossier import generate_fir_dossier
        findings = self._mock_findings()
        pdf = generate_fir_dossier(b"Test document", "test.pdf", findings)
        # ReportLab PDFs start with %PDF-
        assert pdf[:4] == b'%PDF', f"Invalid PDF header: {pdf[:10]}"

    def test_legal_provisions_list(self):
        from src.legal.bns_dossier import LEGAL_PROVISIONS
        assert len(LEGAL_PROVISIONS) == 3, "Should have 3 legal provisions"
        sections = [p["section"] for p in LEGAL_PROVISIONS]
        assert any("318" in s for s in sections), "BNS 318 should be listed"
        assert any("336" in s for s in sections), "BNS 336 should be listed"
        assert any("66D" in s for s in sections), "IT Act 66D should be listed"


# ═══════════════════════════════════════════════════════════════════════════════
# AI EVALUATOR TESTS
# ═══════════════════════════════════════════════════════════════════════════════
class TestAIEvaluator:
    """Tests for src/ai/agent_evaluator.py"""

    def test_mock_analysis_structure(self):
        from src.ai.agent_evaluator import _mock_analysis
        result = _mock_analysis("Pay registration fee of Rs.2000 to join.")
        required = ["threat_rating", "verdict", "summary", "red_flags",
                    "syntax_anomalies", "suspicious_clauses", "source"]
        for key in required:
            assert key in result, f"Missing key: {key}"

    def test_mock_scam_text_high_score(self):
        from src.ai.agent_evaluator import _mock_analysis
        scam_text = (
            "Pay registration fee of Rs.2000. "
            "Pay laptop deposit of Rs.3000. "
            "Join Telegram channel. Pay processing fee. "
            "Pay joining fee to confirm your seat."
        )
        result = _mock_analysis(scam_text)
        assert result["threat_rating"] >= 60, f"Scam text should score >= 60, got {result['threat_rating']}"
        assert result["verdict"] in ("SUSPICIOUS", "SCAM")

    def test_mock_clean_text_low_score(self):
        from src.ai.agent_evaluator import _mock_analysis
        clean_text = (
            "We are pleased to offer you an internship. Annual CTC: Rs.3 LPA. "
            "Employee ID will be issued. No fee required. Provident Fund applicable. "
            "Joining date: 1st February 2024. HR Department."
        )
        result = _mock_analysis(clean_text)
        assert result["threat_rating"] <= 40, f"Clean text should score <= 40, got {result['threat_rating']}"

    def test_verdict_valid_values(self):
        from src.ai.agent_evaluator import _mock_analysis
        result = _mock_analysis("Any text here.")
        assert result["verdict"] in ("CLEAN", "SUSPICIOUS", "SCAM")

    def test_evaluate_document_returns_dict(self):
        from src.ai.agent_evaluator import evaluate_document
        result = evaluate_document("This is a test internship offer.")
        assert isinstance(result, dict)
        assert "threat_rating" in result
        assert "verdict" in result


# ═══════════════════════════════════════════════════════════════════════════════
# INTEGRATION TEST
# ═══════════════════════════════════════════════════════════════════════════════
class TestIntegration:
    """End-to-end pipeline test."""

    def test_full_pipeline_on_scam_text(self):
        """Run all modules on synthetic scam data and verify risk signals."""
        from src.forensics.metadata import _mock_pdf_metadata
        from src.forensics.banking  import assess_banking_risk
        from src.forensics.network  import build_syndicate_graph, clear_registry
        from src.ai.agent_evaluator  import _mock_analysis
        from src.legal.bns_dossier  import compute_sha256, generate_fir_dossier

        clear_registry()

        scam_text = (
            "Pay registration fee of Rs.1500 to SBIN0001234 (IFSC). "
            "UPI: fraudjobs@ybl. Join Telegram channel. "
            "Laptop security deposit Rs.3000. Limited seats — pay within 24 hours."
        )

        # Metadata mock
        meta = _mock_pdf_metadata()
        assert meta["risk_score"] > 0

        # Banking
        banking = assess_banking_risk(scam_text, claimed_hq="Bengaluru")
        assert banking["risk_score"] > 0
        assert len(banking["ifsc_codes"]) > 0

        # Graph
        G, flags, is_syndicate = build_syndicate_graph(
            {"UPI": banking["upi_handles"], "IFSC": banking["ifsc_codes"]},
            doc_label="test_integration.pdf",
        )
        assert G.number_of_nodes() >= 1

        # AI
        ai = _mock_analysis(scam_text)
        assert ai["verdict"] in ("SUSPICIOUS", "SCAM")

        # Dossier
        doc_bytes = scam_text.encode("utf-8")
        h = compute_sha256(doc_bytes)
        assert len(h) == 64

        findings = {
            "overall_risk": 80,
            "metadata_risk": meta["risk_score"],
            "ela_prob": 0.65,
            "ela_summary": "High ELA risk",
            "banking_risk": banking["risk_score"],
            "is_syndicate": is_syndicate,
            "syndicate_summary": "Test",
            "ifsc_codes": banking["ifsc_codes"],
            "scam_triggers": list(meta["scam_triggers_found"].keys()),
            "metadata_flags": meta["flags"],
            "banking_flags": banking["flags"],
            "network_flags": flags,
            "ela_flags": [],
        }
        pdf = generate_fir_dossier(doc_bytes, "scam_test.pdf", findings)
        assert pdf[:4] == b'%PDF', "Should produce valid PDF"

        print("\n✅ Full integration test passed!")
        print(f"   Banking risk:  {banking['risk_score']}")
        print(f"   AI verdict:    {ai['verdict']} ({ai['threat_rating']})")
        print(f"   Is syndicate:  {is_syndicate}")
        print(f"   PDF size:      {len(pdf):,} bytes")


# ═══════════════════════════════════════════════════════════════════════════════
# DOCUMENT CLASSIFIER GATEKEEPER TESTS
# ═══════════════════════════════════════════════════════════════════════════════
class TestDocumentClassifier:
    """Tests for src/ai/document_classifier.py gatekeeper."""

    def test_classifier_accepts_offer_letter(self):
        from src.ai.document_classifier import classify_document_type
        offer_bytes = b"%PDF-1.4\nInternship Offer Letter. We are pleased to offer you a position as Software Intern. Stipend: Rs.20000."
        res = classify_document_type(offer_bytes, mime_type="application/pdf", text_content="Internship Offer Letter. We are pleased to offer you a position as Software Intern. Stipend: Rs.20000.")
        assert res["is_recruitment_document"] is True
        assert "offer" in res["detected_type"].lower() or "internship" in res["detected_type"].lower()
        assert res["confidence"] > 0

    def test_classifier_rejects_resume(self):
        from src.ai.document_classifier import classify_document_type
        resume_text = "Curriculum Vitae\nName: John Doe\nEducation: B.Tech\nTechnical Skills: Python\nWork Experience: Intern"
        res = classify_document_type(resume_text.encode("utf-8"), mime_type="application/pdf", text_content=resume_text)
        assert res["is_recruitment_document"] is False
        assert "resume" in res["detected_type"].lower() or "non-recruitment" in res["detected_type"].lower()
        assert res["rejection_reason"] is not None

    def test_classifier_extensibility_routing(self):
        from src.ai.document_classifier import get_pipeline_route, is_recruitment_category, DocumentCategory
        assert get_pipeline_route(DocumentCategory.OFFER_LETTER.value) == "internship_fraud_pipeline"
        assert get_pipeline_route(DocumentCategory.LOAN_APPROVAL_NOTICE.value) == "loan_fraud_pipeline"
        assert is_recruitment_category("Internship Offer Letter") is True
        assert is_recruitment_category("Utility Bill") is False


if __name__ == "__main__":
    # Quick manual run
    import subprocess
    result = subprocess.run(
        [sys.executable, "-m", "pytest", __file__, "-v", "--tb=short"],
        cwd=str(ROOT),
    )
    sys.exit(result.returncode)
