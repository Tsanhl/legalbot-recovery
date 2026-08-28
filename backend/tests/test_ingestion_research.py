from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from backend.app.research import (
    ContentMode,
    CoverageGapDetector,
    GapKind,
    GapQueue,
    GapStatus,
    OfficialSourceRegistry,
    OnlineDisposition,
    SubjectCoverage,
    adapter_registry,
)


class OfficialSourcePolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        project_root = Path(__file__).resolve().parents[2]
        cls.registry = OfficialSourceRegistry.load(
            project_root / "config" / "official_sources.json"
        )
        cls.adapters = adapter_registry(cls.registry)

    def test_every_online_source_is_staged_only(self) -> None:
        self.assertTrue(self.registry.all())
        self.assertEqual(
            {policy.online_disposition for policy in self.registry.all()},
            {OnlineDisposition.STAGED_ONLY},
        )

    def test_find_case_law_is_metadata_only_and_rejects_judgment_bytes(self) -> None:
        policy = self.registry.get("find_case_law")
        adapter = self.adapters["find_case_law"]
        plan = adapter.plan("ewhc/ch/2025/17")
        self.assertEqual(policy.content_mode, ContentMode.METADATA_ONLY)
        self.assertEqual(plan.expected_content_mode, ContentMode.METADATA_ONLY)
        self.assertNotIn("data.xml", plan.url)
        with self.assertRaises(PermissionError):
            adapter.stage(
                canonical_url=plan.url,
                identity="[2025] EWHC 17 (Ch)",
                metadata={"neutral_citation": "[2025] EWHC 17 (Ch)"},
                content=b"judgment full text",
            )
        staged = adapter.stage(
            canonical_url=plan.url,
            identity="[2025] EWHC 17 (Ch)",
            metadata={"neutral_citation": "[2025] EWHC 17 (Ch)"},
            content=None,
        )
        self.assertIsNone(staged.content)
        self.assertEqual(staged.disposition, "staged_only")
        self.assertEqual(staged.review_state, "unreviewed")

    def test_legislation_adapter_plans_machine_readable_xml(self) -> None:
        plan = self.adapters["legislation_gov_uk"].plan("ukpga/2010/15")
        self.assertEqual(plan.expected_content_mode, ContentMode.FULL_TEXT)
        self.assertEqual(plan.url, "https://www.legislation.gov.uk/ukpga/2010/15/data.xml")
        self.assertEqual(plan.headers["Accept"], "application/xml")

    def test_eu_and_echr_adapters_are_registered_and_stage_only(self) -> None:
        eur_lex = self.adapters["eur_lex"].plan("32016R0679")
        self.assertIn("CELEX:32016R0679", eur_lex.url)
        self.assertEqual(eur_lex.expected_content_mode, ContentMode.FULL_TEXT)
        for source_id, identity in (("curia", "C-311/18"), ("hudoc", "001-203165")):
            plan = self.adapters[source_id].plan(identity)
            self.assertEqual(plan.expected_content_mode, ContentMode.METADATA_ONLY)
            with self.assertRaises(PermissionError):
                self.adapters[source_id].stage(
                    canonical_url=plan.url,
                    identity=identity,
                    metadata={},
                    content=b"full text",
                )


class GapQueueTests(unittest.TestCase):
    def test_candidates_can_only_be_staged_for_review_not_promoted(self) -> None:
        with TemporaryDirectory() as directory:
            queue = GapQueue(Path(directory) / "gaps.json", allow_writes=True)
            gap = queue.enqueue(
                subject="land_law",
                jurisdiction="england_wales",
                kind=GapKind.CASE_AUTHORITY,
                reason_code="missing_binding_authority",
                description="No reviewed binding authority is mapped.",
                priority=90,
            )
            staged = queue.stage_candidate(
                gap.gap_id,
                source_id="find_case_law",
                source_identity="neutral_citation:[2025] UKSC 1",
                canonical_url="https://caselaw.nationalarchives.gov.uk/uksc/2025/1",
                metadata={"title": "Example", "neutral_citation": "[2025] UKSC 1"},
            )
            self.assertEqual(staged.status, GapStatus.CANDIDATE_STAGED)
            self.assertEqual(len(staged.candidates), 1)
            self.assertFalse(hasattr(queue, "promote"))
            reviewed = queue.require_review(gap.gap_id)
            self.assertEqual(reviewed.status, GapStatus.REVIEW_REQUIRED)
            self.assertEqual(queue.list()[0].candidates[0].source_id, "find_case_law")

    def test_coverage_detector_creates_specific_research_gaps(self) -> None:
        with TemporaryDirectory() as directory:
            queue = GapQueue(Path(directory) / "gaps.json", allow_writes=True)
            created = CoverageGapDetector(queue).inspect(
                SubjectCoverage(
                    subject="evidence",
                    jurisdiction="england_wales",
                    sources_with_currentness_flags=1,
                    sources_without_citation_metadata=1,
                )
            )
            self.assertEqual(len(created), 6)
            kinds = {item.kind for item in queue.list()}
            self.assertIn(GapKind.LEGISLATION, kinds)
            self.assertIn(GapKind.CASE_AUTHORITY, kinds)
            self.assertIn(GapKind.COMMENCEMENT_OR_EFFECT, kinds)
            self.assertIn(GapKind.CITATION_METADATA, kinds)
            repeated = CoverageGapDetector(queue).inspect(
                SubjectCoverage(
                    subject="evidence",
                    jurisdiction="england_wales",
                    sources_with_currentness_flags=1,
                    sources_without_citation_metadata=1,
                )
            )
            self.assertEqual(set(repeated), set(created))
            self.assertEqual(len(queue.list()), 6)


if __name__ == "__main__":
    unittest.main()
