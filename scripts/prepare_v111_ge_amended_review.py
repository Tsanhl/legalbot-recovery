"""Create a successor GE owner-review pack; never execute or export training.

Every output is create-only. Originals and private unseen bytes remain unchanged.
Private prompts are hashed, never decoded. No cleanup is performed.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import html
import json
import os
import re
import stat
import zipfile
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from prepare_v111_ge_owner_review import (
    BASE,
    PRIVATE_NAME,
    PRIVATE_PIN,
    PRIVATE_ZIP_PIN,
    VISIBLE_NAME,
    VISIBLE_PIN,
    canonical,
    member,
    sha,
    verify_package,
)

ROOT = Path(__file__).resolve().parents[1]
SOURCE_REVIEW = ROOT / "data/evaluations/general-enquiries/LegalBot-GE-2026-08-31-review-r2"
PROPOSALS = ROOT / "data/evaluations/general-enquiries/LegalBot-GE-2026-09-01-amendments-r1"
VISIBLE_RECORDS_PIN = "d1b6f72552dee49ca6380d3016f4908453b93a67f5cb639b19bc741c168075d5"
DECISIONS = ["UNREVIEWED", "KEEP", "AMEND", "MOVE", "EXCLUDE_FROM_SCORING"]


def write_new(path: Path, value: str | bytes) -> None:
    with path.open("xb") as handle:
        handle.write(value.encode() if isinstance(value, str) else value)


def json_new(path: Path, value: Any) -> None:
    write_new(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def short_scope(value: str) -> str:
    return {
        "ENGLAND_AND_WALES": "England and Wales",
        "UNITED_KINGDOM": "UK - applicability must be checked",
        "UNITED_KINGDOM_NATION_CHECK_REQUIRED": "UK nation must be clarified",
        "CROSS_BORDER": "Cross-border - applicable law must be checked",
        "EUROPEAN_UNION": "European Union",
        "SCOTLAND": "Scotland",
        "FRANCE": "France",
    }.get(value, value)


def verify_inputs() -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    receipts = [
        verify_package(BASE / VISIBLE_NAME, VISIBLE_PIN),
        verify_package(BASE / PRIVATE_NAME, PRIVATE_PIN),
    ]
    private_zip = member(BASE, PRIVATE_NAME + ".zip")
    if sha(private_zip) != PRIVATE_ZIP_PIN or stat.S_IMODE(private_zip.stat().st_mode) != 0o600:
        raise ValueError("private ZIP identity or mode mismatch")
    custody = json.loads(member(BASE / PRIVATE_NAME, "PRIVATE-CUSTODY-REGISTRY.json").read_text())
    if custody["question_count"] != 306 or custody["topic_count"] != 17:
        raise ValueError("unexpected private custody counts")
    source = member(SOURCE_REVIEW, "VISIBLE-GE-SET.jsonl")
    if sha(source) != VISIBLE_RECORDS_PIN:
        raise ValueError("visible predecessor changed")
    rows = [json.loads(line) for line in source.read_text().splitlines()]
    if len(rows) != 331 or len({r["question_id"] for r in rows}) != 331:
        raise ValueError("visible predecessor completeness mismatch")
    if Counter("stress" if "STRESS" in r["lane"] else "core" for r in rows) != {
        "core": 306,
        "stress": 25,
    }:
        raise ValueError("visible predecessor lane counts mismatch")
    for row in rows:
        parent = {k: v for k, v in row.items() if k != "record_content_sha256"}
        if hashlib.sha256(canonical(parent)).hexdigest() != row["record_content_sha256"]:
            raise ValueError("predecessor record digest mismatch")
    proposals: dict[str, dict[str, Any]] = {}
    for filename in ["topics-a.json", "topics-b.json"]:
        payload = json.loads(member(PROPOSALS, filename).read_text())
        if payload["authorizing"]:
            raise ValueError("amendment must not authorize anything")
        for row in payload["records"]:
            if row["question_id"] in proposals:
                raise ValueError("overlapping amendment IDs")
            proposals[row["question_id"]] = row
    if set(proposals) != {r["question_id"] for r in rows}:
        raise ValueError("amendment coverage must be exactly 331")
    merged = []
    for ordinal, parent in enumerate(rows, 1):
        proposal = proposals[parent["question_id"]]
        needed = {
            "prompt",
            "amendment_reason",
            "scenario_family_id",
            "prompt_style",
            "indispensable_facts",
            "helpful_facts",
            "safe_first_response",
            "clarification_strategy",
            "initial_question_budget",
            "conclusion_requires",
            "dimensions",
        }
        if not needed.issubset(proposal):
            raise ValueError("incomplete case review criteria")
        if not isinstance(proposal["prompt"], str) or not proposal["prompt"].strip():
            raise ValueError("empty prompt")
        if len(proposal["indispensable_facts"]) > 3 or len(proposal["helpful_facts"]) > 2:
            raise ValueError("unbounded clarification checklist")
        if not 0 <= proposal["initial_question_budget"] <= 3:
            raise ValueError("invalid proposed clarification budget")
        if proposal["prompt_style"] not in {"NATURAL_GE", "TARGETED_ISSUE"}:
            raise ValueError("invalid prompt style")
        if proposal["clarification_strategy"] not in {
            "answer_then_clarify",
            "conditional_answer",
            "ask_before_definite_conclusion",
            "no_clarification_needed",
        }:
            raise ValueError("invalid clarification strategy")
        required_dimensions = {
            "difficulty",
            "urgency",
            "safety",
            "currentness",
            "structure",
            "robustness",
        }
        if set(proposal["dimensions"]) != required_dimensions:
            raise ValueError("incomplete scenario dimensions")
        if re.search(r"/Users/|/home/|LegalBot-New|cp-[ds]\d{2}", proposal["prompt"]):
            raise ValueError("private path or evaluation ID in question")
        current = dict(parent)
        current.update(
            {
                "schema": "legalbot.ge-visible-owner-review-candidate.v3",
                "question_version_id": parent["question_id"] + ":r3",
                "content_version": "GE-visible-r3",
                "prompt": proposal["prompt"],
                "source_record_content_sha256": parent["record_content_sha256"],
                "source_content_version": "GE-visible-r2",
                "source_review_ordinal": ordinal,
                "prompt_changed": proposal["prompt"] != parent["prompt"],
                "amendment_reason": proposal["amendment_reason"],
                "scenario_family_id": proposal["scenario_family_id"],
                "prompt_style": proposal["prompt_style"],
                "proposed_dimensions": proposal["dimensions"],
                "proposed_clarification_criteria": {
                    k: proposal[k]
                    for k in [
                        "indispensable_facts",
                        "helpful_facts",
                        "safe_first_response",
                        "clarification_strategy",
                        "initial_question_budget",
                        "conclusion_requires",
                    ]
                },
                "usage_role": "VISIBLE_DEVELOPMENT_EVALUATION_REVIEW_ONLY",
                "training_export_eligible": False,
                "unseen_eligible": False,
                "owner_wording_decision": "UNREVIEWED",
                "legal_gold_approved": False,
                "admitted_source_version": None,
                "currentness_verified_at": None,
                "next_mandatory_review_at": None,
                "do_not_train_as_timeless_rule": True,
            }
        )
        current.pop("record_content_sha256")
        current["record_content_sha256"] = hashlib.sha256(canonical(current)).hexdigest()
        if any(
            current[k]
            for k in [
                "answer_model_authorized",
                "retrieval_authorized",
                "phase2b_authorized",
                "scored_evaluation_eligible",
                "gold_answer_created",
            ]
        ):
            raise ValueError("review record unexpectedly authorizing")
        if parent["safety_refusal_required"] and re.search(
            r"what.{0,40}(refus|must be refused)", current["prompt"], re.I
        ):
            raise ValueError("refusal answer cue remains in an amended refusal prompt")
        merged.append(current)
    if len({r["prompt"] for r in merged}) != 331:
        raise ValueError("exact duplicate amended prompts")
    system = json.loads(member(PROPOSALS, "system-scenarios.json").read_text())["records"]
    if len(system) != 32 or len({r["system_case_id"] for r in system}) != 32:
        raise ValueError("system suite completeness mismatch")
    if any(r["execution_authorized"] for r in system):
        raise ValueError("system review must not authorize execution")
    details = {
        "source_receipts": receipts,
        "custody": custody,
        "private_zip": private_zip,
        "original_rows": rows,
    }
    return merged, system, details


def build_pdf(
    path: Path,
    rows: list[dict[str, Any]],
    system: list[dict[str, Any]],
    topics: list[dict[str, Any]],
    run_id: str,
) -> dict[str, Any]:
    import reportlab
    from pypdf import PdfReader
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import (
        BaseDocTemplate,
        Flowable,
        Frame,
        HRFlowable,
        PageBreak,
        PageTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
    )

    font_root = Path(reportlab.__file__).parent / "fonts"
    pdfmetrics.registerFont(TTFont("GEReview", str(font_root / "Vera.ttf")))
    pdfmetrics.registerFont(TTFont("GEReviewBold", str(font_root / "VeraBd.ttf")))
    pdfmetrics.registerFontFamily("GEReview", normal="GEReview", bold="GEReviewBold")
    navy, teal, grey = [colors.HexColor(s) for s in ["#17384B", "#176E73", "#526574"]]
    styles = {
        "title": ParagraphStyle(
            "title", fontName="GEReviewBold", fontSize=26, leading=31, textColor=navy, spaceAfter=14
        ),
        "h1": ParagraphStyle(
            "h1", fontName="GEReviewBold", fontSize=18, leading=23, textColor=navy, spaceAfter=12
        ),
        "body": ParagraphStyle(
            "body", fontName="GEReview", fontSize=10, leading=14.5, textColor=navy, spaceAfter=10
        ),
        "prompt": ParagraphStyle(
            "prompt", fontName="GEReview", fontSize=10.2, leading=14.1, textColor=navy, spaceAfter=7
        ),
        "small": ParagraphStyle(
            "small", fontName="GEReview", fontSize=7.6, leading=10.2, textColor=grey, spaceAfter=4
        ),
        "id": ParagraphStyle(
            "id", fontName="GEReviewBold", fontSize=8, leading=11, textColor=teal, spaceAfter=5
        ),
        "head": ParagraphStyle(
            "head", fontName="GEReviewBold", fontSize=8, leading=11, textColor=colors.white
        ),
        "cell": ParagraphStyle("cell", fontName="GEReview", fontSize=8, leading=11, textColor=navy),
    }

    def p(text: str, style: str = "body") -> Any:
        return Paragraph(html.escape(text), styles[style])

    class ReviewDoc(BaseDocTemplate):
        def afterFlowable(self, flowable: Any) -> None:
            key = getattr(flowable, "bookmark_key", None)
            if key:
                self.canv.bookmarkPage(key)
                self.canv.addOutlineEntry(flowable.getPlainText(), key, 0, False)

    class ReviewCard(Flowable):
        def __init__(self, key: str, paragraphs: list[Any]) -> None:
            super().__init__()
            self.key, self.paragraphs = key, paragraphs
            self.parts: list[tuple[Any, float]] = []

        def wrap(self, avail_width: float, avail_height: float) -> tuple[float, float]:
            self.width = avail_width
            self.parts = []
            total = 10.0
            for para in self.paragraphs:
                _, height = para.wrap(avail_width - 16, avail_height)
                self.parts.append((para, height))
                total += height + para.style.spaceAfter
            self.height = total + 72
            if self.height > 720:
                raise ValueError("question card too tall for a complete page")
            return avail_width, self.height

        def draw(self) -> None:
            canvas = self.canv
            y = self.height - 8
            for para, height in self.parts:
                y -= height
                para.drawOn(canvas, 8, y)
                y -= para.style.spaceAfter
            canvas.setFillColor(grey)
            canvas.setFont("GEReview", 7.4)
            canvas.drawString(8, y - 9, "Owner wording decision:")
            canvas.acroForm.choice(
                name=f"decision_{self.key}",
                tooltip=f"Wording decision {self.key}",
                value="UNREVIEWED",
                options=DECISIONS,
                x=115,
                y=y - 14,
                width=165,
                height=17,
                fontName="Helvetica",
                fontSize=7.8,
                borderWidth=0.6,
                borderColor=teal,
                fillColor=colors.HexColor("#F4F8FA"),
                textColor=navy,
                fieldFlags="combo",
                relative=True,
                forceBorder=True,
            )
            canvas.drawString(291, y - 9, "Notes / proposed wording:")
            canvas.acroForm.textfield(
                name=f"notes_{self.key}",
                tooltip=f"Notes or proposed wording {self.key}; no personal matter information",
                value="",
                x=8,
                y=y - 56,
                width=self.width - 16,
                height=35,
                fontName="Helvetica",
                fontSize=8,
                borderWidth=0.5,
                borderColor=colors.HexColor("#BFCDD5"),
                fillColor=colors.white,
                textColor=navy,
                fieldFlags="multiline",
                maxlen=3000,
                relative=True,
                forceBorder=True,
            )
            canvas.setStrokeColor(colors.HexColor("#D5E0E6"))
            canvas.line(0, 1, self.width, 1)

    def footer(canvas: Any, doc: Any) -> None:
        canvas.saveState()
        width, height = A4
        canvas.setFont("GEReview", 7)
        canvas.setFillColor(grey)
        canvas.drawString(
            42, 22, "GE-visible-r3 | Owner review only | No unseen prompts or approved gold"
        )
        canvas.drawRightString(width - 42, 22, f"Page {doc.page}")
        if doc.page > 1:
            canvas.setFont("GEReviewBold", 7.2)
            canvas.setFillColor(teal)
            canvas.drawString(
                42, height - 25, "GENERAL ENQUIRIES / AMENDED FULL REVIEW / 1 SEPTEMBER 2026"
            )
            canvas.linkRect(
                "Topic index",
                "topic-index",
                (width - 108, height - 32, width - 42, height - 18),
                relative=0,
                thickness=0,
            )
            canvas.drawRightString(width - 42, height - 25, "TOPIC INDEX")
        canvas.restoreState()

    story: list[Any] = [
        Spacer(1, 30),
        p("GENERAL ENQUIRIES", "title"),
        p("Amended full owner-review pack", "h1"),
        p("331 visible legal questions + 32 separate system scenarios"),
        HRFlowable(width="100%", thickness=2, color=teal),
        Spacer(1, 16),
    ]
    intro = [
        "Content: GE-visible-r3. Review layout: 1.0. Generated: 1 September 2026. Supersedes the visible-r2 review for new wording review only; every predecessor remains preserved.",
        f"All 331 original case IDs are retained. {sum(r['prompt_changed'] for r in rows)} prompts changed; every case has proposed clarification criteria, scenario dimensions and a family identifier. Full before/after records and digests are in the companion change log.",
        "Default product scope is England and Wales. Each case retains its recorded jurisdiction: explicit Scottish, EU, UK-nation or cross-border facts override a generic default. A review label is not a user-provided fact or proof that the jurisdiction has been qualified.",
        "The inherited legal-currentness cutoff is 28 August 2026. It is not a verification date. No gold answers, admitted source versions or new legal-currentness decisions are created here. Administrative Law and Wills/Estates remain source-admission pending.",
        "The 306-question private unseen bank remains content-r2, separate and unchanged. Its prompts are absent from this book. Independent custody review and overlap checks are still needed before any one-pass test.",
        "These visible cases support future development evaluation, not a training export or unseen test. The pack includes training preparation rules, but zero approved training examples. No evaluation, training, source admission, promotion or live run is authorized.",
        "Strict preservation: nothing is deleted unless the owner explicitly requests deletion. Excluding a case from scoring never deletes the question or its history.",
    ]
    story.extend(p(text) for text in intro)
    story.extend([PageBreak(), p("How to review", "h1")])
    for text in [
        "Use the fillable decision and notes fields on each card, or the companion Markdown/JSON files. Save an annotated copy under a new filename; preserve this immutable review original and its checksums. Do not place personal matter information in notes.",
        "KEEP means proposed wording is acceptable; AMEND requests wording or criteria changes; MOVE proposes a different topic/routing label; EXCLUDE_FROM_SCORING proposes future ineligibility. None deletes records, approves law/gold, freezes a split or authorizes execution. UNREVIEWED is not acceptance.",
        "Recorded scope/date and source flags are inherited draft metadata. Proposed dimensions and clarification criteria need owner review. The initial-question number is a proposed burden limit, not an instruction to ask unnecessary questions or a new approved scoring rule.",
        "The model must not receive this review book or its IDs, lane names, flags, family labels or criteria. A separate prompt-only preview is supplied for review of the boundary; it is not an authorized request payload.",
        "Review usefulness for ordinary people, preservation of material facts, whether necessary questions are specific, and whether a conditional or limited answer could help. Related variants must be grouped honestly rather than counted as independent competence.",
        "The 32 system scenarios are separate from the 331 doctrinal questions. Their synthetic fixtures and required fault injection are part of each scenario; they are not all standalone model prompts.",
    ]:
        story.append(p(text))
    story.extend([PageBreak()])
    heading = p("Topic index", "h1")
    heading.bookmark_key = "topic-index"
    story.append(heading)
    data = [[p("Topic", "head"), p("Core", "head"), p("Stress", "head"), p("Readiness", "head")]]
    for topic in topics:
        state = (
            "Source admission pending"
            if topic["topic_id"] in {"administrative-law", "wills-and-estates"}
            else "Review only; not scored"
        )
        data.append(
            [
                p(topic["display_name"], "cell"),
                p(str(topic["core_question_count"]), "cell"),
                p(str(topic["stress_question_count"]), "cell"),
                p(state, "cell"),
            ]
        )
    table = Table(data, colWidths=[225, 42, 54, A4[0] - 84 - 321], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), navy),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#EFF5F8"), colors.white]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    story.extend(
        [
            table,
            Spacer(1, 14),
            p("Appendix: 32 synthetic system-behaviour scenarios, separately counted.", "small"),
        ]
    )
    ordinal = 0
    for topic in topics:
        story.append(PageBreak())
        title = p(topic["display_name"], "h1")
        title.bookmark_key = topic["topic_id"]
        story.append(title)
        story.append(
            p(
                "All case criteria below are proposed owner-review aids, not approved legal gold.",
                "small",
            )
        )
        for row in [r for r in rows if r["topic_id"] == topic["topic_id"]]:
            ordinal += 1
            criteria = row["proposed_clarification_criteria"]
            dims = row["proposed_dimensions"]
            status = "AMENDED" if row["prompt_changed"] else "WORDING RETAINED"
            source_lane = "stress" if "STRESS" in row["lane"] else "core"
            paras = [
                p(f"{ordinal:03d}  {row['question_id']}  |  {status}", "id"),
                p(row["prompt"], "prompt"),
            ]
            paras.append(
                p(
                    f"Recorded scope: {short_scope(row['primary_jurisdiction'])} | cutoff: {row['legal_currentness_cutoff']} | source lane: {source_lane}",
                    "small",
                )
            )
            paras.append(
                p(
                    f"Proposed: {dims['difficulty']} / urgency {dims['urgency']} / safety {dims['safety']} / {dims['currentness']} / {dims['structure']}",
                    "small",
                )
            )
            if criteria["indispensable_facts"]:
                paras.append(
                    p(
                        "Before a definite conclusion: "
                        + " | ".join(criteria["indispensable_facts"]),
                        "small",
                    )
                )
            if criteria["helpful_facts"]:
                paras.append(p("Helpful: " + " | ".join(criteria["helpful_facts"]), "small"))
            paras.append(p("Safe first response: " + criteria["safe_first_response"], "small"))
            paras.append(
                p(
                    f"Strategy: {criteria['clarification_strategy'].replace('_', ' ')} | proposed initial questions: up to {criteria['initial_question_budget']} | family: {row['scenario_family_id']}",
                    "small",
                )
            )
            story.extend([ReviewCard(f"q{ordinal:03d}", paras), Spacer(1, 10)])
    story.append(PageBreak())
    heading = p("System-behaviour appendix", "h1")
    heading.bookmark_key = "system-suite"
    story.append(heading)
    story.append(
        p(
            "32 separate scenarios. Synthetic fixtures are required; no execution or legal gold is supplied.",
            "small",
        )
    )
    for index, row in enumerate(system, 1):
        paras = [p(row["system_case_id"] + " | " + row["title"], "id")]
        paras.extend(
            p(turn["role"].capitalize() + ": " + turn["content"], "prompt")
            for turn in row["user_turns"]
        )
        paras.append(p("Fixture: " + row["fixture"], "small"))
        paras.append(p("Expected behaviour: " + " | ".join(row["expected_behaviour"]), "small"))
        paras.append(p("Must not: " + " | ".join(row["prohibited_behaviour"]), "small"))
        story.extend([ReviewCard(f"s{index:03d}", paras), Spacer(1, 10)])
    with path.open("xb") as stream:
        doc = ReviewDoc(
            stream,
            pagesize=A4,
            leftMargin=42,
            rightMargin=42,
            topMargin=48,
            bottomMargin=43,
            title="General Enquiries - Amended Full Owner Review",
            author="LegalBot",
        )
        doc.addPageTemplates(
            PageTemplate(
                id="review",
                frames=[
                    Frame(
                        42,
                        43,
                        A4[0] - 84,
                        A4[1] - 91,
                        leftPadding=0,
                        rightPadding=0,
                        topPadding=0,
                        bottomPadding=0,
                    )
                ],
                onPage=footer,
            )
        )
        doc.build(story)
    reader = PdfReader(path)
    extracted = " ".join(" ".join((page.extract_text() or "").split()) for page in reader.pages)
    for row in rows:
        if row["question_id"] not in extracted or " ".join(row["prompt"].split()) not in extracted:
            raise ValueError("PDF missing a complete visible prompt")
    for row in system:
        if row["system_case_id"] not in extracted:
            raise ValueError("PDF missing a system case")
        for turn in row["user_turns"]:
            if " ".join(turn["content"].split()) not in extracted:
                raise ValueError("PDF missing a system turn")
    fields = reader.get_fields() or {}
    if len(fields) != 2 * (331 + 32):
        raise ValueError("PDF interactive-field count mismatch")
    for name, field in fields.items():
        expected = "UNREVIEWED" if name.startswith("decision_") else ""
        if str(field.get("/V", "")) != expected:
            raise ValueError("PDF owner-decision default mismatch")
    widgets = []
    for page in reader.pages:
        for ref in page.get("/Annots", []):
            annotation = ref.get_object()
            if annotation.get("/Subtype") == "/Widget":
                widgets.append(annotation)
                if not annotation.get("/AP", {}).get("/N"):
                    raise ValueError("PDF widget has no appearance")
    if len(widgets) != len(fields):
        raise ValueError("PDF widget/tree mismatch")
    return {
        "path": str(path.relative_to(ROOT)),
        "sha256": sha(path),
        "pages": len(reader.pages),
        "visible_prompts_verified": 331,
        "system_cases_verified": 32,
        "fillable_fields": len(fields),
        "all_decisions_unreviewed": True,
        "content_version": "GE-visible-r3",
        "layout_version": "1.0",
        "run_id": run_id,
    }


def prepare(run_id: str) -> dict[str, Any]:
    if not re.fullmatch(r"LegalBot-GE-2026-09-01-review-r[3-9]\d*", run_id):
        raise ValueError("invalid create-only review run ID")
    rows, system, details = verify_inputs()
    original = {r["question_id"]: r for r in details["original_rows"]}
    registry = json.loads(
        member(BASE / VISIBLE_NAME, "VISIBLE-QUESTION-BANK-REGISTRY.json").read_text()
    )
    topics = registry["topics"]
    out = ROOT / "data/evaluations/general-enquiries" / run_id
    pdf = ROOT / "output/pdf" / f"{run_id}.pdf"
    bundle = ROOT / "output" / f"{run_id}-visible.zip"
    if out.exists() or pdf.exists() or bundle.exists():
        raise FileExistsError("preserve outputs; select a new immutable run revision")
    out.mkdir(parents=True)
    pdf.parent.mkdir(parents=True, exist_ok=True)
    write_new(
        out / "GE-VISIBLE-REVIEW.jsonl",
        "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows),
    )
    projection = [{"question": r["prompt"], "task_type": "general"} for r in rows]
    if any(set(r) != {"question", "task_type"} for r in projection):
        raise ValueError("model-input preview contains evaluator metadata")
    write_new(
        out / "PROMPT-PROJECTION-PREVIEW.jsonl",
        "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in projection),
    )
    json_new(
        out / "PROMPT-MAP-EVALUATOR-ONLY.json",
        {
            "authorizing": False,
            "must_not_enter_model_context": True,
            "records": [
                {
                    "projection_line": i,
                    "question_id": r["question_id"],
                    "question_version_id": r["question_version_id"],
                    "projection_sha256": hashlib.sha256(canonical(projection[i - 1])).hexdigest(),
                }
                for i, r in enumerate(rows, 1)
            ],
        },
    )
    json_new(
        out / "SYSTEM-SCENARIOS.json",
        {"schema": "legalbot.ge-system-scenarios.v1", "authorizing": False, "records": system},
    )
    review = [
        "# Full amended GE set - content r3\n",
        "All 331 original identities retained. Wording and criteria are proposals, not legal gold. Save review annotations in a new copy; do not overwrite predecessor artifacts.\n",
    ]
    changes = []
    decisions = []
    for topic in topics:
        review.append(f"## {topic['display_name']}\n")
        for row in [r for r in rows if r["topic_id"] == topic["topic_id"]]:
            before = original[row["question_id"]]
            c = row["proposed_clarification_criteria"]
            review.extend(
                [
                    f"### {row['source_review_ordinal']:03d} {row['question_id']}\n",
                    row["prompt"] + "\n",
                    f"Recorded jurisdiction: {short_scope(row['primary_jurisdiction'])}. Inherited cutoff: {row['legal_currentness_cutoff']} (not verification).\n",
                    f"Source readiness: `{row['topic_execution_status']}`. Prompt style: {row['prompt_style']}. Family: `{row['scenario_family_id']}`.\n",
                    "Proposed dimensions: "
                    + json.dumps(row["proposed_dimensions"], ensure_ascii=False)
                    + "\n",
                    "Before a definite conclusion: "
                    + (
                        "; ".join(c["indispensable_facts"])
                        or "No additional facts required for the proposed limited response."
                    )
                    + "\n",
                    "Helpful facts: " + ("; ".join(c["helpful_facts"]) or "None specified.") + "\n",
                    "Safe first response: " + c["safe_first_response"] + "\n",
                    "Conclusion that must wait: "
                    + (c["conclusion_requires"] or "None specified.")
                    + "\n",
                    f"Clarification strategy: {c['clarification_strategy']}; proposed initial question budget: {c['initial_question_budget']}.\n",
                    "Amendment reason: " + row["amendment_reason"] + "\n",
                    "Owner wording decision: UNREVIEWED\n\nNotes / proposed wording:\n",
                ]
            )
            changes.append(
                {
                    "question_id": row["question_id"],
                    "parent_record_sha256": before["record_content_sha256"],
                    "successor_record_sha256": row["record_content_sha256"],
                    "prompt_changed": row["prompt_changed"],
                    "before_prompt": before["prompt"],
                    "after_prompt": row["prompt"],
                    "reason": row["amendment_reason"],
                    "source_jurisdiction_preserved": row["primary_jurisdiction"]
                    == before["primary_jurisdiction"],
                    "source_cutoff_preserved": row["legal_currentness_cutoff"]
                    == before["legal_currentness_cutoff"],
                    "diff": "\n".join(
                        difflib.unified_diff(
                            [before["prompt"]],
                            [row["prompt"]],
                            fromfile="GE-visible-r2",
                            tofile="GE-visible-r3",
                            lineterm="",
                        )
                    ),
                }
            )
            decisions.append(
                {
                    "question_id": row["question_id"],
                    "question_version_id": row["question_version_id"],
                    "record_sha256": row["record_content_sha256"],
                    "wording_decision": "UNREVIEWED",
                    "criteria_decision": "UNREVIEWED",
                    "notes": "",
                    "replacement_prompt": None,
                    "source_approval": False,
                    "gold_approval": False,
                    "currentness_approval": False,
                    "execution_approval": False,
                }
            )
    write_new(out / "FULL-GE-SET.md", "\n".join(review))
    json_new(
        out / "REVIEW-DECISIONS.json",
        {
            "authorizing": False,
            "allowed_wording_decisions": DECISIONS,
            "deletion_authorized": False,
            "records": decisions,
        },
    )
    (out / "REVIEW-DECISIONS.json").chmod(0o600)
    json_new(
        out / "CASE-CHANGELOG.json",
        {
            "authorizing": False,
            "deleted_cases": 0,
            "source_cases": 331,
            "successor_cases": 331,
            "records": changes,
        },
    )
    changed_count = sum(r["prompt_changed"] for r in rows)
    changelog = [
        "# Case-by-case amendment log\n",
        f"{changed_count} prompts amended; {331 - changed_count} wording retained; all 331 receive proposed review criteria and dimensions. No case deleted. Source jurisdiction, cutoff and original authorization/readiness flags are preserved, not re-certified.\n",
    ]
    for change in changes:
        changelog.extend(
            [
                f"## {change['question_id']}\n",
                "Reason: " + change["reason"] + "\n",
                "Before: " + change["before_prompt"] + "\n",
                "After: " + change["after_prompt"] + "\n",
            ]
        )
    write_new(out / "CHANGELOG.md", "\n".join(changelog))
    system_md = [
        "# Separate system-behaviour review scenarios\n",
        "32 synthetic cases, not part of the 331 doctrinal total. No execution or approved legal gold.\n",
    ]
    for item in system:
        system_md.extend(
            [
                f"## {item['system_case_id']} - {item['title']}\n",
                "\n".join(
                    turn["role"].capitalize() + ": " + turn["content"]
                    for turn in item["user_turns"]
                )
                + "\n",
                "Fixture: " + item["fixture"] + "\n",
                "Expected: " + " | ".join(item["expected_behaviour"]) + "\n",
                "Must not: " + " | ".join(item["prohibited_behaviour"]) + "\n",
            ]
        )
    write_new(out / "SYSTEM-SCENARIOS.md", "\n".join(system_md))
    json_new(
        out / "EVALUATION-CONTRACT-DRAFT.json",
        {
            "schema": "legalbot.ge-review-evaluation-contract-draft.v1",
            "authorizing": False,
            "owner_frozen": False,
            "content_version": "GE-visible-r3",
            "visible_case_count": 331,
            "system_case_count_separate": 32,
            "model_preview_fields": ["question", "task_type"],
            "not_an_executable_request_bank": True,
            "future_declared_context_only": [
                "actual_user_conversation_facts",
                "explicit_user_jurisdiction",
                "explicit_as_of_date",
            ],
            "evaluator_only": [
                "question_id",
                "ordinal",
                "topic",
                "lane",
                "expected_issues",
                "refusal_flags",
                "urgency_flags",
                "criteria",
                "family_id",
                "gold",
            ],
            "case_state_isolation_required": True,
            "seeded_order_required": True,
            "approved_order_seed": None,
            "family_split_required": True,
            "private_overlap_verified": False,
            "required_outcomes": [
                "supported_answer",
                "safe_clarification",
                "supported_limited_answer",
                "appropriate_refusal",
                "over_refusal",
                "unsupported_claim",
                "system_error",
                "incomplete",
            ],
            "scoring_thresholds": None,
            "run_validity_approved": False,
            "source_gold_currentness_approved": False,
            "training_export_authorized": False,
            "unseen_execution_authorized": False,
        },
    )
    training = """# Training preparation - separate from evaluation

This pack prepares the requested future evaluation -> training/improvement ->
unseen workflow. It contains **zero approved training examples or supervised gold
answers**. The full 331-case visible bank is a development evaluation bank; the
32 system scenarios are a separate review suite. Neither is silently relabelled
as training data. The 306 private unseen cases are never training input.

Before weight-changing training, create a distinct rights-cleared, privacy-reviewed
dataset with independently supported targets, provenance and a training-internal
validation partition. Group scenario families before splitting. An independent
custodian must check protected-set overlap without disclosing unseen text or
case-specific findings to development. A changed name, date or paraphrase does not
make a visible case unseen. No training export is created by this review pack.

Freeze the baseline candidate and evaluation contract first. Use visible findings
to diagnose source, retrieval, prompt, code or model defects, then select the
approved remedy. Weight changes require an exact base model, dataset/adapter pins,
resource budget, recipe, stop criteria and execution approval. Preserve all
predecessors. Re-evaluate development performance, freeze the successor, and only
then conduct the independently authorized unseen run once. No run is started here.

Training authoring fields to prepare: example ID; scenario family; rights and
privacy decision; source/evidence version; reviewed context and target; task mode;
clarification/refusal behaviour where applicable; split role; reviewer decision;
base-model compatibility. Empty or unreviewed fields cannot be treated as approval.

Source feasibility, wording review and gold review should inform one another.
Never turn a model-generated plausible answer into independently reviewed legal
gold. If only prompt/retrieval repair is performed, do not report weights trained.
"""
    write_new(out / "TRAINING-PREPARATION.md", training)
    json_new(
        out / "TRAINING-AUTHORING-TEMPLATE.json",
        {
            "authorizing": False,
            "approved_example_count": 0,
            "records": [],
            "required_fields": [
                "example_id",
                "scenario_family_id",
                "rights_privacy_decision",
                "source_evidence_version",
                "reviewed_input_context",
                "reviewed_target",
                "task_type",
                "behaviour_targets",
                "split_role",
                "reviewer_decision",
                "base_model_compatibility",
            ],
            "existing_evaluation_cases_may_be_relabelled_as_training": False,
            "unseen_content_may_be_used": False,
        },
    )
    private_link = os.path.relpath(details["private_zip"], out)
    custody_md = [
        "# Full private GE unseen custody\n",
        "306 draft questions across 17 topics (18 each). Content version remains GE-private-r2. The full existing archive is preserved byte-for-byte; no unseen prompt was decoded or amended by this operation.\n",
        f"[Open the complete existing private archive]({private_link})\n",
        f"ZIP SHA-256: `{PRIVATE_ZIP_PIN}`\n",
        "The visible-r3 amendments do not certify this private-r2 bank's wording, semantic independence or legal quality. Independent custody review must apply the same naturalness, jurisdiction/date, family-overlap, clarification and safety criteria before freezing it. If a private change is needed, preserve the original and create a separately controlled successor; do not send prompts or case-specific findings back into this development conversation.\n",
        "No owner freeze, unseen run or disclosure gate has been executed. Keep this archive separate from the visible ZIP and all training material. Do not paste its contents into the model used for improvement. Prior exposure makes affected cases ineligible for an honest unseen claim.\n",
        "| Topic | Draft count |\n| --- | ---: |",
    ]
    for topic in details["custody"]["topics"]:
        custody_md.append(f"| {topic['topic_id']} | {topic['question_count']} |")
    write_new(out / "UNSEEN-CUSTODY.md", "\n".join(custody_md) + "\n")
    pdf_info = build_pdf(pdf, rows, system, topics, run_id)
    write_new(out / pdf.name, pdf.read_bytes())
    readme = f"""# General Enquiries - amended full review pack

Content: **GE-visible-r3**. PDF layout: **1.0**. All 331 original case IDs
remain; {changed_count} prompts amended and {331 - changed_count} retained. Every case has
proposed clarification criteria, independent scenario dimensions and a family ID.
Original bytes are unchanged. Source scopes/dates and readiness flags are retained,
not re-certified. There are no approved legal gold answers or training examples.

- [Full fillable PDF]({pdf.name}): all 331 legal prompts and a separate 32-case system appendix.
- [Editable full set](FULL-GE-SET.md) and [complete structured review records](GE-VISIBLE-REVIEW.jsonl).
- [Every before/after amendment](CHANGELOG.md), [structured change log](CASE-CHANGELOG.json), and [owner decision file](REVIEW-DECISIONS.json).
- [Prompt-only boundary preview](PROMPT-PROJECTION-PREVIEW.jsonl); [mapping stays evaluator-only](PROMPT-MAP-EVALUATOR-ONLY.json). Not an executable bank.
- [Separate system scenarios](SYSTEM-SCENARIOS.md) and [evaluation contract draft](EVALUATION-CONTRACT-DRAFT.json).
- [Training preparation](TRAINING-PREPARATION.md): independent training data and approved targets remain to be created; no evaluation/unseen relabelling.
- [Full separate unseen custody](UNSEEN-CUSTODY.md): all 306 private-r2 drafts remain unchanged, with an archive link and independent review requirements.

Save annotations under a new filename. KEEP/AMEND/MOVE/EXCLUDE_FROM_SCORING
are proposed wording decisions; exclusion never deletes records. No decision is
silently accepted. Source, gold, currentness, split and execution approvals remain
separate. Do not put private personal matter information into annotations.

No deletion, source scan/build, answer-model invocation, training export/run,
scored evaluation, private prompt reading, promotion or live activation occurred.
After reviewing these materials, return to step-1 design review; later execution
is still deferred. The strict no-deletion rule applies to every agent and cleanup
path, including temporary files. Visual PDF QA is recorded separately.
"""
    write_new(out / "README.md", readme)
    artifacts = [{"path": p.name, "sha256": sha(p)} for p in sorted(out.iterdir()) if p.is_file()]
    manifest = {
        "schema": "legalbot.ge-amended-review-pack.v1",
        "authorizing": False,
        "created_at_utc": datetime.now(UTC).isoformat(),
        "run_id": run_id,
        "content_version": "GE-visible-r3",
        "layout_version": "1.0",
        "visible_core": 306,
        "visible_stress": 25,
        "visible_total": 331,
        "prompts_amended": changed_count,
        "prompts_retained": 331 - changed_count,
        "original_case_ids_preserved": True,
        "deleted_cases": 0,
        "source_jurisdictions_and_cutoffs_preserved": True,
        "system_cases_separate": 32,
        "scenario_families": len({r["scenario_family_id"] for r in rows}),
        "approved_training_examples": 0,
        "approved_gold_answers": 0,
        "source_records_sha256": VISIBLE_RECORDS_PIN,
        "source_packages": details["source_receipts"],
        "amendment_sources": [
            {"path": str(p.relative_to(ROOT)), "sha256": sha(p)}
            for p in sorted(PROPOSALS.glob("*.json"))
        ],
        "private_unseen": {
            "count": 306,
            "content_version": "GE-private-r2",
            "archive_path": str(details["private_zip"].relative_to(ROOT)),
            "archive_sha256": PRIVATE_ZIP_PIN,
            "mode": "0600",
            "prompts_decoded": False,
            "content_amended": False,
            "owner_frozen": False,
            "semantic_independence_verified": False,
        },
        "pdf": pdf_info,
        "artifacts": artifacts,
        "visual_qa_required": True,
        "owner_decisions_accepted": 0,
        "source_scan_run": False,
        "index_build_run": False,
        "answer_model_run": False,
        "training_export_created": False,
        "training_run": False,
        "evaluation_run": False,
        "unseen_run": False,
        "promotion_run": False,
        "live_run": False,
        "deletion_performed": False,
    }
    manifest["content_sha256"] = hashlib.sha256(canonical(manifest)).hexdigest()
    json_new(out / "PACK-MANIFEST.json", manifest)
    write_new(
        out / "SHA256SUMS.txt",
        "".join(f"{sha(p)}  {p.name}\n" for p in sorted(out.iterdir()) if p.is_file()),
    )
    with zipfile.ZipFile(bundle, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(out.iterdir()):
            archive.write(path, arcname=run_id + "/" + path.name)
        archive.writestr(
            run_id + "/OPEN-FIRST.txt",
            "Open README.md or the PDF in this folder. Private unseen prompts are NOT included. The 306-question private archive is a separate owner-custody delivery; its workspace link is listed in UNSEEN-CUSTODY.md. Save annotations to a new copy; do not delete originals.\n",
        )
    bundle.chmod(0o600)
    return {
        "run_id": run_id,
        "visible": 331,
        "changed": changed_count,
        "system_cases": 32,
        "pdf_pages": pdf_info["pages"],
        "fillable_fields": pdf_info["fillable_fields"],
        "private_content_decoded": False,
        "bundle": str(bundle.relative_to(ROOT)),
        "bundle_sha256": sha(bundle),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.run_id), sort_keys=True))
