"""Create a complete visible GE draft review projection; never run evaluation.

Private unseen JSONL is streamed through SHA-256 only, never decoded. Existing
question packages are read-only. Outputs are create-only, non-authorizing review
materials, not answers, gold, training records or a new execution bank.
Run with the bundled document Python runtime (ReportLab and pypdf required).
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import stat
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "data/evaluations/phase2b-question-drafts"
VISIBLE_NAME = "LegalBot-Phase2B-2026-08-28-common-public-visible-development-r2"
PRIVATE_NAME = "LegalBot-Phase2B-2026-08-28-common-public-private-unseen-r2"
VISIBLE_PIN = "d03fe95ee1ad72444580d7ca492f7fc947db4604d23214da8a086e3dbbecb359"
PRIVATE_PIN = "a73ef297738cf0745d1233e8d2c4748412d534bff41afadd1086e6e349f68a91"
PRIVATE_ZIP_PIN = "a5c782b011995932419788b0bcc66ebe10467fabd8d4244a0003a6f4efd6c267"


def canonical(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def member(directory: Path, relative: str) -> Path:
    rel = Path(relative)
    if rel.is_absolute() or ".." in rel.parts or directory.is_symlink():
        raise ValueError("unsafe review source member")
    path = directory
    for part in rel.parts:
        path /= part
        if path.is_symlink():
            raise ValueError("symbolic review source member")
    if not path.is_file():
        raise ValueError("missing review source member")
    return path


def verify_package(directory: Path, pin: str) -> dict[str, Any]:
    manifest = json.loads(member(directory, "PACKAGE-MANIFEST.json").read_text())
    claimed = manifest.pop("package_content_sha256")
    if claimed != pin or hashlib.sha256(canonical(manifest)).hexdigest() != pin:
        raise ValueError("question package pin mismatch")
    checked = private_modes = 0
    for line in member(directory, "SHA256SUMS.txt").read_text().splitlines():
        digest, relative = line.split("  ", 1)
        path = member(directory, relative)
        if sha(path) != digest:
            raise ValueError("question package member mismatch")
        if path.suffix == ".jsonl" and directory.name == PRIVATE_NAME:
            if stat.S_IMODE(path.stat().st_mode) != 0o600:
                raise ValueError("private unseen file permissions changed")
            private_modes += 1
        checked += 1
    return {
        "run_name": directory.name,
        "package_content_sha256": pin,
        "verified_member_count": checked,
        "private_jsonl_mode_checks": private_modes,
    }


def write_new(path: Path, content: str | bytes, *, private: bool = False) -> None:
    raw = content.encode() if isinstance(content, str) else content
    with path.open("xb") as handle:
        handle.write(raw)
    if private:
        path.chmod(0o600)


def flags(row: dict[str, Any]) -> str:
    labels = ["STRESS" if "STRESS" in row["lane"] else "CORE"]
    for key, label in [
        ("blocking_clarification_required", "material clarification"),
        ("urgent_handoff_required", "urgent handoff"),
        ("evidence_preservation_required", "preserve evidence"),
        ("safety_refusal_required", "safety/refusal"),
    ]:
        if row[key]:
            labels.append(label)
    return " | ".join(labels)


def build_pdf(
    path: Path, topics: list[dict[str, Any]], rows_by_topic: dict[str, list[dict[str, Any]]]
) -> int:
    import reportlab
    from pypdf import PdfReader
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import (
        BaseDocTemplate,
        Frame,
        HRFlowable,
        KeepTogether,
        PageBreak,
        PageTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
    )

    fonts = Path(reportlab.__file__).parent / "fonts"
    pdfmetrics.registerFont(TTFont("Review", str(fonts / "Vera.ttf")))
    pdfmetrics.registerFont(TTFont("ReviewBold", str(fonts / "VeraBd.ttf")))
    pdfmetrics.registerFontFamily("Review", normal="Review", bold="ReviewBold")
    navy, teal, grey = (
        colors.HexColor("#18364B"),
        colors.HexColor("#176C72"),
        colors.HexColor("#586875"),
    )
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="Cover",
            fontName="ReviewBold",
            fontSize=29,
            leading=34,
            textColor=navy,
            spaceAfter=18,
        )
    )
    styles.add(
        ParagraphStyle(
            name="Intro", fontName="Review", fontSize=11, leading=17, textColor=navy, spaceAfter=13
        )
    )
    styles.add(
        ParagraphStyle(
            name="Topic",
            fontName="ReviewBold",
            fontSize=19,
            leading=24,
            textColor=navy,
            spaceAfter=12,
            keepWithNext=True,
        )
    )
    styles.add(
        ParagraphStyle(
            name="Sub",
            fontName="ReviewBold",
            fontSize=10,
            leading=14,
            textColor=teal,
            spaceBefore=10,
            spaceAfter=9,
            keepWithNext=True,
        )
    )
    styles.add(
        ParagraphStyle(
            name="ID", fontName="ReviewBold", fontSize=8, leading=11, textColor=teal, spaceAfter=4
        )
    )
    styles.add(
        ParagraphStyle(
            name="Prompt",
            fontName="Review",
            fontSize=10.1,
            leading=14.3,
            textColor=navy,
            spaceAfter=5,
        )
    )
    styles.add(
        ParagraphStyle(
            name="Small",
            fontName="Review",
            fontSize=7.6,
            leading=10.7,
            textColor=grey,
            spaceAfter=5,
        )
    )
    styles.add(
        ParagraphStyle(name="Cell", fontName="Review", fontSize=8.2, leading=11.5, textColor=navy)
    )
    styles.add(
        ParagraphStyle(
            name="CellHead",
            fontName="ReviewBold",
            fontSize=8.2,
            leading=11.5,
            textColor=colors.white,
        )
    )

    class ReviewDoc(BaseDocTemplate):
        def afterFlowable(self, flowable: Any) -> None:
            key = getattr(flowable, "bookmark_key", None)
            if key:
                self.canv.bookmarkPage(key)
                self.canv.addOutlineEntry(flowable.getPlainText(), key, 0, False)

    def footer(canvas: Any, doc: Any) -> None:
        canvas.saveState()
        width, height = A4
        canvas.setStrokeColor(colors.HexColor("#D7E0E5"))
        canvas.line(44, 34, width - 44, 34)
        canvas.setFillColor(grey)
        canvas.setFont("Review", 7.1)
        canvas.drawString(
            44, 22, "LegalBot | Visible question drafts | No unseen prompts or answers"
        )
        canvas.drawRightString(width - 44, 22, f"Page {doc.page}")
        if doc.page > 1:
            canvas.setFont("ReviewBold", 7.5)
            canvas.setFillColor(teal)
            canvas.drawString(
                44, height - 27, "GENERAL ENQUIRIES / FULL OWNER REVIEW / 31 AUGUST 2026"
            )
        canvas.restoreState()

    doc = ReviewDoc(
        str(path),
        pagesize=A4,
        leftMargin=44,
        rightMargin=44,
        topMargin=48,
        bottomMargin=46,
        title="LegalBot - Full General Enquiry Review",
        author="LegalBot",
    )
    doc.addPageTemplates(
        PageTemplate(
            id="review",
            frames=[
                Frame(
                    44,
                    46,
                    A4[0] - 88,
                    A4[1] - 94,
                    leftPadding=0,
                    rightPadding=0,
                    topPadding=0,
                    bottomPadding=0,
                )
            ],
            onPage=footer,
        )
    )

    def p(text: str, style: str = "Intro") -> Paragraph:
        return Paragraph(html.escape(text), styles[style])

    story: list[Any] = [
        Spacer(1, 48),
        p("GENERAL\nENQUIRIES".replace("\n", " "), "Cover"),
        p("Full visible question bank for owner review", "Intro"),
        p("331 questions  /  17 topics  /  306 core + 25 stress", "Intro"),
        HRFlowable(width="100%", thickness=2, color=teal),
        Spacer(1, 22),
        p(
            "The complete current r2 set is reproduced here. Every prompt and question ID is preserved; no sampling, shortening or new questions were introduced."
        ),
        p(
            "Review wording, everyday usefulness, coverage, necessary clarification and safety. Mark KEEP, AMEND, MOVE or REMOVE and identify the question ID in your notes."
        ),
        p(
            "These are question drafts. This book contains no gold answers, model answers, training records or private unseen prompts. Wording review does not approve a legal proposition or authorize execution."
        ),
        p(
            "The separate private GE bank has 306 drafts, 18 per topic. Its complete ZIP remains in private custody. Keep unseen wording and findings out of training/development so it can support later testing."
        ),
        p(
            "Administrative Law and Wills/Estates remain pending source admission. All other topics also require evidence/gold review and the applicable execution gates. The source bank's 28 August 2026 currentness field is not a fresh legal-currentness certification."
        ),
        p(
            "Delivery order: 1 System design; 2 Evaluation -> training/improvement -> unseen, GE first; 3 Live, last."
        ),
        PageBreak(),
        p("Topic index", "Topic"),
    ]
    data = [
        [
            p("Topic", "CellHead"),
            p("Core", "CellHead"),
            p("Stress", "CellHead"),
            p("Readiness", "CellHead"),
        ]
    ]
    for topic in topics:
        state = (
            "Source admission pending"
            if topic["topic_id"] in {"administrative-law", "wills-and-estates"}
            else "Preparation only"
        )
        data.append(
            [
                p(topic["display_name"], "Cell"),
                p(str(topic["core_question_count"]), "Cell"),
                p(str(topic["stress_question_count"]), "Cell"),
                p(state, "Cell"),
            ]
        )
    table = Table(data, colWidths=[232, 42, 54, A4[0] - 88 - 328], repeatRows=1, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), navy),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F0F5F7"), colors.white]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.extend(
        [
            table,
            Spacer(1, 18),
            p(
                "Flags describe existing draft controls, not completed legal checks. A material-clarification flag should be reviewed for necessity; it is not a reason to refuse all safe general guidance.",
                "Small",
            ),
            p(
                "Current flags: 51 urgent-handoff cases, 51 evidence-preservation cases, 114 material-clarification cases and 4 safety/refusal cases. These counts do not prove comprehensive risk coverage.",
                "Small",
            ),
        ]
    )
    number = 0
    for index, topic in enumerate(topics, 1):
        story.append(PageBreak())
        heading = p(f"{index:02d}. {topic['display_name']}", "Topic")
        heading.bookmark_key = topic["topic_id"]
        story.append(heading)
        story.append(
            p(
                f"{topic['core_question_count']} core + {topic['stress_question_count']} stress. All questions remain drafts for review.",
                "Small",
            )
        )
        if topic["topic_id"] in {"administrative-law", "wills-and-estates"}:
            story.append(
                p(
                    "SOURCE ADMISSION PENDING: included for complete wording review, not scored-evaluation eligibility.",
                    "Small",
                )
            )
        lane = None
        for row in rows_by_topic[topic["topic_id"]]:
            kind = "Stress questions" if "STRESS" in row["lane"] else "Core questions"
            if kind != lane:
                story.append(p(kind, "Sub"))
                lane = kind
            number += 1
            story.append(
                KeepTogether(
                    [
                        p(f"{number:03d}  {row['question_id']}", "ID"),
                        p(row["prompt"], "Prompt"),
                        p(flags(row), "Small"),
                        p(
                            "Decision: KEEP / AMEND / MOVE / REMOVE     Notes: __________________________",
                            "Small",
                        ),
                        HRFlowable(width="100%", thickness=0.35, color=colors.HexColor("#D7E0E5")),
                        Spacer(1, 9),
                    ]
                )
            )
    if number != 331:
        raise ValueError("full visible PDF count changed")
    doc.build(story)
    reader = PdfReader(path)
    extracted = " ".join((page.extract_text() or "") for page in reader.pages)
    normalized = " ".join(extracted.split())
    for rows in rows_by_topic.values():
        for row in rows:
            if (
                row["question_id"] not in normalized
                or " ".join(row["prompt"].split()) not in normalized
            ):
                raise ValueError("PDF question completeness failed")
    return len(reader.pages)


def prepare(run_id: str) -> dict[str, Any]:
    if not re.fullmatch(r"LegalBot-GE-\d{4}-\d{2}-\d{2}-review-r[1-9]\d*", run_id):
        raise ValueError("invalid GE review run ID")
    visible, private = BASE / VISIBLE_NAME, BASE / PRIVATE_NAME
    receipts = [verify_package(visible, VISIBLE_PIN), verify_package(private, PRIVATE_PIN)]
    private_zip = member(BASE, PRIVATE_NAME + ".zip")
    if sha(private_zip) != PRIVATE_ZIP_PIN or stat.S_IMODE(private_zip.stat().st_mode) != 0o600:
        raise ValueError("private ZIP identity/permissions changed")
    registry = json.loads(member(visible, "VISIBLE-QUESTION-BANK-REGISTRY.json").read_text())
    custody = json.loads(member(private, "PRIVATE-CUSTODY-REGISTRY.json").read_text())
    if (
        custody["question_count"] != 306
        or custody["topic_count"] != 17
        or custody["prompt_disclosure_authorized"]
    ):
        raise ValueError("unexpected private custody contract")
    topics = registry["topics"]
    rows: list[dict[str, Any]] = []
    raw_lines: list[bytes] = []
    by_topic: dict[str, list[dict[str, Any]]] = {}
    ids: set[str] = set()
    for topic in topics:
        topic_rows = []
        for filename, expected in [
            ("VISIBLE-CORE-QUESTION-SET.jsonl", topic["core_question_count"]),
            ("VISIBLE-STRESS-QUESTION-SET.jsonl", topic["stress_question_count"]),
        ]:
            raw = member(visible, f"topics/{topic['topic_id']}/{filename}").read_bytes()
            lines = raw.splitlines(keepends=True)
            if len(lines) != expected:
                raise ValueError("visible topic count mismatch")
            for line in lines:
                row = json.loads(line)
                digest = row["record_content_sha256"]
                if (
                    hashlib.sha256(
                        canonical({k: v for k, v in row.items() if k != "record_content_sha256"})
                    ).hexdigest()
                    != digest
                ):
                    raise ValueError("visible record digest mismatch")
                if (
                    row["question_id"] in ids
                    or row["question_type"] != "GENERAL_ENQUIRY"
                    or row["scored_evaluation_eligible"]
                ):
                    raise ValueError("unexpected visible record contract")
                ids.add(row["question_id"])
                rows.append(row)
                topic_rows.append(row)
                raw_lines.append(line)
        by_topic[topic["topic_id"]] = topic_rows
    counts = Counter("stress" if "STRESS" in row["lane"] else "core" for row in rows)
    if dict(counts) != {"core": 306, "stress": 25} or len(ids) != 331:
        raise ValueError("full GE bank count mismatch")
    out = ROOT / "data/evaluations/general-enquiries" / run_id
    pdf = ROOT / "output/pdf" / f"{run_id}.pdf"
    if out.exists() or pdf.exists():
        raise FileExistsError("review outputs already exist; use a new immutable revision")
    out.mkdir(parents=True)
    pdf.parent.mkdir(parents=True, exist_ok=True)
    write_new(out / "VISIBLE-GE-SET.jsonl", b"".join(raw_lines))
    review = [
        "# Full General Enquiry set - owner review\n",
        "331 visible questions: 306 core + 25 stress, across all 17 topics. Original prompts and IDs are unchanged. No private unseen prompts, answers or gold are included.\n",
        "Use KEEP, AMEND, MOVE or REMOVE with the exact question ID. Do not include personal matter details in review notes. Changes remain proposals until versioned and verified.\n",
    ]
    decisions = []
    for topic in topics:
        review.append(f"## {topic['display_name']}\n")
        review.append(f"Draft readiness: `{topic['topic_execution_status']}`.\n")
        for row in by_topic[topic["topic_id"]]:
            review.extend(
                [
                    f"### {row['question_id']}\n",
                    row["prompt"] + "\n",
                    flags(row) + "\n",
                    "Owner decision: UNREVIEWED\n\nProposed amendment / notes: \n",
                ]
            )
            decisions.append(
                {
                    "question_id": row["question_id"],
                    "source_record_sha256": row["record_content_sha256"],
                    "decision": "UNREVIEWED",
                    "replacement_prompt": None,
                    "move_to_topic": None,
                    "notes": "",
                }
            )
    write_new(out / "FULL-GE-SET.md", "\n".join(review))
    write_new(
        out / "REVIEW-DECISIONS.json",
        json.dumps(
            {
                "authorizing": False,
                "allowed_decisions": ["UNREVIEWED", "KEEP", "AMEND", "MOVE", "REMOVE"],
                "source_package_content_sha256": VISIBLE_PIN,
                "decisions": decisions,
            },
            indent=2,
        )
        + "\n",
        private=True,
    )
    private_link = os.path.relpath(private_zip, out)
    custody_text = [
        "# Full GE unseen custody - owner review\n",
        "The complete private bank contains 306 drafts: 18 questions in each of 17 topics. This page contains counts and file identities only, not the prompts. The bank is not owner-frozen and no unseen scoring/disclosure gate is executed here.\n",
        f"[Existing complete private ZIP]({private_link})\n",
        f"Package digest: `{PRIVATE_PIN}`\n\nZIP SHA-256: `{PRIVATE_ZIP_PIN}`\n",
        "Keep independent owner custody review separate from model development. Do not paste unseen wording or case-specific findings into training/development. If that happens, affected items must be treated as exposed and replaced in a new version before claiming a later test is unseen.\n",
        "| Topic | Questions | Readiness |\n| --- | ---: | --- |",
    ]
    for topic in custody["topics"]:
        custody_text.append(
            f"| {topic['topic_id']} | {topic['question_count']} | {topic['topic_execution_status']} |"
        )
    custody_text.append(
        "\nPrivate files were checked by streaming hash and file mode only. Their prompt content was not decoded or projected by this builder. Existing overlap audits are preserved evidence, not proof of semantic independence or a fresh legal review.\n"
    )
    write_new(out / "UNSEEN-CUSTODY-REVIEW.md", "\n".join(custody_text))
    pages = build_pdf(pdf, topics, by_topic)
    pdf_link = os.path.relpath(pdf, out)
    readme = f"""# General Enquiries - full current-set review

This is phase-1 preparation under the three-phase plan. GE is first.

- [Full review PDF]({pdf_link}): all 331 visible prompts, with review lines and topic bookmarks.
- [Editable full set](FULL-GE-SET.md): the same complete wording and case IDs.
- [Full visible structured records](VISIBLE-GE-SET.jsonl): exact original JSONL records.
- [Owner decisions](REVIEW-DECISIONS.json): 331 UNREVIEWED entries; no assumed acceptance.
- [Separate full unseen custody](UNSEEN-CUSTODY-REVIEW.md): 306 drafts, metadata and a link to the existing private ZIP; no unseen prompts in this visible pack.

Review GE usefulness, wording, topic coverage, necessary facts, safety and scope.
Keep/amend/move/remove decisions are proposals, not legal-currentness adoption,
gold answers, training consent, a scored run or release authority. Administrative
Law and Wills/Estates remain source-admission pending; every topic still needs the
applicable evidence and execution checks. The 17-topic inventory is not proof of
complete housing, employment, family, immigration, benefits/debt or consumer coverage.

No prompts were rewritten, sampled or added. No private unseen JSONL was parsed.
No source/index/model execution, training, validation disclosure, signature,
promotion or live action was performed. PDF text extraction verified every visible
question and full prompt. Visual QA is recorded separately before delivery.

Do not store private personal matter information in review annotations. The
original question packages remain unchanged; later accepted amendments require
a new version with an explicit diff and leakage/eligibility checks.
"""
    write_new(out / "README.md", readme)
    artifacts = [{"path": p.name, "sha256": sha(p)} for p in sorted(out.iterdir()) if p.is_file()]
    manifest = {
        "schema": "legalbot.v111.ge-question-review-projection.v1",
        "authorizing": False,
        "created_at_utc": datetime.now(UTC).isoformat(),
        "run_id": run_id,
        "purpose": "phase-1-owner-question-draft-review-only",
        "delivery_phases": 3,
        "first_evaluation_lane": "GENERAL_ENQUIRY",
        "visible_core_count": 306,
        "visible_stress_count": 25,
        "visible_total_count": 331,
        "topic_count": 17,
        "private_unseen_count_from_verified_registry": 306,
        "private_prompt_content_parsed": False,
        "private_prompt_projection_created": False,
        "source_packages": receipts,
        "private_zip_sha256": PRIVATE_ZIP_PIN,
        "exact_visible_record_bytes_preserved": True,
        "pdf": {
            "path": str(pdf.relative_to(ROOT)),
            "sha256": sha(pdf),
            "page_count": pages,
            "all_331_prompt_texts_verified": True,
        },
        "artifacts": artifacts,
        "visual_qa_required_before_delivery": True,
        "source_scan_run": False,
        "index_build_run": False,
        "answer_model_run": False,
        "training_run": False,
        "unseen_run": False,
        "owner_freeze_created": False,
        "promotion_run": False,
        "live_run": False,
    }
    manifest["content_sha256"] = hashlib.sha256(canonical(manifest)).hexdigest()
    write_new(out / "PACK-MANIFEST.json", json.dumps(manifest, indent=2) + "\n")
    write_new(
        out / "SHA256SUMS.txt",
        "".join(f"{sha(p)}  {p.name}\n" for p in sorted(out.iterdir()) if p.is_file()),
    )
    return {
        "run_id": run_id,
        "visible": 331,
        "private_custody": 306,
        "pdf_pages": pages,
        "pdf": str(pdf.relative_to(ROOT)),
        "private_content_parsed": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.run_id), sort_keys=True))
