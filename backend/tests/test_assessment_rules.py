from app.assessment.rules import (
    FeedbackBodyExtractor,
    FeedbackRuleExtractor,
    GradeBand,
    RulePolarity,
    assessment_standard_privacy_issues,
    explicit_grade_band,
    general_seventy_rules,
    generalise_assessment_standard_text,
    is_owner_style_reusable_standard,
)
from app.ingestion.models import Annotation, BlockKind, StructuralBlock


def test_only_explicit_grade_bands_are_used() -> None:
    assert explicit_grade_band("Mark: 74") == GradeBand.SEVENTY_PLUS
    assert explicit_grade_band("62%") == GradeBand.SIXTY
    assert explicit_grade_band("Score 55") == GradeBand.FIFTY
    assert explicit_grade_band("Good work") == GradeBand.UNKNOWN


def test_marker_comments_become_positive_and_avoid_rules() -> None:
    extractor = FeedbackRuleExtractor()
    positive = extractor.extract(
        (Annotation("c1", "Mark 74: the qualified thesis and counterargument are persuasive."),),
        subject="contract",
    )[0]
    avoid = extractor.extract(
        (
            Annotation(
                "c2", "Mark 58: application to the facts is too general and needs precision."
            ),
        ),
        subject="contract",
    )[0]
    assert positive.polarity == RulePolarity.POSITIVE
    assert avoid.polarity == RulePolarity.AVOID
    assert avoid.remediation_text


def test_unknown_grade_comment_is_not_silently_generalised() -> None:
    rules = FeedbackRuleExtractor().extract(
        (Annotation("c1", "The analysis should engage with authority in more detail."),),
        subject="land",
    )
    assert rules == ()


def test_grade_band_does_not_invert_comment_polarity() -> None:
    extractor = FeedbackRuleExtractor()
    critical_comment_on_first = extractor.extract(
        (Annotation("c1", "Mark 74: the conclusion is unclear and needs more analysis."),),
        subject="land",
    )
    praise_on_lower_mark = extractor.extract(
        (Annotation("c2", "Mark 58: the introduction is clear and persuasive."),),
        subject="land",
    )
    assert critical_comment_on_first == ()
    assert praise_on_lower_mark == ()


def test_mixed_document_grades_are_not_used_as_a_global_fallback() -> None:
    rules = FeedbackRuleExtractor().extract(
        (Annotation("c1", "The thesis is clear and persuasive."),),
        subject="land",
        document_grade_text="Question 1: 72. Question 2: 62.",
    )
    assert rules == ()


def test_feedback_body_excludes_student_answer_prefix() -> None:
    blocks = (
        StructuralBlock(
            0,
            BlockKind.PARAGRAPH,
            "STUDENT PROSE MUST NEVER BECOME ASSESSMENT GUIDANCE.",
        ),
        StructuralBlock(
            1,
            BlockKind.PARAGRAPH,
            "FINAL GRADE 72/100 GRADEMARK REPORT GENERAL COMMENTS. "
            "The thesis is clear and persuasive. The remedy discussion is missing and needs more detail.",
        ),
    )
    comments = FeedbackBodyExtractor().extract(blocks)
    text = " ".join(comment.text for comment in comments)
    assert "STUDENT PROSE" not in text
    assert "clear and persuasive" in text
    assert "missing and needs more detail" in text

    rules = FeedbackRuleExtractor().extract(
        comments,
        subject="trusts",
        document_grade_text="FINAL GRADE 72/100",
    )
    assert len(rules) == 1
    assert rules[0].polarity == RulePolarity.POSITIVE


def test_rule_ids_are_reproducible_and_subjects_inherit_general_standard() -> None:
    comment = Annotation("c1", "Mark 72: the qualified thesis is persuasive and precise.")
    first = FeedbackRuleExtractor().extract((comment,), subject="land")
    second = FeedbackRuleExtractor().extract((comment,), subject="land")
    assert first[0].id == second[0].id
    assert any("qualified thesis" in rule for rule in general_seventy_rules("essay"))


def test_cross_subject_general_standards_load_for_any_subject(database) -> None:
    """Owner standards stored as subject=general apply beyond that literal subject."""

    from app.db import utc_iso

    now = utc_iso()
    database.execute(
        """
        INSERT INTO rubric_rules(
          id, task_type, subject, criterion, polarity, grade_band, rule_text,
          remediation_text, review_status, created_at
        ) VALUES
          ('std-70', NULL, 'general', 'application', 'positive_pattern', '70+',
           'Apply each governing rule accurately to the material facts.', NULL,
           'approved', ?),
          ('std-60', NULL, 'general', 'analysis', 'error_to_avoid', '60-69',
           'Do not assert a conclusion without explaining the connecting reason.',
           'Add the inferential link before the conclusion.', 'approved', ?),
          ('std-essay', 'essay', 'general', 'scholarship', 'positive_pattern', '70+',
           'Integrate relevant academic views into the analysis.', NULL,
           'approved', ?)
        """,
        (now, now, now),
    )
    for task, subject in (("general", None), ("general", "tort"), ("problem", "contract")):
        ids = {
            row["id"] for row in database.approved_assessment_rules(task_type=task, subject=subject)
        }
        assert "std-70" in ids
        assert "std-60" in ids
        assert "std-essay" not in ids
    essay_ids = {
        row["id"] for row in database.approved_assessment_rules(task_type="essay", subject="land")
    }
    assert {"std-70", "std-60", "std-essay"} <= essay_ids


def test_runner_uses_only_immutable_owner_guidance_pending_feedback_reaudit(database) -> None:
    from cryptography.fernet import Fernet

    from app.config import Settings
    from app.crypto import LocalCipher
    from app.db import utc_iso
    from app.orchestration.runner import AnswerRunner
    from app.types import TaskType

    now = utc_iso()
    database.execute(
        """
        INSERT INTO rubric_rules(
          id, task_type, subject, criterion, polarity, grade_band, rule_text,
          remediation_text, review_status, created_at
        ) VALUES
          ('mix-70', NULL, 'general', 'thesis', 'positive_pattern', '70+',
           'Sustain a clear thesis throughout the answer.', NULL, 'approved', ?),
          ('mix-50', NULL, 'general', 'issue_spotting', 'error_to_avoid', '50-59',
           'Do not omit a material defence raised by the facts.',
           'Checklist every material issue.', 'approved', ?)
        """,
        (now, now),
    )
    runner = AnswerRunner(
        settings=Settings(project_root=database.path.parent, test_mode=True),
        database=database,
        cipher=LocalCipher(Fernet.generate_key()),
        retriever=object(),  # unused
        model=object(),  # unused
    )
    rules = runner._assessment_rules(TaskType.GENERAL, "tort")
    joined = "\n".join(rules)
    assert "70+ target" in joined
    assert "anti-pattern" in joined
    assert "Target:" in joined
    assert "Repair:" in joined
    assert "Sustain a clear thesis" not in joined
    assert "Do not omit a material defence" not in joined
    assert runner._assessment_guidance(TaskType.GENERAL, "tort").bundle_sha256


def test_owner_style_standard_rejects_pii_and_student_directed_prose() -> None:
    issues = assessment_standard_privacy_issues(
        "Email marker@example.com about /Users/owner/Desktop/Law/file.pdf"
    )
    assert "pii_or_local_path" in issues
    assert "student_directed" in assessment_standard_privacy_issues(
        "You wrote a descriptive answer that needs more authority."
    )
    assert "administrative_feedback" in assessment_standard_privacy_issues(
        "If you need clarification please email me; Grademark report attached."
    )
    assert (
        generalise_assessment_standard_text(
            "Mark 58: in essay Q3 you wrote a vague negligence paragraph."
        )
        is None
    )
    good = (
        "Apply each governing rule accurately and explicitly to the material facts; "
        "distinguish facts that support different outcomes rather than stating a conclusory result."
    )
    assert is_owner_style_reusable_standard(good)
    assert generalise_assessment_standard_text(good) == good


def test_owner_style_standard_rejects_toc_false_positives() -> None:
    assert not is_owner_style_reusable_standard(
        "(3) Analysis of the Effects of a Concentration in the common market"
    )
    assert not is_owner_style_reusable_standard(
        "http://ec.europa.eu/competition/antitrust/legislation/overview.pdf needs analysis"
    )


def test_canonical_standards_load_despite_superseded_provenance(database) -> None:
    """Owner standards must draft even when assessment provenance was superseded."""

    from app.db import utc_iso

    now = utc_iso()
    database.execute(
        """
        INSERT INTO documents(
          id, content_sha256, source_identity_id, safe_display_name, media_type,
          status, lane, subject_primary, jurisdiction, created_at, updated_at
        ) VALUES (
          'doc-assess', ?, 'identity-assess', 'source-assess.pdf', 'application/pdf',
          'processed', 'assessment_guidance', 'general', 'England and Wales', ?, ?
        )
        """,
        ("a" * 64, now, now),
    )
    database.execute(
        """
        INSERT INTO source_versions(
          id, document_id, version_sha256, canonical_markdown_path, title,
          review_status, superseded_by, created_at
        ) VALUES
          ('sv-old', 'doc-assess', ?, 'data/vault/assess-old.md', 'Assessment pack',
           'rejected', 'sv-new', ?),
          ('sv-new', 'doc-assess', ?, 'data/vault/assess-new.md', 'Assessment pack',
           'rejected', NULL, ?)
        """,
        ("a" * 64, now, "b" * 64, now),
    )
    database.execute(
        """
        INSERT INTO rubric_rules(
          id, task_type, subject, criterion, polarity, grade_band, rule_text,
          remediation_text, source_version_id, review_status, created_at
        ) VALUES (
          'assessment-canonical-load-v1', NULL, NULL, 'application',
          'positive_pattern', '70+',
          'Apply each governing rule accurately to the material facts for drafting.',
          NULL, 'sv-old', 'approved', ?
        )
        """,
        (now,),
    )
    ids = {
        row["id"] for row in database.approved_assessment_rules(task_type="general", subject="tort")
    }
    assert "assessment-canonical-load-v1" in ids
