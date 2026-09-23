from datetime import date

import pytest

from app.config import Settings
from app.model_routes import CodexBridgeGateway
from app.orchestration.answer_structure import canonical_heading, section_contract
from app.orchestration.contracts import ModelDraft
from app.orchestration.retry_policy import is_deterministic_safety_failure
from app.orchestration.runner import _bind_model_draft_context
from app.runtime_adapters import LoopbackModelGateway
from app.types import StructuredDraft, TaskType


def test_host_owned_roles_survive_normalisation_without_model_heading_prose():
    draft = StructuredDraft.model_validate({
        "title": "Unverified legal title", "task_type": "general", "jurisdiction": "England",
        "as_of_date": "2026-09-23", "sections": [{
            "id": "next-steps", "heading": "Unverified legal claim smuggled into a heading",
            "claims": [{"id": "c1", "text": "A supported step", "evidence_ids": ["e1"]}],
        }],
    })
    bound = _bind_model_draft_context(
        ModelDraft(raw_text="{}", structured=draft, rubric_scores={}, model_version="synthetic", metrics={}),
        task_type=TaskType.GENERAL, jurisdiction="England", as_of_date=date(2026, 9, 23),
    )
    assert bound.structured.sections[0].heading == "Practical next steps"
    assert canonical_heading("general", "unrecognised-id", 1) == "Analysis 1"
    assert section_contract("essay")[0]["id"] == "thesis"


def test_hosted_provider_gets_its_own_budget_without_changing_qwen(tmp_path):
    settings = Settings(project_root=tmp_path)
    local = LoopbackModelGateway(settings)
    codex = CodexBridgeGateway(settings, {"model_id": "gpt-5.5", "auth_mode": "chatgpt_signin"})
    assert local.max_question_chars == 3500
    assert codex.max_question_chars == 30000
    assert codex.assessment_character_budget > local.assessment_character_budget
    assert codex.output_token_budget > local.output_token_budget
    assert codex._generation_config_sha256() != local._generation_config_sha256()


def test_quality_repair_is_allowed_while_evidence_safety_still_stops():
    assert not is_deterministic_safety_failure("applicable_avoidance_standard_failed")
    for code in ("unsupported_material_fact", "false_quotation", "wrong_jurisdiction", "personal_data_leakage"):
        assert is_deterministic_safety_failure(code)


def application_draft():
    return StructuredDraft.model_validate({
        "title":"Application", "task_type":"general", "jurisdiction":"England",
        "as_of_date":"2026-09-23", "sections":[{"id":"application","heading":"Application",
        "claims":[{"id":"rule","text":"A consumer may receive a refund.","evidence_ids":["e1"]},
                  {"id":"apply","kind":"application","text":"The consumer seeks a refund of £799.",
                   "evidence_ids":["e1"],"fact_quotes":["I paid £799."],"rule_claim_ids":["rule"]}]}]})


def test_application_binds_exact_user_facts_without_turning_them_into_law():
    from app.quality.fact_provenance import verified_application_quotes
    draft=application_draft()
    claim=draft.sections[0].claims[1]
    assert verified_application_quotes(claim,draft,"I paid £799.") == ("I paid £799.",)
    for question in (None,"I paid £500."):
        with pytest.raises(ValueError,match="application_fact_not_in_question"):
            verified_application_quotes(claim,draft,question)
    with pytest.raises(ValueError,match="application_legal_rule_dependency_invalid"):
        verified_application_quotes(claim.model_copy(update={"rule_claim_ids":["apply"]}),draft,"I paid £799.")
    with pytest.raises(ValueError,match="application_evidence_outside_legal_rules"):
        verified_application_quotes(claim.model_copy(update={"evidence_ids":["another"]}),draft,"I paid £799.")


def test_application_fact_values_reach_validator_but_invented_values_still_hold(evidence):
    from app.quality.evaluator import QualityEvaluator
    draft=application_draft()
    span=evidence.model_copy(update={"id":"e1","text":"A consumer may receive a refund."})
    def evaluate(question):
        return QualityEvaluator().evaluate(answer_version_id="a1",draft=draft,
            rendered_text="A consumer may receive a refund.",evidence_by_id={"e1":span},
            word_count=450,word_target=450,question=question)
    assert not any(f.code=="unsupported_material_fact" for f in evaluate("I paid £799.").findings)
    assert any(f.code=="unsupported_material_fact" for f in evaluate("I paid £500.").findings)


def test_application_binding_feedback_identifies_exact_missing_dependency_without_mutation():
    from app.quality.fact_provenance import (
        application_binding_repair_hint,
        verified_application_quotes,
    )
    draft = application_draft()
    claim = draft.sections[0].claims[1].model_copy(update={"rule_claim_ids": ["missing-rule"]})
    before = draft.model_dump_json()
    hint = application_binding_repair_hint(claim, draft, "I paid £799.")
    assert '"invalid_rule_claim_ids": ["missing-rule"]' in hint
    assert '"existing_rule_candidates_by_evidence": {"e1": ["rule"]}' in hint
    assert "does not establish" in hint
    assert draft.model_dump_json() == before
    with pytest.raises(ValueError, match="application_legal_rule_dependency_invalid"):
        verified_application_quotes(claim, draft, "I paid £799.")


def test_application_review_preserves_full_fact_context_and_binds_changes(evidence):
    from app.quality.ai_evidence_reviewer import freeze_material_claims
    draft = application_draft()
    span = evidence.model_copy(update={"id": "e1", "jurisdiction": "England"})
    first = freeze_material_claims(draft=draft, evidence_by_id={"e1": span},
                                  question="I paid £799. The laptop was new.")
    second = freeze_material_claims(draft=draft, evidence_by_id={"e1": span},
                                   question="I paid £799. The laptop was used.")
    assert first[0].question_context == ""  # User text never supplies a pure legal rule.
    assert first[0].identity == second[0].identity
    assert first[1].model_payload()["question_context"].endswith("The laptop was new.")
    assert first[1].assumed_question_facts == ("I paid £799.",)
    assert first[1].identity.evidence_bundle_sha256 != second[1].identity.evidence_bundle_sha256


def test_gap_uuid_digits_are_not_misclassified_as_a_phone(tmp_path, cipher):
    from app.orchestration.gaps import GapQueue
    from app.types import KnowledgeGap
    gap=KnowledgeGap(id="39a68ef2-4071-4936-9c59-b5da8bbf5d74",
        job_id="f793e803-68ef-47b3-9fe9-888622374560",missing_proposition="Call +44 7700 900123 about a refund.",jurisdiction="England")
    path=GapQueue(tmp_path,cipher).persist(gap)
    restored=KnowledgeGap.model_validate_json(cipher.decrypt_text(path.read_bytes()))
    assert restored.id==gap.id and restored.job_id==gap.job_id
    assert "+44" not in restored.missing_proposition and "[PHONE]" in restored.missing_proposition


def test_no_attachment_is_a_supplied_fact_not_a_missing_document():
    from app.orchestration.behavior import looks_like_missing_document
    assert not looks_like_missing_document("There was no prescribed form or attachment. I have not agreed to leave.",0)
    assert looks_like_missing_document("Please see the attached notice.",0)


def test_excess_length_has_a_scoped_repair_and_cannot_release_full(evidence):
    from app.quality.evaluator import QualityEvaluator
    report=QualityEvaluator().evaluate(answer_version_id="long-answer",draft=application_draft(),
        rendered_text="A consumer may receive a refund.",evidence_by_id={"e1":evidence},
        word_count=1000,word_target=700,question="I paid £799.")
    finding=next(f for f in report.findings if f.code=="longer_than_requested")
    assert finding.section_id=="application"
    assert str(report.release_state)=="held_for_review"


def test_selected_provider_identity_is_used_for_review_provenance(tmp_path):
    from app.model_routes import RoutedModelGateway
    settings=Settings(project_root=tmp_path)
    router=RoutedModelGateway(settings)
    assert router.selected_model_id==settings.model_id
    selected=CodexBridgeGateway(settings,{"model_id":"gpt-5.5","auth_mode":"chatgpt_signin"})
    token=router._selected.set(selected)
    try:
        assert router.selected_model_id=="gpt-5.5"
        assert router.selected_generation_config_sha256==selected._generation_config_sha256()
    finally:
        router.reset(token)
    assert router.selected_model_id==settings.model_id


def test_checkpoint_cannot_reuse_an_answer_across_provider_budget_changes():
    from app.orchestration.runner import draft_checkpoint_input_sha256
    args=dict(question="Refund?",task_type=TaskType.GENERAL,jurisdiction="England",as_of_date=date(2026,9,23),
        word_target=450,pack_digest="a"*64,assessment_rules=[],upload_context=[],
        assessment_bundle_sha256="b"*64,model_id="same-model")
    assert draft_checkpoint_input_sha256(**args,generation_config_sha256="c"*64) != draft_checkpoint_input_sha256(**args,generation_config_sha256="d"*64)


def test_ge_prompt_leads_with_conclusion_without_forcing_repeated_analysis():
    from app.orchestration.answer_structure import drafting_section_contract
    assert [r['id'] for r in drafting_section_contract('general')] == [
        'direct-answer', 'next-steps', 'applicable-law', 'qualifications',
    ]
    assert drafting_section_contract('essay') == section_contract('essay')
    assert canonical_heading('general', 'conclusion', 5) == 'Conclusion'


def test_codex_reasoning_profile_is_explicit_and_digest_bound(tmp_path):
    gateway = CodexBridgeGateway(Settings(project_root=tmp_path), {
        'model_id': 'gpt-5.5', 'auth_mode': 'chatgpt_signin',
    })
    assert gateway._reasoning_effort('draft') == 'high'
    assert gateway._reasoning_effort('repair') == 'high'
    assert gateway._reasoning_effort('semantic_verify') == 'medium'
    from app.model_routes import HostedEvidenceGateway
    assert gateway._generation_config_sha256() != HostedEvidenceGateway._generation_config_sha256(gateway)
