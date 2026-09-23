"""Own synthetic in-memory review inputs; no case data, network, models or cleanup."""
from copy import deepcopy

import pytest
from jsonschema import Draft202012Validator
from scripts import ge_auto_visible_answer_review as r
from scripts.ge_auto_case_protocol import render_source_links

H = r.sha256(b'SYNTHETIC PIN ONLY')
URL = 'https://www.legislation.gov.uk/synthetic-test-only'
ANSWER = 'You may request a conditional refund.'
LAW = 'Synthetic rule: a conditional refund may be requested.'
QUESTION = 'May I request a conditional refund?'


def span(text, excerpt=None):
    excerpt = text if excerpt is None else excerpt
    start = text.index(excerpt)
    return {'start': start, 'end': start + len(excerpt), 'text': excerpt}


class SyntheticParent:
    """Strict test ledger. It supplies no claim of actual model/fence execution."""
    def __init__(self):
        self.artifacts = None
        self.lineage = None
        self.receipt_binding = None
        self.actions = []

    def verify(self, action, binding):
        self.actions.append(action)
        if action == 'answer_review_inputs':
            return (binding['artifacts'] == self.artifacts and binding['lineage'] == self.lineage
                    and binding['hashes'] == {k:r.sha256(v) for k,v in self.artifacts.items()})
        if action == 'answer_review_receipt':
            return binding == self.receipt_binding
        return False


def bundle(status='ANSWER'):
    candidate = {'status': status, 'answer': ANSWER, 'cited_proposition_ids': ['P1']}
    references = [{'proposition_id': 'P1', 'sources': [{'source_sha256': H,
        'canonical_url': URL, 'final_url': URL, 'locators': [{'part_id': 'B1', 'locator': 'Synthetic section 1'}]}]}]
    rendered = render_source_links(candidate, references)
    terminal = {'case_id': 'VISIBLE-SYNTHETIC-1', 'turn': 1, 'answer': candidate,
        'rendered_answer': rendered, 'rendered_answer_sha256': r.sha256(rendered.encode()),
        'citation_renderer': 'DETERMINISTIC_SOURCE_LINKS_NOT_OSCOLA_CERTIFIED',
        'state': 'FINAL_RECORDED_AWAITING_BLIND_SCORING', 'artifacts': {'raw-final.json': H}}
    artifacts = {
        'scenario': r.canonical({'schema': 'legalbot.ge-visible-review-scenario.v1',
            'case_id': 'VISIBLE-SYNTHETIC-1', 'visibility': 'VISIBLE', 'turn': 1,
            'question': QUESTION, 'question_sha256': r.sha256(QUESTION.encode()),
            'request_sha256': H, 'as_of_date': '2026-09-05',
            'jurisdictions': ['England'], 'author_expectations_included': False}),
        'fact_projection': r.canonical({'schema': 'legalbot.ge-visible-fact-projection.v1',
            'case_id': 'VISIBLE-SYNTHETIC-1', 'turn': 1, 'request_sha256': H,
            'query_plan_id': 'query-plan-synthetic', 'query_plan_sha256': H,
            'fact_snapshot_id': 'fact-snapshot-synthetic', 'fact_snapshot_sha256': H,
            'facts': [{'fact_id': 'fact-question', 'turn': 1, 'kind': 'question',
                'source_id': 'request-synthetic', 'text': QUESTION,
                'text_sha256': r.sha256(QUESTION.encode()), 'origin': 'user_statement',
                'status': 'stated', 'affected_issue_ids': ['R1']}],
            'semantic_facts_inferred': False, 'author_expectations_included': False}),
        'candidate': r.canonical(candidate), 'terminal': r.canonical(terminal),
        'evidence': r.canonical({'case_id': 'VISIBLE-SYNTHETIC-1', 'source_references': references,
            'sources': [{'source_id': 'S1', 'selected_evidence_id': 'evidence-synthetic',
                'raw_sha256': H, 'parser_sha256': H, 'parsed_sha256': H,
                'source_review_sha256': H, 'canonical_url': URL, 'final_url': URL,
                'valid_from': '2026-09-05', 'valid_to': '2026-09-05', 'jurisdiction': 'GB-ENG',
                'scope': 'SYNTHETIC ONLY', 'limits': ['No actual law or legal result.'],
                'required_context_block_ids': ['B1'], 'blocks': [{'block_id': 'B1', 'ordinal': 1,
                    'locator': 'Synthetic section 1', 'text': LAW, 'text_sha256': r.sha256(LAW.encode())}]}]}),
        'source_review': r.canonical({'case_id': 'VISIBLE-SYNTHETIC-1', 'reviewer_ids': ['source-reviewer'],
            'context_ids': ['source-context'], 'records': [{'kind': 'SYNTHETIC_SOURCE_REVIEW',
                                                         'source_sha256': H, 'professional': False}]}),
        'requirements': r.canonical([{'requirement_id': 'R1', 'text': 'Address the conditional request.'}]),
        'candidate_receipt': r.canonical({'SYNTHETIC_TEST_ONLY': True, 'candidate_sha256': r.sha256(r.canonical(candidate))}),
    }
    lineage = {'case_id': 'VISIBLE-SYNTHETIC-1', 'turn': 1, 'runtime_sha256': H,
        'terminal_sha256': r.sha256(artifacts['terminal']), 'candidate_context_id': 'candidate-context',
        'excluded_reviewer_context_ids': ['candidate-context', 'mapper-context']}
    parent = SyntheticParent()
    parent.artifacts, parent.lineage = deepcopy(artifacts), deepcopy(lineage)
    return artifacts, lineage, parent


def prepare(artifacts, lineage, parent):
    return r.prepare_review(artifacts=artifacts, expected_hashes={k:r.sha256(v) for k,v in artifacts.items()},
                            lineage=lineage, host_verify=parent.verify)


def no_source_bundle(status='HOLD'):
    artifacts, lineage, parent = bundle(status)
    candidate = {'status': status, 'answer': 'I could not verify the applicable law.', 'cited_proposition_ids': []}
    terminal = r.decode(artifacts['terminal'])
    terminal.update(answer=candidate, rendered_answer=candidate['answer'],
                    rendered_answer_sha256=r.sha256(candidate['answer'].encode()))
    artifacts['candidate'], artifacts['terminal'] = r.canonical(candidate), r.canonical(terminal)
    evidence = r.decode(artifacts['evidence'])
    evidence.update(sources=[], source_references=[])
    artifacts['evidence'] = r.canonical(evidence)
    artifacts['source_review'] = r.canonical({'case_id': lineage['case_id'], 'reviewer_ids': [],
        'context_ids': [], 'records': [], 'not_performed_reason': 'NO_CAPTURED_SOURCES'})
    lineage['terminal_sha256'] = r.sha256(artifacts['terminal'])
    parent.artifacts, parent.lineage = deepcopy(artifacts), deepcopy(lineage)
    return artifacts, lineage, parent


def test_held_answer_with_no_sources_can_receive_claim_review():
    artifacts, lineage, parent = no_source_bundle()
    packet = prepare(artifacts, lineage, parent)
    assert r.decode(packet['artifacts']['evidence'].encode())['sources'] == []
    assert packet['source_reviewer_metadata']['reviewer_ids'] == []
    assert 'full_answer_pass' not in packet


def test_no_sources_cannot_support_a_substantive_answer():
    with pytest.raises(r.ReviewError, match='source review|without reviewed evidence'):
        prepare(*no_source_bundle('ANSWER'))


def test_absent_source_review_must_not_claim_reviewer_identity():
    artifacts, lineage, parent = no_source_bundle()
    metadata = r.decode(artifacts['source_review'])
    metadata['reviewer_ids'] = ['invented-reviewer']
    artifacts['source_review'] = r.canonical(metadata)
    parent.artifacts = deepcopy(artifacts)
    with pytest.raises(r.ReviewError, match='cannot claim an identity'):
        prepare(artifacts, lineage, parent)


def response(packet):
    bindings = {k:v['const'] for k,v in r.review_schema(packet)['properties']['bindings']['properties'].items()}
    rendered = packet['candidate_projection']['text']
    return {'bindings': bindings,
        'coverage': {'all_material_claims_identified': True, 'all_material_omissions_checked': True,
                     'whole_context_read': True, 'explanation': 'Synthetic complete review only.'},
        'answer_units': [{**span(rendered, ANSWER), 'claim_ids': ['C1', 'C2', 'C3'], 'non_claim_reason': ''},
                         {'start': len(ANSWER), 'end': len(rendered), 'text': rendered[len(ANSWER):],
                          'claim_ids': [], 'non_claim_reason': 'Deterministic links; metadata checked separately.'}],
        'claims': [{'claim_id': 'C1', 'claim_sha256': r.sha256(ANSWER.encode()),
            'answer_span': span(rendered, ANSWER), 'material': True, 'kind': 'LEGAL',
            'requirement_ids': ['R1'], 'depends_on_claim_ids': [],
            'status': 'SUPPORTED', 'evidence_spans': [{**span(LAW), 'source_id': 'S1', 'block_id': 'B1'}],
            'fact_spans': [], 'explanation': 'Synthetic rule supports the conditional statement.'},
            {'claim_id': 'C2', 'claim_sha256': r.sha256(ANSWER.encode()),
            'answer_span': span(rendered, ANSWER), 'material': True, 'kind': 'FACT',
            'requirement_ids': ['R1'], 'depends_on_claim_ids': [],
            'status': 'SUPPORTED', 'evidence_spans': [],
            'fact_spans': [{**span(QUESTION, 'conditional refund'), 'fact_id': 'fact-question'}],
            'explanation': 'Synthetic scenario supplies the condition.'},
            {'claim_id': 'C3', 'claim_sha256': r.sha256(ANSWER.encode()),
            'answer_span': span(rendered, ANSWER), 'material': True, 'kind': 'APPLICATION',
            'requirement_ids': ['R1'], 'depends_on_claim_ids': ['C1', 'C2'],
            'status': 'SUPPORTED', 'evidence_spans': [], 'fact_spans': [],
            'explanation': 'Application depends on the reviewed rule and scenario fact.'}],
        'requirement_reviews': [{'requirement_id': 'R1', 'status': 'ADDRESSED',
                                 'answer_spans': [span(rendered, ANSWER)], 'explanation': 'Conditional request addressed.'}],
        'additional_omissions': [],
        'factual_checks': {k:{'status': 'PASS', 'reason': 'Synthetic checked circumstance.'} for k in r.FACTUAL_CHECKS},
        'quality': {k:{'score': score, 'reason': 'Synthetic numeric threshold test.'}
                    for k,score in zip(r.QUALITY_MAX, [17.5, 15, 10.5, 9, 8, 5, 5])},
        'assessment_summary': 'SYNTHETIC only; no real candidate has been scored.'}


@pytest.fixture
def prepared():
    artifacts, lineage, parent = bundle()
    packet = prepare(artifacts, lineage, parent)
    return packet, response(packet), parent


def test_number_schema_supports_fractional_floors_and_exact_70(prepared):
    packet, review, _ = prepared
    Draft202012Validator.check_schema(r.review_schema(packet))
    result = r.validate_review_output(review, packet)
    assert result['quality_score'] == 70 and result['provisional_full_answer_pass']
    assert not result['full_answer_pass']
    assert result['review_acceptance'] == 'PENDING_PARENT_RECEIPT_VERIFICATION'
    assert result['bindings']['rendered_answer_sha256'] != result['bindings']['raw_model_answer_sha256']
    assert packet['candidate_projection']['text'].startswith(ANSWER + '\n\nSources')


@pytest.mark.parametrize('value', [True, '17.5', -1, 25.1, float('nan'), float('inf')])
def test_invalid_numeric_scores_refused(prepared, value):
    packet, review, _ = prepared
    review['quality']['legal_and_factual_accuracy']['score'] = value
    with pytest.raises(r.ReviewError):
        r.validate_review_output(review, packet)


def test_threshold_not_rounded_up(prepared):
    packet, review, _ = prepared
    review['quality']['traceability_and_citations']['score'] = 4.999
    result = r.validate_review_output(review, packet)
    assert result['quality_score'] == 69.999 and not result['quality_pass']


def test_high_total_cannot_override_critical_floor(prepared):
    packet, review, _ = prepared
    for k, maximum in r.QUALITY_MAX.items():
        review['quality'][k]['score'] = maximum
    review['quality']['authority_and_currentness']['score'] = 10.49
    result = r.validate_review_output(review, packet)
    assert result['quality_score'] > 90 and not result['critical_floor_pass'] and not result['full_answer_pass']


@pytest.mark.parametrize('defect', ['unsupported', 'contradicted', 'unresolved', 'omitted_requirement',
    'additional_omission', 'incomplete_claims', 'unread_context', 'failed_fact', 'mandatory_na'])
def test_material_failure_precedes_quality(prepared, defect):
    packet, review, _ = prepared
    if defect in ('unsupported', 'contradicted', 'unresolved'):
        review['claims'][0]['status'] = defect.upper()
        review['claims'][2]['status'] = defect.upper()
    elif defect == 'omitted_requirement':
        review['requirement_reviews'][0]['status'] = 'OMITTED'
    elif defect == 'additional_omission':
        review['additional_omissions'] = [{'material': True, 'description': 'Missing synthetic exception.', 'explanation': 'Material limit omitted.'}]
    elif defect == 'incomplete_claims':
        review['coverage']['all_material_claims_identified'] = False
    elif defect == 'unread_context':
        review['coverage']['whole_context_read'] = False
    else:
        review['factual_checks']['jurisdiction_scope']['status'] = 'NOT_APPLICABLE' if defect == 'mandatory_na' else 'FAIL'
    with pytest.raises(r.ReviewError, match='quality only'):
        r.validate_review_output(review, packet)
    review['quality'] = None
    result = r.validate_review_output(review, packet)
    assert not result['factual_pass'] and result['quality_score'] is None and not result['full_answer_pass']


@pytest.mark.parametrize('defect', ['missing_requirement', 'duplicate_requirement', 'unknown_evidence',
    'wrong_quote', 'wrong_claim_hash', 'missing_support', 'uncovered_claim', 'raw_only_projection',
    'inventory_overlap', 'unclassified_tail', 'altered_hash', 'extra_approval', 'missing_dimension'])
def test_review_mechanical_forgery_or_incompleteness_refused(prepared, defect):
    packet, review, _ = prepared
    if defect == 'missing_requirement': review['requirement_reviews'] = []
    elif defect == 'duplicate_requirement': review['requirement_reviews'] *= 2
    elif defect == 'unknown_evidence': review['claims'][0]['evidence_spans'][0]['block_id'] = 'other-case'
    elif defect == 'wrong_quote': review['claims'][0]['evidence_spans'][0]['text'] = 'Invented'
    elif defect == 'wrong_claim_hash': review['claims'][0]['claim_sha256'] = H
    elif defect == 'missing_support': review['claims'][0]['evidence_spans'] = []
    elif defect == 'uncovered_claim': review['answer_units'][0].update(claim_ids=[], non_claim_reason='Unexamined')
    elif defect == 'raw_only_projection': review['answer_units'] = review['answer_units'][:1]
    elif defect == 'inventory_overlap': review['answer_units'] *= 2
    elif defect == 'unclassified_tail': review['answer_units'] = [{**span(packet['candidate_projection']['text']), 'claim_ids': ['C1'], 'non_claim_reason': ''}]
    elif defect == 'altered_hash': review['bindings']['candidate_answer_sha256'] = H
    elif defect == 'extra_approval': review['source_admission'] = True
    else: review['quality'].pop('traceability_and_citations')
    with pytest.raises(r.ReviewError): r.validate_review_output(review, packet)


@pytest.mark.parametrize('defect', ['missing_context', 'wrong_block_hash', 'wrong_case', 'historical_window',
    'rendered_tamper', 'raw_tamper', 'locator_tamper', 'missing_terminal', 'nonvisible'])
def test_input_failure_even_if_attacker_rehashes_its_payload(defect):
    artifacts, lineage, parent = bundle()
    if defect == 'missing_terminal':
        artifacts.pop('terminal')
    elif defect == 'nonvisible':
        value = r.decode(artifacts['scenario']); value['visibility'] = 'PRIVATE'; artifacts['scenario'] = r.canonical(value)
    elif defect in ('rendered_tamper', 'raw_tamper'):
        value = r.decode(artifacts['terminal'])
        if defect == 'rendered_tamper':
            value['rendered_answer'] += ' Fabricated link'
            value['rendered_answer_sha256'] = r.sha256(value['rendered_answer'].encode())
        else:
            candidate = r.decode(artifacts['candidate']); candidate['answer'] = 'Different raw answer'
            artifacts['candidate'] = r.canonical(candidate); value['answer'] = candidate
        artifacts['terminal'] = r.canonical(value); lineage['terminal_sha256'] = r.sha256(artifacts['terminal'])
    else:
        value = r.decode(artifacts['evidence']); s = value['sources'][0]
        if defect == 'missing_context': s['required_context_block_ids'].append('MISSING')
        elif defect == 'wrong_block_hash': s['blocks'][0]['text'] += ' injected'
        elif defect == 'wrong_case': value['case_id'] = 'OTHER'
        elif defect == 'historical_window': s['valid_to'] = s['valid_from'] = '2019-11-11'
        else: value['source_references'][0]['sources'][0]['locators'][0]['locator'] = 'Invented section'
        artifacts['evidence'] = r.canonical(value)
    with pytest.raises(r.ReviewError): prepare(artifacts, lineage, parent)


def test_parent_input_verifier_cannot_be_replaced_by_matching_self_hashes():
    artifacts, lineage, parent = bundle()
    altered = r.decode(artifacts['requirements']); altered[0]['text'] = 'Invented easier requirement'
    artifacts['requirements'] = r.canonical(altered)
    with pytest.raises(r.ReviewError, match='parent input'): prepare(artifacts, lineage, parent)


def test_duplicate_and_nonfinite_json_rejected():
    for value in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1e999}'):
        with pytest.raises(r.ReviewError): r.decode(value)


def test_renderer_code_drift_refused_without_changing_parent_file(prepared, monkeypatch):
    packet, review, _ = prepared
    monkeypatch.setattr(r, 'citation_renderer_sha256', lambda: H)
    with pytest.raises(r.ReviewError, match='renderer changed'):
        r.validate_review_output(review, packet)


def test_fact_claim_requires_candidate_visible_fact_provenance(prepared):
    packet, review, _ = prepared
    review['claims'][1]['fact_spans'] = []
    with pytest.raises(r.ReviewError, match='candidate-visible provenance'): r.validate_review_output(review, packet)
    review['claims'][1]['fact_spans'] = [{**span(QUESTION, 'conditional refund'), 'fact_id': 'fact-question'}]
    assert r.validate_review_output(review, packet)['factual_pass']


@pytest.mark.parametrize('defect', ['missing_fact_dependency', 'outside_dependency',
                                    'dependency_cycle', 'missing_requirement_binding'])
def test_application_dependency_graph_is_enforced(prepared, defect):
    packet, review, _ = prepared
    application = review['claims'][2]
    if defect == 'missing_fact_dependency':
        application['depends_on_claim_ids'] = ['C1']
    elif defect == 'outside_dependency':
        application['depends_on_claim_ids'] = ['C1', 'MISSING']
    elif defect == 'dependency_cycle':
        review['claims'][0]['depends_on_claim_ids'] = ['C3']
    else:
        application['requirement_ids'] = []
    with pytest.raises(r.ReviewError):
        r.validate_review_output(review, packet)


@pytest.mark.parametrize('status', ['HOLD', 'CLARIFICATION'])
def test_responsible_nonanswer_is_not_full_answer_pass(status):
    artifacts, lineage, parent = bundle(status)
    packet = prepare(artifacts, lineage, parent)
    result = r.validate_review_output(response(packet), packet)
    assert result['quality_pass'] and not result['full_answer_pass']


def final_args(packet, review, parent):
    output = r.canonical(review)
    receipt = r.canonical({'SYNTHETIC_REVIEW_OBSERVATION': True, 'context': 'fresh-answer-context'})
    identity = {'reviewer_id': 'answer-reviewer', 'context_id': 'fresh-answer-context',
                'model': 'SYNTHETIC', 'provider': 'SYNTHETIC', 'receipt_sha256': r.sha256(receipt)}
    parent.receipt_binding = {'identity': identity, 'lineage': packet['lineage'],
        'packet_sha256': packet['packet_sha256'], 'review_input_bytes_sha256': r.sha256(r.canonical(packet)),
        'output_sha256': r.sha256(output), 'output_bytes': output, 'receipt_bytes': receipt,
        'schema_sha256': r.sha256(r.canonical(r.review_schema(packet))),
        'instructions_sha256': packet['bindings']['instructions_sha256'],
        'required_checks': ['actual fresh context/model/provider', 'exact input/output/schema/instructions',
            'read-only fence and actual file inventory', 'no source research',
            'candidate/source-review lineage unchanged']}
    return dict(packet=packet, output_bytes=output, expected_output_sha256=r.sha256(output),
                reviewer_receipt_bytes=receipt, identity=identity, host_verify=parent.verify)


def test_receipt_accepted_only_from_exact_parent_ledger_and_metadata_separate(prepared):
    packet, review, parent = prepared
    args = final_args(packet, review, parent)
    result = r.finalize_review(**args)
    assert result['review_acceptance'] == 'ACCEPTED_PARENT_VERIFIED_AI_REVIEW'
    assert result['full_answer_pass']
    assert result['source_reviewer_metadata'] == packet['source_reviewer_metadata']
    assert result['answer_reviewer_metadata']['reviewer_id'] != result['source_reviewer_metadata']['reviewer_ids'][0]
    assert not result['professional_legal_sign_off'] and not result['source_admission']
    parent.receipt_binding = None
    with pytest.raises(r.ReviewError, match='parent actual reviewer'): r.finalize_review(**args)


@pytest.mark.parametrize('defect', ['source_context', 'candidate_context', 'source_identity', 'wrong_model', 'fake_receipt', 'wrong_output'])
def test_review_receipt_independence_and_hash_swaps_refused(prepared, defect):
    packet, review, parent = prepared
    args = final_args(packet, review, parent)
    args['identity'] = deepcopy(args['identity'])
    if defect == 'source_context': args['identity']['context_id'] = 'source-context'
    elif defect == 'candidate_context': args['identity']['context_id'] = 'candidate-context'
    elif defect == 'source_identity': args['identity']['reviewer_id'] = 'source-reviewer'
    elif defect == 'wrong_model': args['identity']['model'] = 'UNOBSERVED MODEL'
    elif defect == 'fake_receipt': args['reviewer_receipt_bytes'] = b'{}'
    else: args['expected_output_sha256'] = H
    with pytest.raises(r.ReviewError): r.finalize_review(**args)
