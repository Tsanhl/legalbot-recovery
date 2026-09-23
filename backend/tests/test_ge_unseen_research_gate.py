"""Synthetic receipt/gate checks; no bank, model, network or file writes."""
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase

from scripts.ge_unseen_research_gate import (
    REQUIRED_CHECKS, require_plan_execution, require_research_runtime,
)


def seal(value):
    body = {k: v for k, v in value.items() if k != "content_sha256"}
    return {**body, "content_sha256": hashlib.sha256(
        json.dumps(body, sort_keys=True).encode()).hexdigest()}


class GateTests(TestCase):
    def setUp(self):
        root = Path('/synthetic')
        public = root / 'public'
        self.files = {}
        self.hashes = {}
        self.r = SimpleNamespace(ROOT=root, PUBLIC=public, RUN_ID='test',
            read=lambda p: self.files[p], seal=seal,
            sha=lambda p: self.hashes.get(p, 'b' * 64), safe_path=lambda p: None,
            runtime_files=lambda: {'scripts/real.py': 'd' * 64},
            runtime_environment=lambda: {'synthetic_environment': 'original'})
        self.plan = {
            'run_id': 'test', 'owner_instruction': 'do in full then the plan',
            'creation_review_then_one_pass': True, 'training': False,
            'production_admission': False, 'active_mutation': False,
            'promotion': False, 'live': False, 'visible_research_gate_required': True,
            'original_start_sha256': 'b' * 64, 'owner_authorization_sha256': 'b' * 64,
            'scope_amendment_sha256': 'b' * 64, 'accepted_plan_path': 'public/accepted.txt',
            'accepted_plan_sha256': 'b' * 64,
        }
        self.validation = {
            'run_id': 'test', 'status': 'PASS', 'plan_execution_sha256': 'b' * 64,
            'runtime_files': self.r.runtime_files(), 'private_bank_used': False,
            'runtime_environment': self.r.runtime_environment(),
            'weight_training': False, 'artifacts': {'proof/inference.json': 'b' * 64},
            'checks': {name: {'status': 'PASS', 'evidence': ['proof/inference.json']}
                       for name in REQUIRED_CHECKS},
            'model_manifest_sha256': 'a' * 64, 'baseline_generation_sha256': 'e' * 64,
        }
        self.refresh()

    def refresh(self):
        self.files[self.r.PUBLIC / 'PLAN-EXECUTION-AUTHORIZATION.json'] = seal(self.plan)
        self.files[self.r.PUBLIC / 'AUTO-RESEARCH-VISIBLE-VALIDATION.json'] = seal(self.validation)

    def test_missing_gate_does_not_fall_back_to_browser_route(self):
        self.files.pop(self.r.PUBLIC / 'AUTO-RESEARCH-VISIBLE-VALIDATION.json')
        with self.assertRaises(KeyError):
            require_research_runtime(self.r)

    def test_runtime_changed_after_visible_validation_is_rejected(self):
        self.r.runtime_files = lambda: {'scripts/real.py': 'e' * 64}
        with self.assertRaises(RuntimeError):
            require_research_runtime(self.r)

    def test_environment_changed_after_validation_is_rejected(self):
        self.r.runtime_environment = lambda: {'synthetic_environment': 'changed'}
        with self.assertRaises(RuntimeError):
            require_research_runtime(self.r)

    def test_every_required_check_must_pass_with_bound_evidence(self):
        for name in REQUIRED_CHECKS:
            with self.subTest(name=name):
                saved = self.validation['checks'][name]
                self.validation['checks'][name] = {'status': 'HOLD', 'evidence': []}
                self.refresh()
                with self.assertRaises(RuntimeError):
                    require_research_runtime(self.r)
                self.validation['checks'][name] = saved

    def test_evidence_byte_change_is_rejected_even_if_receipt_flags_pass(self):
        self.hashes[self.r.ROOT / 'proof/inference.json'] = 'c' * 64
        with self.assertRaises(RuntimeError):
            require_research_runtime(self.r)

    def test_private_case_reuse_is_rejected(self):
        self.validation['private_bank_used'] = True
        self.refresh()
        with self.assertRaises(RuntimeError):
            require_research_runtime(self.r)

    def test_authority_cannot_expand_to_training(self):
        self.plan['training'] = True
        self.refresh()
        with self.assertRaises(RuntimeError):
            require_plan_execution(self.r)

    def test_evidence_path_cannot_escape(self):
        self.plan['accepted_plan_path'] = '../other/accepted.txt'
        self.refresh()
        with self.assertRaises(RuntimeError):
            require_plan_execution(self.r)

    def test_fully_bound_synthetic_receipt_passes_mechanical_gate(self):
        # This proves only validator behavior, not an actual implementation pass.
        self.assertEqual(require_research_runtime(self.r), seal(self.validation))
