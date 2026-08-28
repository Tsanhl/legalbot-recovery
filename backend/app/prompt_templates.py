"""Tracked prompt templates available without importing the evaluation stack."""

from __future__ import annotations

import hashlib
from pathlib import Path

PROMPTS_DIR = Path(__file__).resolve().parent / "evaluation" / "prompts"
PROPOSER_TEMPLATE_NAME = "proposer_mapping.v2.txt"
SEMANTIC_VERIFIER_TEMPLATE_NAME = "semantic_verifier.v2.txt"
AI_EVIDENCE_REVIEWER_TEMPLATE_NAME = "ai_evidence_reviewer.v2.txt"
DRAFT_GENERATOR_TEMPLATE_NAME = "draft_generator.v4.txt"


def prompt_template_bytes(name: str) -> bytes:
    path = PROMPTS_DIR / name
    if path.parent.resolve() != PROMPTS_DIR.resolve() or not path.is_file():
        raise ValueError("prompt template is missing")
    return path.read_bytes()


def prompt_template_sha256(name: str) -> str:
    return hashlib.sha256(prompt_template_bytes(name)).hexdigest()


def prompt_template_text(name: str) -> str:
    return prompt_template_bytes(name).decode("utf-8")


PROPOSER_TEMPLATE_SHA256 = prompt_template_sha256(PROPOSER_TEMPLATE_NAME)
SEMANTIC_VERIFIER_TEMPLATE_SHA256 = prompt_template_sha256(SEMANTIC_VERIFIER_TEMPLATE_NAME)
AI_EVIDENCE_REVIEWER_TEMPLATE_SHA256 = prompt_template_sha256(AI_EVIDENCE_REVIEWER_TEMPLATE_NAME)
DRAFT_GENERATOR_TEMPLATE_SHA256 = prompt_template_sha256(DRAFT_GENERATOR_TEMPLATE_NAME)
