"""Pinned Qwen causal yes/no reranking with the installed Transformers runtime.

The installed sentence-transformers 5.1 CrossEncoder uses a sequence-classifier
loader; this pinned model declares Qwen3ForCausalLM. Use the model publisher's
documented causal inference recipe, never a newly initialized classification head.
No model/download/library replacement or weight training is performed.
"""
from __future__ import annotations

import fcntl
import json
import math
import time

from scripts.ge_auto_research_runtime import PIN, ROOT, _digest, _safe

MAX_PAIRS = 8
MAX_TOKENS = 2048
PREFIX = ('<|im_start|>system\nJudge whether the Document meets the requirements '
          'based on the Query and the Instruct provided. Note that the answer '
          'can only be "yes" or "no".<|im_end|>\n<|im_start|>user\n')
SUFFIX = '<|im_end|>\n<|im_start|>assistant\n<think>\n\n</think>\n\n'
RECIPE_SOURCE = 'https://huggingface.co/Qwen/Qwen3-Reranker-0.6B/blob/e61197ed45024b0ed8a2d74b80b4d909f1255473/README.md'


def verified_reranker_identity():
    from scripts.model.download_retrieval_models import (
        _file_manifest_sha256,
        _recursive_file_manifest,
        _validate,
        load_spec,
    )
    item = next(x for x in load_spec(PIN)['models'] if x['role'] == 'reranker')
    path = ROOT / item['directory']
    _safe(path)
    _validate(path, item)
    actual = _file_manifest_sha256(_recursive_file_manifest(path))
    saved = json.loads((path / 'retrieval-model.json').read_text())
    config = json.loads((path / 'config.json').read_text())
    if (actual != item['file_manifest_sha256'] or saved['revision'] != item['revision']
            or saved['source_repo'] != item['source_repo']
            or config['architectures'] != ['Qwen3ForCausalLM']):
        raise RuntimeError('pinned causal reranker identity mismatch')
    value = {'source_repo': item['source_repo'], 'revision': item['revision'],
             'directory': item['directory'], 'file_manifest_sha256': actual,
             'loader': 'AutoModelForCausalLM', 'scoring': 'LAST_TOKEN_YES_NO_SOFTMAX',
             'recipe_source': RECIPE_SOURCE, 'device': 'cpu', 'threads': 2,
             'batch_size': 1, 'max_pairs': MAX_PAIRS, 'max_tokens': MAX_TOKENS,
             'local_files_only': True, 'training': False, 'prefix_sha256': _digest(PREFIX),
             'suffix_sha256': _digest(SUFFIX)}
    return {**value, 'identity_sha256': _digest(value)}


class PinnedRerankerSession:
    def __init__(self):
        self.lock = None
        self.model = None
        self.tokenizer = None
        self.identity = None
        self.calls = []
        self.loading_info = None

    def __enter__(self):
        lock = ROOT / 'data/research/ge-auto-research/embedding.lock'
        _safe(lock)
        lock.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock = lock.open('a+')
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.identity = verified_reranker_identity()
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer
            torch.set_num_threads(2)
            path = str(ROOT / self.identity['directory'])
            self.tokenizer = AutoTokenizer.from_pretrained(
                path, local_files_only=True, trust_remote_code=False, padding_side='left')
            self.model, self.loading_info = AutoModelForCausalLM.from_pretrained(
                path, local_files_only=True, trust_remote_code=False,
                torch_dtype=torch.float32, output_loading_info=True)
            if any(self.loading_info.get(k) for k in ('missing_keys', 'unexpected_keys', 'mismatched_keys', 'error_msgs')):
                raise RuntimeError('reranker weights were not loaded exactly; refuse manufactured head')
            self.model.eval()
            self.yes = self.tokenizer.encode('yes', add_special_tokens=False)
            self.no = self.tokenizer.encode('no', add_special_tokens=False)
            if len(self.yes) != 1 or len(self.no) != 1 or self.yes == self.no:
                raise RuntimeError('reranker yes/no token identity invalid')
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *args):
        self.model = self.tokenizer = None
        if self.lock is not None:
            fcntl.flock(self.lock, fcntl.LOCK_UN)
            self.lock.close()
            self.lock = None

    def predict(self, pairs, *, show_progress_bar=False):
        """Compatible with the existing QwenRerankerProvider's injected model seam."""
        import torch
        from backend.app.retrieval.qwen import LEGAL_RETRIEVAL_INSTRUCTION
        if self.model is None or not 1 <= len(pairs) <= MAX_PAIRS:
            raise ValueError('active pinned reranker and at most eight pairs required')
        scores = []
        for query, document in pairs:
            if not all(isinstance(x, str) and x.strip() for x in (query, document)):
                raise ValueError('nonempty query/document required')
            text = (PREFIX + f'<Instruct>: {LEGAL_RETRIEVAL_INSTRUCTION}\n<Query>: {query}'
                    f'\n<Document>: {document}' + SUFFIX)
            ids = self.tokenizer.encode(text, add_special_tokens=False)
            if len(ids) > MAX_TOKENS:
                raise ValueError('ranking context exceeded; refuse silent truncation')
            started = time.monotonic()
            tokens = torch.tensor([ids], dtype=torch.long)
            with torch.inference_mode():
                logits = self.model(input_ids=tokens, attention_mask=torch.ones_like(tokens),
                                    use_cache=False).logits[0, -1]
                pair_logits = torch.stack([logits[self.no[0]], logits[self.yes[0]]])
                score = float(torch.softmax(pair_logits.float(), dim=0)[1])
            if not math.isfinite(score) or not 0 <= score <= 1:
                raise RuntimeError('invalid reranker probability')
            scores.append(score)
            self.calls.append({'query_sha256': _digest(query), 'document_sha256': _digest(document),
                               'tokens': len(ids), 'score': score,
                               'seconds': round(time.monotonic() - started, 6)})
        return scores

    def receipt(self):
        return {'schema': 'legalbot.ge-auto-research-reranking.v1', 'model_identity': self.identity,
                'loading_info': self.loading_info, 'calls': self.calls,
                'actual_pairs_scored': len(self.calls), 'training': False,
                'classification_head_created': False}
