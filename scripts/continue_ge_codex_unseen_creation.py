#!/usr/bin/env python3
"""Drain authorized creation work; never seal, execute a candidate, or train."""
from __future__ import annotations

import json
import fcntl
import hashlib
import os
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, nullcontext

from scripts import run_ge_codex_unseen as run
from scripts import ge_unseen_author_parts as authorparts
from scripts import ge_unseen_preseal_repair as preseal_repair
from scripts.ge_unseen_creation_outcome import STAGES, inspect_outcome
from scripts.ge_unseen_oracle_parts import assemble_parts, prepare_parts


_RENDER_SCRIPT = """
import hashlib
import sys
from pathlib import Path
from types import SimpleNamespace
from scripts.ge_unseen_fixture_repair import render_formatter_output

work, root, private = map(Path, sys.argv[1:4])
def safe_path(path):
    path = path.absolute()
    if '..' in path.parts or not path.is_relative_to(root):
        raise RuntimeError('render path outside authorized workspace')
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise RuntimeError('render symlink refused')
def recheckable(stage, completion):
    return (stage == 'fixture-format' and type(completion.get('returncode')) is int
            and completion['returncode'] == 0 and completion.get('validation_error') is None)
for name, expected in zip(('output.json', 'COMPLETION.json'), sys.argv[4:6], strict=True):
    path = work / name
    safe_path(path)
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise RuntimeError('formatter changed before rendering')
r = SimpleNamespace(PRIVATE=private, safe_path=safe_path, completion_recheckable=recheckable)
render_formatter_output(r, work)
"""


@contextmanager
def coordinator_lock(r=run):
    """One dispatch/controller owner; retain the lock inode after release."""
    path = r.PUBLIC / "CONTINUOUS-COORDINATOR.lock"
    r.safe_path(path)
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("construction coordinator already running") from None
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def active_work(r=None):
    r = run if r is None else r
    works = set()
    for stage in STAGES:
        root = r.PRIVATE / stage
        r.safe_path(root)
        for work in root.glob("shard-*"):
            r.safe_path(work)
            if ((work / "INVOCATION.json").exists()
                    and not (work / "COMPLETION.json").exists()
                    and not interrupted_work_acknowledged(r, work)):
                works.add(work)
    return works


def active_jobs(r=None) -> int:
    return len(active_work(r))


def interruption_receipt_path(r, work):
    """Return the external receipt path for one abandoned invocation.

    The receipt is deliberately outside ``work``.  The original invocation
    directory therefore remains byte-for-byte evidence of the consumed attempt.
    """

    relative = work.relative_to(r.PRIVATE).as_posix()
    key = hashlib.sha256(relative.encode("utf-8")).hexdigest()
    return r.PRIVATE / "receipts" / "controller-interruptions" / f"{key}.json"


def interrupted_work_acknowledged(r, work) -> bool:
    """Accept only an exact, separately recorded controller interruption."""

    receipt_path = interruption_receipt_path(r, work)
    if not receipt_path.exists():
        return False
    try:
        receipt = r.read(receipt_path)
        relative = work.relative_to(r.PRIVATE).as_posix()
        return bool(
            receipt.get("schema") == "legalbot.ge-worker-interruption.v1"
            and receipt.get("work") == relative
            and receipt.get("invocation_sha256") == r.sha(work / "INVOCATION.json")
            and receipt.get("attempt_consumed") is True
            and receipt.get("automatic_retry") is False
            and receipt.get("original_work_artifacts_modified") is False
        )
    except (KeyError, OSError, RuntimeError, TypeError, ValueError):
        return False


def usage_limited(work) -> bool:
    path=work/"stderr.log"
    run.safe_path(path)
    return (work/"COMPLETION.json").exists() and path.exists() and (
        run.read(work/"COMPLETION.json")["returncode"]!=0
        and "usage limit" in path.read_text().lower())


def advance_fixture_repairs():
    """Prepare parent-selected formatting jobs and render each verified output once."""
    prepare = getattr(preseal_repair, "prepare_fixture_repairs", None)
    if callable(prepare):
        prepare(run)
    root = run.PRIVATE / "fixture-format"
    run.safe_path(root)
    for work in sorted(root.glob("shard-*")):
        run.safe_path(work)
        if not (work / "COMPLETION.json").exists():
            continue
        if ((run.PRIVATE / "fixture-repaired" / work.name).exists()
                or any((run.PRIVATE / "receipts/fixture-format" / (work.name + suffix)).exists()
                       for suffix in ("-render.json", "-render-failure.json"))):
            continue
        try:
            run.validate_job(work)
        except Exception:
            continue  # Invalid/failed work is a case hold, never a retry.
        try:
            # Render in the pinned document runtime, not the coordinator venv.
            # Pass paths as argv, keep captured private errors out of progress.
            run.subprocess.run([str(run.BUNDLED_PYTHON), "-B", "-c", _RENDER_SCRIPT,
                               str(work), str(run.ROOT), str(run.PRIVATE),
                               run.sha(work / "output.json"), run.sha(work / "COMPLETION.json")],
                               cwd=run.ROOT, capture_output=True, text=True, check=True, timeout=180)
            run.validate_job(work)
        except Exception as exc:
            # Preserve the failed local attempt too. No polling retry of bytes
            # which failed the bounded formatter or its renderer.
            path = run.PRIVATE / "receipts/fixture-format" / (work.name + "-render-failure.json")
            if not path.exists():
                run.write(path, run.seal({"error_type": type(exc).__name__,
                    "formatter_output_sha256": run.sha(work / "output.json"), "automatic_retry": False}))


def main(*, lock_held=False) -> None:
    with nullcontext() if lock_held else coordinator_lock(run):
        _drain()


def _drain() -> None:
    run.require_scope_amendment()
    prior=None
    failures={}
    futures={}
    usage_stop=False
    with ThreadPoolExecutor(max_workers=8) as pool:
        while True:
            for future,work in list(futures.items()):
                if not future.done():
                    continue
                try:
                    result=future.result()
                    print(json.dumps(result),flush=True)
                    if result["returncode"] or result["validation_error"]:
                        failures[str(work.relative_to(run.PRIVATE))]=result
                        usage_stop |= usage_limited(work)
                except Exception as exc:
                    failures[str(work.relative_to(run.PRIVATE))]={"error_type":type(exc).__name__}
                futures.pop(future)
            if usage_stop:
                # Only a limit encountered by this dispatch stops new work.
                # Historical failed attempts never block unrelated initial/repair jobs.
                if not futures and not active_jobs():
                    print(json.dumps({"stopped":"MODEL_USAGE_LIMIT_NO_UNCHANGED_RETRY"}),flush=True)
                    return
                time.sleep(10)
                continue
            authorparts.prepare_parts(run)
            authorparts.assemble_parts(run)
            if (run.PUBLIC / "PLAN-EXECUTION-AUTHORIZATION.json").exists():
                from scripts.ge_unseen_novelty_intake import prepare as prepare_novelty
                prepare_novelty(run)
            run.prepare_oracles()
            prepare_parts(run)
            assemble_parts(run)
            # Fixture work is local and uses actual uploaded bytes. Errors are
            # preserved; they stop this affected creation path before any retry.
            run.prepare_fixtures()
            completed_oracle=run.collect("oracle","oracles")
            if completed_oracle:
                run.capture_oracles()
                run.prepare_bank_review()
            preseal_repair.prepare_repairs(run)
            advance_fixture_repairs()
            preseal_repair.prepare_rereviews(run)
            current=run.status()
            snapshot={stage:{k:v for k,v in data.items() if k in
                ("attempted","validated_rows","failed_shards")}
                for stage,data in current.items() if stage in STAGES}
            if snapshot!=prior:
                print(json.dumps({"progress":snapshot}),flush=True)
                prior=snapshot
            # Count each running work directory once, including futures whose
            # invocation receipt has not been written yet and external jobs.
            available=max(0,8-len(active_work() | set(futures.values())))
            dispatch=[("author-parts",run.AUTHOR_PROMPT,False),
                      ("bank-review-repair",run.BANK_REVIEW_PROMPT,True),
                      ("oracle-repair",preseal_repair.REPAIR_PROMPT,True),
                      ("bank-review",run.BANK_REVIEW_PROMPT,True),
                      ("oracle-parts",run.ORACLE_PROMPT,True)]
            if any((run.PRIVATE / "novelty-review").glob("shard-*")):
                from scripts.ge_unseen_novelty_review import review_prompt
                dispatch.append(("novelty-review", review_prompt(), False))
            if any((run.PRIVATE / "fixture-format").glob("shard-*")):
                from scripts.ge_unseen_fixture_repair import FORMATTER_PROMPT
                dispatch.insert(1, ("fixture-format", FORMATTER_PROMPT, False))
            if any((run.PRIVATE / "fixture-inventory").glob("shard-*")):
                from scripts.ge_unseen_fixture_repair import REQUIREMENT_PROMPT
                dispatch.insert(1, ("fixture-inventory", REQUIREMENT_PROMPT, False))
            if any((run.PRIVATE / "fixture-inventory-repair").glob("shard-*")):
                from scripts.ge_unseen_fixture_repair import REQUIREMENT_PROMPT
                dispatch.insert(1, ("fixture-inventory-repair", REQUIREMENT_PROMPT, False))
            for stage,prompt,browse in dispatch:
                for work in sorted((run.PRIVATE/stage).glob("shard-*")):
                    if not available or len(futures)>=8:
                        break
                    if (work/"INVOCATION.json").exists() or work in futures.values():
                        continue
                    if not all((work/name).exists() for name in ("input.json","schema.json")):
                        continue
                    futures[pool.submit(run.invoke,work,prompt,browse=browse)]=work
                    available-=1
            if not futures and not active_jobs():
                # An upstream failure can correctly leave a downstream stage
                # uncreated. Do not wait forever for an impossible completion.
                outcome=inspect_outcome(run)
                if outcome["terminal"]:
                    print(json.dumps({"creation_queue_terminal":True,"failures":failures,
                        "overall_state":outcome["overall_state"],
                        "bank_sealed":False,"candidate_executed":False}),flush=True)
                    return
            time.sleep(10)


if __name__=="__main__":
    main()
