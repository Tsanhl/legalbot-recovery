"""Fresh Codex roles with a probed OS file fence and protected host receipts.

No bank defaults or automatic invocation. The host supplies an exact case root,
an already resolved model identity, and its out-of-band capability verifier.
The existing external seatbelt remains the execution boundary on this host.
"""
from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import time
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path

from scripts.ge_auto_case_protocol import (
    MAPPER_REFERENCE_SCHEMA,
    ProtocolError,
    RoleJob,
    checked,
    digest,
    materialize_mapper_spans,
)

ROOT = Path(__file__).resolve().parents[1]
CODEX = Path.home() / ".nvm/versions/node/v24.19.0/bin/codex"
ROLE_WAIT_POLICY = {"total_seconds": 1800, "idle_seconds": 600, "poll_seconds": 30,
                    "progress": "CHANGE_IN_HOST_LOGS_OR_MODEL_OUTPUT_FILE"}
ROLE_RESULT_NAME = "role-result.json"
CLI_LAST_MESSAGE_NAME = "last-message.json"


def transport_prompt(prompt: str, *, schema_name: str) -> str:
    """Require a durable role result independently of the CLI last-message hook.

    Two real mapper runs reached a valid local computation and then exited after
    their last tool call without emitting a final assistant message.  The Codex
    CLI consequently returned zero but did not create its ``-o`` file.  Make the
    fenced worker persist the response itself and keep the CLI capture as
    separate diagnostic evidence.  The host still validates and canonicalizes
    the persisted JSON; merely creating the file cannot make it acceptable.
    """
    return prompt.rstrip() + f"""

OUTPUT TRANSPORT REQUIREMENT. Before finishing, use local Python to validate the
complete response against {schema_name} and write exactly that JSON to
{ROLE_RESULT_NAME}. Create the file once; do not modify any supplied input file.
This persisted file is the response consumed by the host. Your final assistant
message may repeat the same JSON, but it does not replace {ROLE_RESULT_NAME}.
"""


class RoleWaitTimeout(RuntimeError):
    pass


def progress_signature(paths):
    values = []
    for path in paths:
        try:
            stat = path.stat()
            values.append((stat.st_size, stat.st_mtime_ns))
        except FileNotFoundError:
            values.append(None)
    return tuple(values)


def wait_for_role(child, prompt, observe, *, clock=time.monotonic,
                  total_seconds=1800, idle_seconds=600, poll_seconds=30):
    """Bound total runtime and observable silence; never resubmit stdin or retry.

    Silence does not prove that inference is dead. It consumes the declared idle
    budget and produces an explicit incomplete attempt, never accepted evidence.
    """
    started = last_progress = clock()
    signature = observe()
    stdin = prompt
    while True:
        now = clock()
        if now - started >= total_seconds:
            raise RoleWaitTimeout("ROLE_TOTAL_RUNTIME_TIMEOUT")
        if now - last_progress >= idle_seconds:
            raise RoleWaitTimeout("ROLE_NO_OBSERVABLE_PROGRESS_TIMEOUT")
        remaining = min(poll_seconds, total_seconds - (now - started), idle_seconds - (now - last_progress))
        try:
            child.communicate(stdin, timeout=remaining)
            return child.returncode
        except subprocess.TimeoutExpired:
            # communicate retains its partially sent input across timed waits.
            # Sending the prompt again would corrupt the worker's request.
            stdin = None
            current = observe()
            if current != signature:
                signature = current
                last_progress = clock()


def cli_identity():
    # This existing executable is a symlink into the installed npm package.
    # Resolve only that explicit installation, never a source/evidence path.
    resolved = CODEX.resolve(strict=True)
    expected = CODEX.parent.parent / "lib/node_modules/@openai/codex"
    if not resolved.is_relative_to(expected):
        raise RuntimeError("CODEX_INSTALLATION_CHANGED")
    version = subprocess.run([str(CODEX), "--version"], capture_output=True,
                             text=True, check=True).stdout.strip()
    resolved_package = subprocess.run([str(CODEX.parent/"node"), "-e",
        "const {createRequire}=require('module'); const r=createRequire(process.argv[1]); "
        "try { console.log(r.resolve('@openai/codex-darwin-arm64/package.json')); } "
        "catch { console.log(process.argv[2]); }", str(resolved), str(expected/"package.json")],
        capture_output=True, text=True, check=True).stdout.strip()
    native = Path(resolved_package).parent / "vendor/aarch64-apple-darwin/bin/codex"
    if not native.resolve(strict=True).is_relative_to(expected.parent.parent):
        raise RuntimeError("CODEX_NATIVE_INSTALLATION_CHANGED")
    return {"version": version, "launcher_sha256": digest(resolved.read_bytes()),
            "package_sha256": digest((expected/"package.json").read_bytes()),
            "native_sha256": digest(native.read_bytes())}


def safe(path, root):
    if not path.is_absolute() or not path.is_relative_to(root) or ".." in path.parts:
        raise ValueError("ROLE_PATH_SCOPE")
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("ROLE_SYMLINK_DENIED")
    if path.is_file() and path.stat().st_nlink != 1:
        raise ValueError("ROLE_HARDLINK_DENIED")


def file_hash(path):
    safe(path, ROOT)
    return digest(path.read_bytes())


def write_new(path, value):
    safe(path, ROOT)
    raw = value if isinstance(value, bytes) else json.dumps(value, sort_keys=True, ensure_ascii=False).encode()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open("xb") as out:
        out.write(raw)
        out.flush()
        os.fsync(out.fileno())
    path.chmod(0o600)
    return file_hash(path)


def profile(work):
    safe(work, ROOT)
    def quote(p):
        return json.dumps(str(p))
    rules = ["(version 1)", "(allow default)"]
    for action in ("file-read-data", "file-write*"):
        for base in (ROOT, ROOT.parent):
            rules.append(f"(deny {action} (require-all (subpath {quote(base)}) "
                         f"(require-not (subpath {quote(work)}))))")
        for base in (Path.home()/".legalbot-v111-private", Path.home()/".legalbot-v111-clean-visible",
                     Path.home()/".codex/sessions", Path.home()/".codex/archived_sessions"):
            rules.append(f"(deny {action} (subpath {quote(base)}))")
    # Protect every host-supplied file, not merely a fixed filename list.
    for path in sorted(work.rglob("*")):
        safe(path, work)
        if path.is_file():
            rules.append(f"(deny file-write* (literal {quote(path)}))")
    return "".join(rules)


def probe(work, policy):
    own = subprocess.run(["/usr/bin/sandbox-exec", "-p", policy, "/bin/cat", "input.json"],
                         cwd=work, capture_output=True, check=False)
    outside = subprocess.run(["/usr/bin/sandbox-exec", "-p", policy, "/bin/cat", str(ROOT/"README.md")],
                             cwd=work, capture_output=True, check=False)
    readonly = subprocess.run(["/usr/bin/sandbox-exec", "-p", policy, "/usr/bin/python3", "-c",
        "import os; os.open('input.json', os.O_WRONLY)"], cwd=work, capture_output=True, check=False)
    if own.returncode or own.stdout != (work/"input.json").read_bytes() or outside.returncode == 0 or readonly.returncode == 0:
        raise RuntimeError("ROLE_FENCE_PROBE_FAILED")
    return {"own_exact_input_readable": True, "outside_public_file_denied": True,
            "input_write_open_denied": True, "private_bank_probe": "NOT_ATTEMPTED",
            "profile_sha256": digest(policy.encode())}


class CodexRoleRuntime:
    def __init__(self, *, case_root, protected_root, model, provider, expected_cli, capability, verify):
        self.case_root, self.protected_root = Path(case_root), Path(protected_root)
        for path in (self.case_root, self.protected_root):
            safe(path, ROOT)
        if (self.case_root == self.protected_root or self.protected_root.is_relative_to(self.case_root)
                or self.case_root.is_relative_to(self.protected_root)):
            raise ValueError("ROLE_RECEIPTS_REQUIRE_DISJOINT_HOST_ROOT")
        if not re.fullmatch(r"gpt-[A-Za-z0-9_.-]+", model) or provider != "openai":
            raise ValueError("UNVERIFIED_ROLE_MODEL_IDENTITY")
        self.model, self.provider = model, provider
        if cli_identity() != expected_cli:
            raise ValueError("FROZEN_CLI_IDENTITY_CHANGED")
        self.expected_cli = dict(expected_cli)
        self.capability, self.verify = capability, verify
        self.receipts = {}

    def __call__(self, job: RoleJob):
        safe(job.root, self.case_root)
        binding = {"case_root": str(self.case_root), "job_root": str(job.root),
                   "role": job.role, "context_id": job.context_id, "input_sha256": job.input_sha256,
                   "model": self.model, "provider": self.provider, "browse": False}
        if job.allow_browsing or self.verify(self.capability, binding) is not True:
            raise PermissionError("ROLE_CAPABILITY_DENIED")
        if json.loads((job.root/"input.json").read_bytes()) != job.input or digest(job.input) != job.input_sha256:
            raise ValueError("ROLE_INPUT_BINDING_CHANGED")
        if json.loads((job.root/"schema.json").read_bytes()) != job.schema or (job.root/"prompt.txt").read_text() != job.prompt:
            raise ValueError("ROLE_PROMPT_SCHEMA_CHANGED")
        schema_name = "transport-schema.json" if job.role == "mapper" else "schema.json"
        model_output_name = ROLE_RESULT_NAME
        cli_output_name = CLI_LAST_MESSAGE_NAME
        if job.role == "mapper" and json.loads((job.root/schema_name).read_bytes()) != MAPPER_REFERENCE_SCHEMA:
            raise ValueError("MAPPER_TRANSPORT_SCHEMA_CHANGED")
        host = self.protected_root / job.context_id
        host.mkdir(mode=0o700, parents=True, exist_ok=False)
        inputs = {p.relative_to(job.root).as_posix(): file_hash(p) for p in sorted(job.root.rglob("*")) if p.is_file()}
        policy = profile(job.root)
        fence = probe(job.root, policy)
        cli = cli_identity()
        if cli != self.expected_cli:
            raise RuntimeError("FROZEN_CLI_IDENTITY_CHANGED")
        effective_prompt = transport_prompt(job.prompt, schema_name=schema_name)
        started = {**binding, "started": datetime.now(UTC).isoformat(), "fresh_context": True,
                   "cli_identity": cli, "fence": fence, "input_inventory": inputs,
                   "runtime_file_sha256": file_hash(Path(__file__).resolve()), "training": False,
                   "effective_prompt_sha256": digest(effective_prompt.encode()),
                   "role_result_name": model_output_name,
                   "cli_last_message_name": cli_output_name,
                   "wait_policy": dict(ROLE_WAIT_POLICY)}
        write_new(host/"START.json", started)
        command = ["/usr/bin/sandbox-exec", "-p", policy, str(CODEX), "-a", "never", "exec",
                   "--ephemeral", "--skip-git-repo-check", "--ignore-user-config",
                   "--dangerously-bypass-approvals-and-sandbox", "--model", self.model,
                   "-c", 'model_reasoning_effort="high"', "-c", 'web_search="disabled"',
                   "-C", str(job.root), "--output-schema", str(job.root/schema_name),
                   "-o", str(job.root/cli_output_name), "-"]
        # Never launch without the verified outer OS fence. The CLI flag avoids a
        # second incompatible nested seatbelt; it does not remove this boundary.
        with (host/"stdout.log").open("xb") as out, (host/"stderr.log").open("xb") as err:
            child = subprocess.Popen(command, cwd=job.root, stdin=subprocess.PIPE,
                                     stdout=out, stderr=err, start_new_session=True)
            stop_reason = None
            try:
                returncode = wait_for_role(child, effective_prompt.encode(),
                    lambda: progress_signature((host/"stdout.log", host/"stderr.log",
                                                 job.root/model_output_name, job.root/cli_output_name)),
                    **{k: ROLE_WAIT_POLICY[k] for k in ("total_seconds", "idle_seconds", "poll_seconds")})
            except RoleWaitTimeout as exc:
                stop_reason = str(exc)
                with suppress(ProcessLookupError):
                    os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
                returncode = 124
        result = {"returncode": returncode, "output_sha256": None, "error": None,
                  "model_output_sha256": None, "span_canonicalization_sha256": None,
                  "span_materialization_sha256": None,
                  "cli_last_message_sha256": (file_hash(job.root/cli_output_name)
                                               if (job.root/cli_output_name).is_file() else None),
                  "wait_stop_reason": stop_reason,
                  "stdout_sha256": file_hash(host/"stdout.log"), "stderr_sha256": file_hash(host/"stderr.log")}
        output = None
        try:
            if stop_reason is not None:
                raise RuntimeError(stop_reason)
            if returncode != 0:
                raise RuntimeError("ROLE_PROCESS_FAILED")
            if any(file_hash(job.root/name) != sha for name, sha in inputs.items()):
                raise RuntimeError("ROLE_INPUT_CHANGED")
            log = (host/"stderr.log").read_text(errors="replace")
            seen_model = re.search(r"(?m)^model:\s*(\S+)", log)
            seen_provider = re.search(r"(?m)^provider:\s*(\S+)", log)
            if not seen_model or not seen_provider or (seen_model[1], seen_provider[1]) != (self.model, self.provider):
                raise RuntimeError("ROLE_ACTUAL_MODEL_NOT_BOUND")
            output = json.loads((job.root/model_output_name).read_bytes())
            result["model_output_sha256"] = file_hash(job.root/model_output_name)
            if job.role == "mapper":
                output, receipt = materialize_mapper_spans(output, job.input["payload"])
                result["output_sha256"] = write_new(job.root/"output.json", output)
                result["span_materialization_sha256"] = write_new(job.root/"span-materialization.json", receipt)
            else:
                checked(output, job.schema)
                result["output_sha256"] = write_new(job.root/"output.json", output)
        except Exception as exc:
            # Protocol errors contain stable internal codes, not source text.
            # Retain those codes so a quotation failure is distinguishable from
            # schema/identity failures without rerunning an expensive model role.
            result["error"] = (type(exc).__name__ + ":" + str(exc)[:120]
                               if isinstance(exc, RuntimeError | ProtocolError) else type(exc).__name__)
        receipt = {**started, **result, "completed": datetime.now(UTC).isoformat(),
                   "start_sha256": file_hash(host/"START.json")}
        receipt_sha = write_new(host/"COMPLETE.json", receipt)
        self.receipts[receipt_sha] = host/"COMPLETE.json"
        if result["error"] is not None:
            raise RuntimeError("ROLE_EXECUTION_HELD")
        return {"context_id": job.context_id, "input_sha256": job.input_sha256,
                "receipt_sha256": receipt_sha, "output": output}
