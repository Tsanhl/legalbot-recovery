#!/usr/bin/env python3
"""Run the dedicated Codex bridge inside a file-restricted macOS sandbox.

Only the ephemeral prompt directory, dedicated CODEX_HOME and executables/
system libraries are readable. The LegalBot repository and protected bank are
not mounted into this process. This wrapper is a development transport gate;
it does not itself qualify a model answer or establish legal correctness.
"""

from __future__ import annotations

import os
import pwd
import shutil
import subprocess
import sys
from pathlib import Path


def _scheme_path(path: Path) -> str:
    value = str(path.resolve())
    if any(character in value for character in ('"', "\n", "\r", "\\")):
        raise RuntimeError("sandbox path contains unsupported characters")
    return f'"{value}"'


def main() -> int:
    if len(sys.argv) < 3 or sys.argv[1:3] != ["codex", "exec"]:
        raise RuntimeError("the isolation wrapper accepts codex exec only")
    sandbox = Path("/usr/bin/sandbox-exec")
    codex_name = shutil.which("codex")
    node_name = shutil.which("node")
    if not sandbox.is_file() or not codex_name or not node_name:
        raise RuntimeError("macOS sandbox, Codex and Node are required")
    work = Path.cwd().resolve()
    home = Path(os.environ.get("CODEX_HOME", "")).resolve()
    if (
        not work.name.startswith("legalbot-codex-")
        or home.name != "codex-bridge-home"
        or not work.is_dir() or not home.is_dir()
        or home.parent != work
    ):
        raise RuntimeError("Codex bridge workspace identity is invalid")
    codex = Path(codex_name).resolve()
    node = Path(node_name).resolve()
    # Node's package installation and native runtime are the only user-home
    # paths the CLI needs. Neither covers the LegalBot workspace or .private.
    package = codex.parent.parent
    if (
        codex.parent.name != "bin"
        or package.name != "codex"
        or package.parent.name != "@openai"
        or package == work or package in work.parents or work in package.parents
        or package == home or package in home.parents or home in package.parents
    ):
        raise RuntimeError("Codex executable is not inside the expected isolated package")
    read_roots = [
        Path("/System"), Path("/usr"), Path("/bin"), Path("/sbin"),
        Path("/Library"), Path("/private/etc"), Path("/dev"),
        package, node.parent, work,
    ]
    auth_source: Path | None = None
    if raw_auth := os.environ.get("LEGALBOT_CODEX_SIGNED_IN_AUTH"):
        expected = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".codex" / "auth.json"
        auth_source = Path(raw_auth)
        if (
            auth_source != expected or auth_source.is_symlink()
            or not auth_source.is_file() or auth_source.stat().st_uid != os.getuid()
            or auth_source.stat().st_mode & 0o077
            or not (home / "auth.json").is_symlink()
            or (home / "auth.json").resolve() != auth_source
        ):
            raise RuntimeError("Codex signed-in credential link is invalid")
    policy = [
        "(version 1)",
        "(deny default)",
        "(allow process*)",
        "(allow sysctl-read)",
        "(allow mach-lookup)",
        "(allow network-outbound)",
        # dyld must inspect the root directory before resolving allowed
        # libraries; literal / grants no read access to its descendants.
        '(allow file-read* (literal "/"))',
        '(allow file-read* (literal "/etc"))',
        '(allow file-read* (literal "/var"))',
        '(allow file-read* (literal "/tmp"))',
    ]
    ancestors = {parent for path in read_roots for parent in path.resolve().parents}
    if auth_source is not None:
        ancestors.update(auth_source.parents)
    for path in sorted(ancestors, key=lambda value: len(str(value))):
        if path != Path("/") and path.is_dir():
            policy.append(f"(allow file-read* (literal {_scheme_path(path)}))")
    for path in read_roots:
        if path.exists():
            policy.append(f"(allow file-read* (subpath {_scheme_path(path)}))")
    if auth_source is not None:
        policy.append(f"(allow file-read* (literal {_scheme_path(auth_source)}))")
    policy.append(f"(allow file-write* (subpath {_scheme_path(work)}))")
    completed = subprocess.run(
        [str(sandbox), "-p", "\n".join(policy), str(Path(codex_name)), *sys.argv[2:]],
        check=False,
    )
    return completed.returncode


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(70) from None
