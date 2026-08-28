from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_IMPORT_PREFIXES = {
    "legal_chat_ui",
    "hybrid_retrieve",
    "vector_index",
    "chromadb",
}
FORBIDDEN_RUNTIME_SUFFIXES = {
    ".sqlite",
    ".sqlite3",
    ".db",
    ".chroma",
}
OLD_PROJECT_ROOT = str(Path.home() / "Desktop" / "mlx-lm-main")


def imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


def check() -> list[str]:
    failures: list[str] = []
    for path in ROOT.rglob("*"):
        if any(
            part
            in {
                ".git",
                ".venv",
                ".wrangler",
                ".next",
                ".vinext",
                "dist",
                "node_modules",
                "models",
                "data",
                "recovery",
            }
            for part in path.parts
        ):
            continue
        if path.is_file() and path.suffix.lower() in FORBIDDEN_RUNTIME_SUFFIXES:
            failures.append(
                f"Runtime database/index committed to clean project: {path.relative_to(ROOT)}"
            )
        if path.suffix == ".py":
            for module in imported_modules(path):
                if module.split(".")[0] in FORBIDDEN_IMPORT_PREFIXES:
                    failures.append(
                        f"Forbidden legacy import {module!r} in {path.relative_to(ROOT)}"
                    )
        if path.is_file() and path.suffix in {
            ".py",
            ".ts",
            ".tsx",
            ".js",
            ".json",
            ".yaml",
            ".yml",
        }:
            text = path.read_text(encoding="utf-8", errors="ignore")
            if OLD_PROJECT_ROOT in text:
                for line_number, line in enumerate(text.splitlines(), start=1):
                    if OLD_PROJECT_ROOT in line:
                        failures.append(
                            f"Forbidden old-project runtime reference in {path.relative_to(ROOT)}:{line_number}"
                        )
    return failures


if __name__ == "__main__":
    problems = check()
    if problems:
        print("\n".join(problems), file=sys.stderr)
        raise SystemExit(1)
    print("Clean-room check passed: no legacy imports, databases, indexes or runtime references.")
