#!/usr/bin/env python3
"""Dependency-free release checks for common unsafe Python patterns."""

from __future__ import annotations

import ast
from pathlib import Path

errors = []
for path in list(Path("portal").glob("*.py")) + list(Path("tests").glob("*.py")):
    source = path.read_text()
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        errors.append(f"{path}:{exc.lineno}: {exc.msg}")
        continue
    for node in ast.walk(tree):
        if (
            isinstance(node, (ast.Call,))
            and isinstance(node.func, ast.Name)
            and node.func.id in {"eval", "exec"}
        ):
            errors.append(f"{path}:{node.lineno}: dynamic {node.func.id} is forbidden")
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"run", "Popen", "call", "check_call", "check_output"}
        ):
            for keyword in node.keywords:
                if (
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                ):
                    errors.append(
                        f"{path}:{node.lineno}: subprocess shell=True is forbidden"
                    )
if errors:
    print("\n".join(errors))
    raise SystemExit(1)
print("Python static safety checks: PASS")
