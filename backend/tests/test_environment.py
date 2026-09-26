"""Guards the project-local import-path isolation (see tools/README.md)."""

import os
import sys


def _norm(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


def test_running_inside_project_venv():
    assert sys.prefix != sys.base_prefix, "tests must run with backend/.venv"


def test_global_python_root_not_on_import_path():
    base = _norm(sys.base_prefix)
    assert base not in {_norm(p) for p in sys.path}, (
        "Global Python root is on sys.path; run backend/setup.ps1 to install "
        "tools/askq_isolate_base_dir.pth into the venv"
    )


def test_standard_library_still_importable():
    import json
    import sqlite3

    assert json.dumps({"ok": True}) == '{"ok": true}'
    assert sqlite3.sqlite_version
