from pathlib import Path

import pytest
from app.core.venv_safety import ensure_correct_interpreter


def test_passes_when_prefix_matches_repo_venv(tmp_path):
    venv_dir = tmp_path / ".venv"
    venv_dir.mkdir()

    ensure_correct_interpreter(sys_prefix=str(venv_dir), repo_root=tmp_path)


def test_raises_when_prefix_is_system_python(tmp_path):
    system_prefix = tmp_path / "usr"
    system_prefix.mkdir()

    with pytest.raises(RuntimeError, match="Refusing to run"):
        ensure_correct_interpreter(sys_prefix=str(system_prefix), repo_root=tmp_path)


def test_raises_when_prefix_is_a_different_venv(tmp_path):
    other_repo = tmp_path / "some-other-project"
    other_venv = other_repo / ".venv"
    other_venv.mkdir(parents=True)

    with pytest.raises(RuntimeError, match="Refusing to run"):
        ensure_correct_interpreter(sys_prefix=str(other_venv), repo_root=tmp_path)


def test_error_message_names_the_correct_activation_command(tmp_path):
    system_prefix = tmp_path / "usr"
    system_prefix.mkdir()

    with pytest.raises(RuntimeError) as exc_info:
        ensure_correct_interpreter(sys_prefix=str(system_prefix), repo_root=tmp_path)

    expected_venv = tmp_path / ".venv"
    assert f"source {expected_venv}/bin/activate" in str(exc_info.value)


def test_default_repo_root_resolves_above_backend_not_inside_it():
    """
    repo_root must resolve to the actual repo root (backend/../), not
    backend/ itself -- that was exactly this incident's mistake
    (CONTEXT.md, 2026-07-23): a venv was expected at backend/.venv, which
    never existed, instead of ../.venv.
    """
    from app.core import venv_safety

    computed_root = Path(venv_safety.__file__).resolve().parents[3]
    assert (computed_root / "backend" / "app" / "core" / "venv_safety.py").is_file()
    assert (computed_root / "CONTEXT.md").is_file()
