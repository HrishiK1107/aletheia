import sys
from pathlib import Path


def ensure_correct_interpreter(sys_prefix: str | None = None, repo_root: Path | None = None) -> None:
    """
    Raise loudly if the running interpreter is not the project's own
    virtualenv (the repo root's .venv, not backend/.venv -- there is no
    venv under backend/).

    Found 2026-07-23: an entire session ran `source .venv/bin/activate`
    from `backend/`, where no .venv exists. The failure was masked by
    `2>/dev/null`, so every command silently fell back to the system
    interpreter instead of erroring. System Python happened to already
    have nearly every project dependency installed -- except `geoip2`,
    which is what eventually surfaced the problem -- and a materially
    different `neo4j` driver version (a 5.2.dev0 prerelease vs. the
    project's pinned 6.1.0), so an entire session's worth of measurements
    ran on an unverified interpreter before anything visibly broke. This
    is the same class of defect as CONTEXT.md item 2.7 (a rate-limited
    external call silently indistinguishable from "no ASN found"): a
    failure mode masked well enough to look like a legitimate result.

    Call at interpreter start -- conftest.py, before any test runs, and at
    the top of every worker's `if __name__ == "__main__":` block -- so a
    missing or misconfigured venv fails immediately and loudly instead of
    silently degrading to whatever happens to be on the system path.
    """
    actual_prefix = Path(sys_prefix if sys_prefix is not None else sys.prefix).resolve()
    root = repo_root if repo_root is not None else Path(__file__).resolve().parents[3]
    expected_venv = (root / ".venv").resolve()

    if actual_prefix != expected_venv:
        raise RuntimeError(
            f"Refusing to run: interpreter is {sys.executable!r} "
            f"(resolved prefix {actual_prefix}), not the project virtualenv "
            f"at {expected_venv}. Activate it with "
            f"`source {expected_venv}/bin/activate` -- from the repo root, "
            "not from backend/, which has no .venv of its own. Running "
            "against a different interpreter can succeed silently if it "
            "happens to have similar packages installed, which masks real "
            "dependency and version gaps (2026-07-23: this happened for a "
            "full session; geoip2 was missing and neo4j was a different "
            "major version, both undetected until something finally "
            "threw)."
        )
