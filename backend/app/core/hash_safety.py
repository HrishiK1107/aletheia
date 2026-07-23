import os
import sys


def ensure_deterministic_hashing() -> None:
    """
    Re-exec the current process with PYTHONHASHSEED pinned, if it isn't
    already.

    Python randomizes string hashing per process by default, which leaks
    into `set` iteration order. Found 2026-07-23: re-running the
    evaluation harness twice against an identical tree produced different
    ARI/precision/recall for the group_by_resolved_ip baseline, because
    app/evaluation/baselines.py's group_by_feature_prefix() builds its
    returned cluster list by iterating a `set` of per-indicator features
    -- so the *order* of that list varied run to run whenever an
    indicator had more than one feature under the same prefix (e.g.
    multiple resolved IPs). app/evaluation/metrics.py's
    build_predicted_labels() has since been fixed to no longer depend on
    that ordering (it canonicalizes cluster order itself before resolving
    multi-membership), but pinning the hash seed here is defence in
    depth against any other code path -- present or future -- that
    implicitly relies on set/dict iteration order.

    PYTHONHASHSEED can only be read at interpreter startup, not changed
    mid-process, so re-exec is the only way to enforce it here short of
    requiring every caller to remember `PYTHONHASHSEED=0 python ...`.
    Call this first thing inside `if __name__ == "__main__":`, before any
    real work starts -- it re-execs at most once, since the child process
    inherits PYTHONHASHSEED=0 and the check then passes.
    """
    if os.environ.get("PYTHONHASHSEED") != "0":
        env = os.environ.copy()
        env["PYTHONHASHSEED"] = "0"
        os.execve(sys.executable, [sys.executable] + sys.argv, env)
