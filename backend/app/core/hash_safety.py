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

    Found 2026-07-24: reusing `sys.argv` verbatim breaks entrypoints
    invoked as `python -m pkg.module`. In that mode Python sets
    `sys.argv[0]` to the *resolved file path*, not `-m pkg.module`, so
    re-exec'ing `[sys.executable] + sys.argv` silently drops module
    context -- the child starts as a bare script with the script's own
    directory on `sys.path[0]` instead of the caller's cwd, and any
    intra-package absolute import in that script then fails with
    `ModuleNotFoundError`. This went unnoticed because every caller in
    `analysis/` is invoked as a plain script, where argv[0] was already a
    bare path and re-exec is a no-op change of invocation style. Detect
    `-m` mode via `sys.modules["__main__"].__spec__` (set only when the
    main module was located via `-m`) and reconstruct the module
    invocation explicitly instead of trusting argv[0].
    """
    if os.environ.get("PYTHONHASHSEED") != "0":
        env = os.environ.copy()
        env["PYTHONHASHSEED"] = "0"
        main_spec = sys.modules["__main__"].__spec__
        if main_spec is not None:
            argv = [sys.executable, "-m", main_spec.name, *sys.argv[1:]]
        else:
            argv = [sys.executable, *sys.argv]
        os.execve(sys.executable, argv, env)
