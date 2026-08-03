"""Run pytest without inheriting a live Hermes Operator Session pointer.

The authenticated operator service intentionally exports the active session root
and id.  Unit tests that exercise environment-only policy defaults must not see
that production pointer.  This helper removes only those two variables in the
child process and otherwise delegates directly to ``python -m pytest`` with
``shell=False``.
"""

from __future__ import annotations

import os
import subprocess
import sys


SESSION_ENV_VARS = (
    "HERMES_GPT_OPERATOR_SESSION_ROOT",
    "HERMES_GPT_OPERATOR_SESSION_ID",
)


def main() -> int:
    env = dict(os.environ)
    for name in SESSION_ENV_VARS:
        env.pop(name, None)
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", *sys.argv[1:]],
        env=env,
        cwd=os.getcwd(),
        shell=False,
    )
    return int(completed.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
