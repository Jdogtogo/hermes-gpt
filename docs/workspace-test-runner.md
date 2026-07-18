# Workspace test runner

`hermes_workspace_run_test` is the conservative compatibility runner retained for existing workflows. It parses a command string into a fixed argv vector and executes with `shell=False` during an approved workspace Operator Session.

## Supported commands

The bounded allowlist covers pytest, npm test/lint, Ruff, mypy, read-only Git status/diff, and direct repository-local Python or Node validation scripts.

```text
python test_standalone.py
python3 scripts/validate_projection.py --case demo
node scripts/check.mjs
```

For direct scripts, Hermes requires:

- an explicit approved `workdir`;
- a script path that resolves inside that working directory;
- an existing regular file;
- `.py` for Python or `.js`, `.mjs`, or `.cjs` for Node;
- no more than eight script arguments.

Interpreter code flags such as `python -c`, paths escaping the working directory, missing scripts, shell operators, pipes, redirects, command substitution, destructive Git operations, and download commands remain blocked.

Every invocation is timeout-bounded, returns captured stdout/stderr, and is written to the Operator audit log.

## General developer commands

Use `hermes_workspace_exec` for broader repository investigation, builds, tests, linters, and language toolchains. It accepts structured argv rather than a command string and runs inside a Docker-confined approved workspace. See `workspace-command-execution.md`.
