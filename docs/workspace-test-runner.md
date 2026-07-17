# Workspace test runner

`hermes_workspace_run_test` executes fixed argument vectors under WSL with `shell=False` during an approved workspace Operator Session.

## Supported commands

The existing bounded allowlist remains available for pytest, npm test/lint, Ruff, mypy, and read-only Git status/diff commands.

The runner also accepts direct repository-local test or validation scripts:

```text
python test_standalone.py
python3 scripts/validate_projection.py --case demo
node scripts/check.mjs
```

For direct scripts, Hermes requires all of the following:

- an explicit approved `workdir`;
- the script resolves inside that working directory;
- the script exists as a regular file;
- Python scripts use `.py`;
- Node scripts use `.js`, `.mjs`, or `.cjs`;
- no more than eight script arguments.

Interpreter code flags such as `python -c`, paths escaping the working directory, missing scripts, shell operators, pipes, redirects, command substitution, destructive Git operations, and network download commands remain blocked.

Every invocation is bounded by the configured timeout, returns captured stdout/stderr, and is written to the Operator audit log. This is controlled repository execution, not unrestricted shell access.
