# Workspace command execution

`hermes_workspace_exec` provides general developer-command execution during an approved workspace Operator Session without exposing an unrestricted host shell.

## API

```text
hermes_workspace_exec(
    argv: list[str],
    workdir: str,
    timeout: int = 300,
    dry_run: bool = true
)
```

The API is deliberately argv-first. It does not accept a command string, does not perform shell parsing, and never invokes `shell=True`.

## Authority model

Every call requires:

- an active, approved, non-expired Operator Session;
- workspace-level authority with the `tests:run` verb;
- a `workdir` under both an approved readable root and an approved writable root;
- direct apply mode and `dry_run=false` for execution.

The most specific approved writable root containing `workdir` becomes the mounted workspace root. Paths supplied in argv must remain inside that root. Existing symlinks are resolved before validation, absolute approved paths are translated to `/workspace/...`, and traversal components are rejected.

## Execution boundary

The host launches only the Docker CLI as a fixed argv vector through `subprocess.run(..., shell=False)`. The requested developer command is appended after the image name and is executed directly by the container runtime, not through a shell.

The container is created with:

- `--rm` and `--init`;
- a read-only container root filesystem;
- no network;
- all Linux capabilities dropped;
- `no-new-privileges`;
- a PID limit;
- the host user UID/GID;
- only the approved workspace mounted read-write at `/workspace`;
- an isolated tmpfs for temporary files and tool caches;
- no host environment or credential mounts.

Standard credential paths inside the workspace, including `.env`, `.npmrc`, credential directories, and explicit session-denied paths, are masked inside the container.

This container boundary is load-bearing. `cwd` validation and `shell=False` alone do not prevent a Python script, npm lifecycle script, Makefile, pytest plugin, compiler, or build tool from reading or writing elsewhere on the host.

## Command validation

The executor does not maintain a growing allowlist of developer tools. Normal argv commands are accepted subject to a compact deny policy.

Direct top-level execution is rejected for:

- shells: `bash`, `sh`, `cmd`, PowerShell variants, and similar shells;
- destructive utilities: `rm`, `del`, `format`, `dd`, `wipefs`, `mkfs*`, and related tools;
- download or remote-access utilities: `curl`, `wget`, SSH clients, netcat variants, and similar tools;
- nested container engines and privilege-elevation utilities;
- inline interpreter forms such as `python -c`, `node --eval`, and encoded PowerShell forms;
- mutating or network-capable Git subcommands, because controlled commits already use `hermes_workspace_git_commit`;
- shell metacharacters, redirects, command substitution, control characters, and secret-bearing `name=value` arguments.

Commands such as `npm run`, `make`, and language test runners may internally invoke a shell inside the container. That shell cannot access host files outside the mounted workspace and cannot use the network.

## Examples

```text
["git", "status"]
["git", "diff"]
["git", "log", "-5"]
["git", "grep", "Household"]
["python", "test_household_read_repository.py"]
["python", "-m", "pytest", "-q"]
["pytest", "-q"]
["uv", "run", "pytest"]
["npm", "run", "build"]
["npm", "run", "test"]
["ruff", "check", "."]
["mypy", "."]
["cargo", "test"]
["go", "test", "./..."]
["dotnet", "test"]
["cmake", "--build", "build"]
["make", "test"]
```

## Docker image

The default image is:

```text
nikolaik/python-nodejs:python3.11-nodejs20
```

Override it for a deployment with:

```text
HERMES_GPT_WORKSPACE_EXEC_IMAGE=<pre-provisioned-image>
```

The executor uses `--pull=never`. It will not silently download an image. The selected image must already exist locally and must contain the required toolchain. A polyglot repository may need a purpose-built, reviewed image.

## Network and package installation

The container is air-gapped. `npm install`, `uv sync`, and similar commands are valid argv, but they can only use vendored dependencies or caches already present in the workspace/image. Networked dependency installation requires a separate, explicitly approved egress design; this tool does not weaken the Operator Session's egress posture.

## Audit model

Each attempted execution records:

- redacted command argv;
- resolved working directory;
- timeout;
- exit code;
- execution duration;
- redacted stdout and stderr;
- backend, image, network mode, and masked-path count;
- Operator Session ID and policy snapshot hash when a session is active;
- audit timestamp and trace ID.

Command output is bounded by the shared subprocess output limit before it is returned or audited.

## Limitations

- Non-interactive execution only; no PTY or stdin streaming.
- Maximum timeout is 600 seconds.
- The workspace may be modified by the invoked command; use Git status/diff after execution.
- Tool availability depends on the pre-provisioned image.
- Ordinary repositories with a `.git` directory inside the approved workspace support read-only Git commands. Linked worktrees whose `.git` file points to metadata outside the approved root are refused; use `hermes_git_status` and `hermes_git_diff` for those repositories.
- Docker daemon availability is required.
- Container isolation protects the host outside the mounted workspace; it does not make untrusted workspace code safe to publish or merge.

`hermes_workspace_run_test` remains available as a conservative compatibility runner. New repository investigation and repair workflows should use `hermes_workspace_exec` when the required Docker image is provisioned.
