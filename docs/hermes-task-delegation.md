# Hermes Task Delegation

The ChatGPT operator profile exposes a durable, bounded delegation surface for submitting work directly to Hermes without exposing the unrestricted `hermes_agent_run` tool.

## Tools

- `hermes_delegate_task` queues a task and returns a durable `dt_...` task ID.
- `hermes_delegated_task_status` reports lifecycle state and authority snapshot.
- `hermes_delegated_task_result` returns captured output after completion.
- `hermes_delegated_task_message` records durable guidance for review or a later continuation task.
- `hermes_delegated_task_cancel` requests cancellation of queued or running work.

## Lifecycle

Tasks move through `queued`, `running`, and one of `completed`, `failed`, or `cancelled`. State is persisted under `logs/delegated_tasks/` using atomic JSON replacement so status and results survive connector requests and can be inspected after completion.

## Security model

Delegation does not expose caller-supplied commands or Hermes' unrestricted terminal toolset.

- `plan` and `read_only` use `file_read_only`; optional web access is allowed only for these non-mutating modes.
- `apply` requires an active approved workspace Operator Session with direct mutation and `filesystem:edit` authority.
- `apply` receives only Hermes `file` and `todo` toolsets.
- Terminal, shell, service, credential, network, skills, and git capabilities are not passed to an apply task.
- The approved workspace is supplied through `HERMES_FILE_READ_SAFE_ROOT` and revalidated against the immutable Operator Session policy.
- Prompts are not returned by status or result tools. Audit records contain the task ID and prompt digest rather than prompt text.
- Output is redacted and bounded before persistence and return.

This separation is deliberate: delegated Hermes can inspect or edit workspace files, while tests, commits, service operations, and other privileged actions remain explicit Controller tools with their existing independent policy gates.

## Operational sequence

1. Request and approve an appropriate Operator Session.
2. Submit a task with `hermes_delegate_task`.
3. Poll `hermes_delegated_task_status` using the returned task ID.
4. Retrieve `hermes_delegated_task_result` after a terminal state.
5. Run verification with `hermes_workspace_run_test` or `hermes_workspace_exec`.
6. Review the diff and commit through `hermes_workspace_git_commit`.

A message added to a currently running one-shot task is recorded durably but cannot be injected into the already-running Hermes process. Submit a continuation task containing the recorded guidance when additional work is required.
