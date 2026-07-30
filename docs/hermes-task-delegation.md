# Hermes Task Delegation

The ChatGPT operator profile exposes a durable, bounded delegation surface for submitting work directly to Hermes without exposing the unrestricted `hermes_agent_run` tool.

## Tools

- `hermes_delegate_task` queues a task and returns a durable `dt_...` task ID.
- `hermes_delegated_task_status` reports lifecycle state and authority snapshot.
- `hermes_delegated_task_result` returns captured output after completion.
- `hermes_delegated_task_message` records durable guidance for review or a later continuation task.
- `hermes_delegated_task_continue` queues an explicit continuation from a resumable checkpoint.
- `hermes_delegated_task_cancel` requests cancellation of queued or running work.

## Lifecycle

Tasks are schema-versioned JSON records under `logs/delegated_tasks/`. They move through explicit states:

- non-terminal: `queued`, `starting`, `running`, `checkpointed`, `awaiting_continuation`, `resuming`, `cancel_requested`
- terminal: `completed`, `incomplete`, `failed`, `timed_out`, `cancelled`, `blocked`

Legal transitions are validated in the delegation layer. A process return code of zero is not sufficient for `completed`; the task must also produce substantive output and, for `apply`, changed-file evidence. Empty model output, fallback output, and apply tasks with no changed files are `incomplete`. Bounded-attempt timeout is `timed_out`. Authority withdrawal is `blocked`.

Each task carries:

- `logical_work_id` for the stable work item;
- `task_id` for the persisted delegated task record;
- `attempt_id` for one bounded dispatch attempt;
- `interaction_id` for one provider/Hermes child interaction;
- `continuation_sequence` and optional `continuation_id` for explicit resumes.

Repeated dispatch of the same logical work returns the existing task, reports already-completed work, or reports a resumable checkpoint instead of silently executing a duplicate.

Checkpoints are written atomically under `logs/delegated_tasks/checkpoints/<logical_work_id>/`. They contain non-secret state needed to continue safely: IDs, lifecycle state, profile, adapter, workdir, git context, changed files, failure category, retry count, timestamps, safe output excerpts, and resume instructions. They do not store raw prompts or credentials.

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

Antigravity is currently represented by the governed Hermes profile worker `antigravity-operator`, not by a separate external Antigravity API adapter. The adapter boundary is therefore: Hermes operator policy validates authority, materialises the selected profile into a task-local `HERMES_HOME`, launches a bounded Hermes child process, captures output and changed-file evidence, classifies the result, checkpoints state, and mirrors lifecycle events into Mission Control when the configured Kanban database is available.

## Operational sequence

1. Request and approve an appropriate Operator Session.
2. Submit a task with `hermes_delegate_task`.
3. Poll `hermes_delegated_task_status` using the returned task ID.
4. Retrieve `hermes_delegated_task_result` after a terminal state.
5. For `incomplete`, `timed_out`, `failed`, or `blocked` states, inspect `checkpoint_ref`, reconcile current repository state, and use `hermes_delegated_task_continue` only when authority, scope, and evidence still permit continuation.
6. Run verification with `hermes_workspace_run_test` or `hermes_workspace_exec`.
7. Review the diff and commit through `hermes_workspace_git_commit`.

A message added to a currently running one-shot task is recorded durably but cannot be injected into the already-running Hermes process. Submit an explicit continuation task containing the recorded guidance when additional work is required.

## Mission Control

When `HERMES_GPT_DELEGATION_MISSION_CONTROL_DB` points at a Kanban database, or when the default `~/.hermes/kanban.db` exists outside test runs, delegation upserts one Mission Control task per `logical_work_id` and appends `task_events` for meaningful lifecycle transitions. Continuations update the same logical work item rather than creating duplicate Mission Control cards.
