"""Live acceptance test for Task-Bound Authority v2 (TASK_AUTHORITY).

Representative low-risk maintenance task, executed against the real module
with a real on-disk task-authority store in a scratch root.
"""
import json
import subprocess
import tempfile
from pathlib import Path

import operator_task_authority as tba

scratch = Path(tempfile.mkdtemp(prefix="tba-live-"))
root = scratch / "opsroot"
wt = scratch / "worktree"
(wt / "ui").mkdir(parents=True)
target = wt / "ui" / "Board.tsx"
target.write_text("export const Board = () => null;\n")
subprocess.run(["git", "init", "-q"], cwd=wt, check=True)
subprocess.run(["git", "add", "-A"], cwd=wt, check=True)
subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t",
                "commit", "-qm", "seed"], cwd=wt, check=True)

# An UNRELATED dirty file that must never leak into the commit.
dirty = wt / "unrelated_dirty.txt"
dirty.write_text("do not commit me\n")

def show(label, data):
    print(f"\n--- {label} ---")
    print(json.dumps(data, indent=2, sort_keys=True))

# 1. Stable logical task ID
task_id = tba.make_task_id("kanban-board-label-fix", worktree=str(wt))
print("1. LOGICAL TASK ID:", task_id)
assert task_id == tba.make_task_id("kanban-board-label-fix", worktree=str(wt))
print("   stable across repeated derivation: PASS")

# 2. Narrow envelope + resolver explains which authority covers it
env = tba.derive_envelope(
    task_class="hermes_agent_kanban_ui",
    writable_files=(str(target),),
    needs_test=True,
    needs_commit=True,
)
first = tba.resolve(task_id=task_id, envelope=env, policy_class="contained", root=root)
show("2. FIRST RESOLUTION (expect one approval request)", first.to_dict())
assert first.approval_required is True
req_id = first.request_id

# Re-sending the SAME ask must NOT create a second request.
again = tba.resolve(task_id=task_id, envelope=env, policy_class="contained", root=root)
print("\n   re-sent identical request ->", again.request_id,
      "| duplicate created:", again.request_id != req_id)
assert again.request_id == req_id
print("   de-duplication: PASS (no supersede, no new request)")

# 3. Single bounded human approval for the whole work package
authority = tba.approve_request(req_id, approved_by="justin", root=root)
print("\n3. APPROVED work package:", authority.task_id, "state:", authority.state)

# 4. read/edit/test/commit with NO further approval
covered = tba.resolve(task_id=task_id, envelope=env, policy_class="contained", root=root)
show("4. POST-APPROVAL RESOLUTION", covered.to_dict())
assert covered.approval_required is False
assert covered.authority_source == "task_bound"

target.write_text("export const Board = () => <div>Stabilization</div>;\n")
print("   edit applied to", target.name)

# Isolated commit: only declared writable roots are staged.
subprocess.run(["git", "add", str(target)], cwd=wt, check=True)
out = subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t",
                      "commit", "-qm", "fix board label"],
                     cwd=wt, capture_output=True, text=True)
print("   commit exit:", out.returncode)
committed = subprocess.run(["git", "show", "--name-only", "--format=", "HEAD"],
                           cwd=wt, capture_output=True, text=True).stdout.split()
print("   files in commit:", committed)
assert "unrelated_dirty.txt" not in committed
print("   dirty unrelated file did NOT leak: PASS")

# 5. Second action in the SAME task -> no new approval
second_env = tba.derive_envelope(
    task_class="hermes_agent_kanban_ui",
    writable_files=(str(target),),
    needs_test=True,
)
second = tba.resolve(task_id=task_id, envelope=second_env,
                     policy_class="contained", root=root)
print("\n5. SECOND ACTION approval_required:", second.approval_required,
      "| source:", second.authority_source)
assert second.approval_required is False

# 6. Survives the old 30-minute expiry
later = authority.created_at + 45 * 60
late = tba.resolve(task_id=task_id, envelope=env, policy_class="contained",
                   now=later, root=root)
print("\n6. AT +45min approval_required:", late.approval_required,
      "| source:", late.authority_source)
assert late.approval_required is False

# 7. Material actions are blocked and demand human approval
for label, kwargs in (
    ("paid-route mutation", {"paid_routing": True}),
    ("secret access", {"paths": ("~/.hermes/auth/token.json",)}),
):
    boundary = tba.material_boundary(**kwargs)
    blocked = tba.resolve(task_id=task_id, envelope=env, policy_class="contained",
                          boundary=boundary, root=root)
    print(f"\n7. BLOCKED [{label}] boundary={boundary} "
          f"approval_required={blocked.approval_required} state={blocked.state}")
    assert blocked.approval_required is True and blocked.state == "blocked"

# 8. Task completion ends the authority
tba.complete_task(task_id, root=root)
final = tba.task_status(task_id, root=root)
show("8. TASK COMPLETE", final)
assert final["task_state"] == "completed" and final["valid"] is False

post = tba.resolve(task_id=task_id, envelope=env, policy_class="contained", root=root)
print("\n   post-completion approval_required:", post.approval_required)
assert post.approval_required is True

print("\n--- AUDIT TRAIL ---")
for line in (root / tba.TASK_AUDIT_NAME).read_text().strip().splitlines():
    rec = json.loads(line)
    print(" ", rec["event"], "|", rec.get("task_id", ""), rec.get("boundary", ""))

print("\nLIVE ACCEPTANCE: ALL CHECKS PASSED")
print("scratch:", scratch)
