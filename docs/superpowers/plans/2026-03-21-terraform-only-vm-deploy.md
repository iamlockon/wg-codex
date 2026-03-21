# Terraform-Only VM Deploy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Consolidate `entry` and `core` VM deployment onto a Terraform-only workflow and retire the current SSH/scp deploy-script provisioners.

**Architecture:** Terraform manages both VM stacks and renders startup configuration that pulls artifacts from GCS and secrets from referenced runtime stores on the VM. GitHub Actions becomes Terraform-only for both `entry` and `core`, using plan/apply/destroy with saved plans and without a `provisioner` split.

**Tech Stack:** GitHub Actions, Terraform, GCE, GCS, Secret Manager, systemd, startup metadata/cloud-init, Rust build artifacts

---

### Task 1: Map script responsibilities into declarative deployment units

**Files:**
- Create: `docs/superpowers/notes/terraform-only-vm-deploy-responsibilities.md`

- [ ] **Step 1: Write the failing test**

Use search to identify the imperative responsibilities still trapped in scripts:

```bash
rg -n "compute scp|compute ssh|systemctl|/etc/default|user-data|metadata-from-file|journalctl|openssl|wg" scripts/deploy-entry-vm.sh scripts/deploy-core-vm.sh
```

- [ ] **Step 2: Run test to verify it fails**

Run: `rg -n "compute scp|compute ssh|systemctl|/etc/default|user-data|metadata-from-file|journalctl|openssl|wg" scripts/deploy-entry-vm.sh scripts/deploy-core-vm.sh`
Expected: multiple matches showing responsibilities not yet modeled declaratively

- [ ] **Step 3: Write minimal implementation**

Document the exact responsibilities that must move into startup templates, Terraform variables, workflow validation, or runtime fetch logic. Keep the note concrete enough to drive implementation without re-reading the whole scripts.

- [ ] **Step 4: Run test to verify it passes**

Run: `test -f docs/superpowers/notes/terraform-only-vm-deploy-responsibilities.md && echo ok`
Expected: `ok`

- [ ] **Step 5: Commit**

```bash
git add docs/superpowers/notes/terraform-only-vm-deploy-responsibilities.md
git commit -m "docs: map vm deploy script responsibilities"
```

### Task 2: Add Terraform-managed rollout support for core

**Files:**
- Create: `deploy/terraform/modules/core_vm/main.tf`
- Create: `deploy/terraform/modules/core_vm/variables.tf`
- Create: `deploy/terraform/modules/core_vm/outputs.tf`
- Create: `deploy/terraform/modules/core_vm/README.md`
- Create: `deploy/terraform/stacks/core-vm/main.tf`
- Create: `deploy/terraform/stacks/core-vm/variables.tf`
- Create: `deploy/terraform/stacks/core-vm/outputs.tf`
- Create: `deploy/terraform/stacks/core-vm/versions.tf`
- Create: `deploy/terraform/stacks/core-vm/terraform.tfvars.example`
- Create: `deploy/terraform/stacks/core-vm/README.md`

- [ ] **Step 1: Write the failing test**

Confirm the `core` Terraform stack does not yet exist:

```bash
test -d deploy/terraform/stacks/core-vm
```

- [ ] **Step 2: Run test to verify it fails**

Run: `test -d deploy/terraform/stacks/core-vm`
Expected: non-zero exit because the stack is missing

- [ ] **Step 3: Write minimal implementation**

Create a Terraform module/stack for `core` that mirrors the VM lifecycle concerns already modeled for `entry`, including address, instance, tags, and firewall inputs. Keep runtime rollout hooks ready for startup configuration inputs rather than SSH provisioning.

- [ ] **Step 4: Run test to verify it passes**

Run: `test -f deploy/terraform/stacks/core-vm/main.tf && test -f deploy/terraform/modules/core_vm/main.tf && echo ok`
Expected: `ok`

- [ ] **Step 5: Commit**

```bash
git add deploy/terraform/modules/core_vm deploy/terraform/stacks/core-vm
git commit -m "feat: add terraform core vm stack"
```

### Task 3: Introduce startup-based deployment templates

**Files:**
- Create: `deploy/startup/entry-startup.sh.tmpl`
- Create: `deploy/startup/core-startup.sh.tmpl`
- Create: `deploy/startup/lib/common.sh.tmpl`
- Modify: `deploy/terraform/modules/entry_vm/main.tf`
- Modify: `deploy/terraform/modules/entry_vm/variables.tf`
- Modify: `deploy/terraform/modules/core_vm/main.tf`
- Modify: `deploy/terraform/modules/core_vm/variables.tf`

- [ ] **Step 1: Write the failing test**

Check that no shared startup templates exist yet:

```bash
test -f deploy/startup/entry-startup.sh.tmpl
```

- [ ] **Step 2: Run test to verify it fails**

Run: `test -f deploy/startup/entry-startup.sh.tmpl`
Expected: non-zero exit because startup templates are missing

- [ ] **Step 3: Write minimal implementation**

Create startup templates that install prerequisites, fetch artifacts from GCS, resolve secret references, write env files/systemd units, and start the service. Wire them into Terraform instance metadata using `templatefile(...)`.

- [ ] **Step 4: Run test to verify it passes**

Run: `test -f deploy/startup/entry-startup.sh.tmpl && test -f deploy/startup/core-startup.sh.tmpl && echo ok`
Expected: `ok`

- [ ] **Step 5: Commit**

```bash
git add deploy/startup deploy/terraform/modules/entry_vm deploy/terraform/modules/core_vm
git commit -m "feat: add startup-based vm rollout templates"
```

### Task 4: Add artifact and secret reference inputs

**Files:**
- Modify: `deploy/terraform/modules/entry_vm/variables.tf`
- Modify: `deploy/terraform/modules/core_vm/variables.tf`
- Modify: `deploy/terraform/stacks/entry-vm/variables.tf`
- Modify: `deploy/terraform/stacks/core-vm/variables.tf`
- Modify: `deploy/env/entry.env.example`
- Modify: `deploy/env/core.env.example`
- Modify: `docs/architecture-plan.md`

- [ ] **Step 1: Write the failing test**

Check that current Terraform/env surfaces do not yet model artifact URIs and secret references:

```bash
rg -n "artifact|secret manager|secret_ref|gcs object|startup" deploy/terraform deploy/env docs/architecture-plan.md
```

- [ ] **Step 2: Run test to verify it fails**

Run: `rg -n "artifact|secret manager|secret_ref|gcs object|startup" deploy/terraform deploy/env docs/architecture-plan.md`
Expected: missing or incomplete coverage for rollout artifact/reference inputs

- [ ] **Step 3: Write minimal implementation**

Add Terraform variables for artifact object paths/checksums and secret reference names, then align env examples/docs around reference-based delivery rather than raw pushed files.

- [ ] **Step 4: Run test to verify it passes**

Run: `rg -n "artifact|secret manager|secret_ref|startup" deploy/terraform deploy/env docs/architecture-plan.md`
Expected: clear matches in the new rollout model

- [ ] **Step 5: Commit**

```bash
git add deploy/terraform deploy/env docs/architecture-plan.md
git commit -m "feat: add vm rollout artifact and secret references"
```

### Task 5: Convert workflows to Terraform-only

**Files:**
- Modify: `.github/workflows/entry-vm-cicd.yml`
- Modify: `.github/workflows/core-vm-cicd.yml`
- Modify: `deploy/terraform/README.md`
- Modify: `deploy/terraform/stacks/entry-vm/README.md`
- Modify: `deploy/terraform/stacks/core-vm/README.md`
- Modify: `docs/deployment-checklist.md`
- Modify: `docs/next-session.md`

- [ ] **Step 1: Write the failing test**

Confirm script-provisioner behavior still exists in workflows/docs:

```bash
rg -n "provisioner|deploy-entry-vm.sh|deploy-core-vm.sh|script provisioner" .github/workflows deploy/terraform docs
```

- [ ] **Step 2: Run test to verify it fails**

Run: `rg -n "provisioner|deploy-entry-vm.sh|deploy-core-vm.sh|script provisioner" .github/workflows deploy/terraform docs`
Expected: matches showing the old dual-path model still exists

- [ ] **Step 3: Write minimal implementation**

Remove the `provisioner` choice from `entry`, add Terraform `plan/apply/destroy` flow to `core`, add artifact upload/reference wiring where needed, and update docs so Terraform is the only supported VM deploy path.

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 - <<'PY'\nimport yaml\nfor path in ['.github/workflows/entry-vm-cicd.yml', '.github/workflows/core-vm-cicd.yml']:\n    with open(path, 'r', encoding='utf-8') as f:\n        yaml.safe_load(f)\nprint('ok')\nPY`
Expected: `ok`

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/entry-vm-cicd.yml .github/workflows/core-vm-cicd.yml deploy/terraform/README.md deploy/terraform/stacks/entry-vm/README.md deploy/terraform/stacks/core-vm/README.md docs/deployment-checklist.md docs/next-session.md
git commit -m "refactor: make vm deploy workflows terraform only"
```

### Task 6: Retire script provisioners after parity

**Files:**
- Delete: `scripts/deploy-entry-vm.sh`
- Delete: `scripts/deploy-core-vm.sh`
- Modify: `scripts/README.md`
- Modify: `docs/deployment-checklist.md`

- [ ] **Step 1: Write the failing test**

Confirm the legacy deploy scripts still exist:

```bash
test -f scripts/deploy-entry-vm.sh && test -f scripts/deploy-core-vm.sh
```

- [ ] **Step 2: Run test to verify it fails**

Run: `test -f scripts/deploy-entry-vm.sh && test -f scripts/deploy-core-vm.sh`
Expected: zero exit, proving the old scripts still exist

- [ ] **Step 3: Write minimal implementation**

Delete the old deploy scripts only after the Terraform-only path has verified parity. Update script/docs references accordingly.

- [ ] **Step 4: Run test to verify it passes**

Run: `! test -f scripts/deploy-entry-vm.sh && ! test -f scripts/deploy-core-vm.sh && echo ok`
Expected: `ok`

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "chore: retire vm deploy scripts"
```

### Task 7: Final verification

**Files:**
- Modify: none

- [ ] **Step 1: Run workflow YAML validation**

Run: `python3 - <<'PY'\nimport yaml\nfor path in ['.github/workflows/entry-vm-cicd.yml', '.github/workflows/core-vm-cicd.yml']:\n    with open(path, 'r', encoding='utf-8') as f:\n        yaml.safe_load(f)\nprint('ok')\nPY`
Expected: `ok`

- [ ] **Step 2: Run Terraform formatting**

Run: `terraform -chdir=deploy/terraform/stacks/entry-vm fmt`
Run: `terraform -chdir=deploy/terraform/stacks/core-vm fmt`

- [ ] **Step 3: Run Terraform validation**

Run: `terraform -chdir=deploy/terraform/stacks/entry-vm init -backend=false && terraform -chdir=deploy/terraform/stacks/entry-vm validate`
Run: `terraform -chdir=deploy/terraform/stacks/core-vm init -backend=false && terraform -chdir=deploy/terraform/stacks/core-vm validate`
Expected: both stacks validate successfully

- [ ] **Step 4: Run targeted repo validation**

Run: `git diff --check`
Expected: no whitespace or conflict-marker issues

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "chore: verify terraform-only vm deploy path"
```
