# Bootstrap Infra Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rename the bootstrap workflow and Terraform stack to `bootstrap-infra` and make the stack create the required entry node catalog GCS bucket.

**Architecture:** The existing bootstrap Terraform stack is renamed in place and extended with one required storage bucket resource. The GitHub workflow is renamed to match, continues to use the saved-plan plan/apply flow, enforces the new `bootstrap-infra` backend prefix convention, and treats node catalog bucket adoption as a required import.

**Tech Stack:** GitHub Actions, Terraform, Google provider, GitHub provider, Bash docs/tooling

---

### Task 1: Rename bootstrap workflow and stack references

**Files:**
- Modify: `.github/workflows/bootstrap-infra.yml`
- Modify: `deploy/terraform/README.md`
- Modify: `deploy/terraform/stacks/bootstrap-infra/README.md`
- Modify: `docs/deployment-checklist.md`
- Modify: `AGENTS.md`

- [ ] **Step 1: Write the failing test**

Use search to confirm legacy names still exist:

```bash
rg -n "bootstrap-gcp-oidc|bootstrap-oidc" .github deploy docs AGENTS.md
```

- [ ] **Step 2: Run test to verify it fails**

Run: `rg -n "bootstrap-gcp-oidc|bootstrap-oidc" .github deploy docs AGENTS.md`
Expected: matches in workflow/docs using old names

- [ ] **Step 3: Write minimal implementation**

Rename the workflow file and Terraform stack directory, then update references to the new names while preserving behavior.

- [ ] **Step 4: Run test to verify it passes**

Run: `rg -n "bootstrap-gcp-oidc|bootstrap-oidc" .github deploy docs AGENTS.md`
Expected: no remaining legacy-name matches outside intentional migration notes

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/bootstrap-infra.yml deploy/terraform/README.md deploy/terraform/stacks/bootstrap-infra/README.md docs/deployment-checklist.md AGENTS.md
git commit -m "refactor: rename bootstrap infra workflow and stack"
```

### Task 2: Add required node catalog bucket provisioning

**Files:**
- Modify: `deploy/terraform/stacks/bootstrap-infra/main.tf`
- Modify: `deploy/terraform/stacks/bootstrap-infra/variables.tf`
- Modify: `deploy/terraform/stacks/bootstrap-infra/terraform.tfvars.example`
- Modify: `.github/workflows/bootstrap-infra.yml`

- [ ] **Step 1: Write the failing test**

Check that the stack does not yet model the node catalog bucket:

```bash
rg -n "google_storage_bucket|node_catalog" deploy/terraform/stacks/bootstrap-infra .github/workflows/bootstrap-infra.yml
```

- [ ] **Step 2: Run test to verify it fails**

Run: `rg -n "google_storage_bucket|node_catalog" deploy/terraform/stacks/bootstrap-infra .github/workflows/bootstrap-infra.yml`
Expected: missing bucket resource and missing workflow inputs/imports for it

- [ ] **Step 3: Write minimal implementation**

Add required Terraform variables and a `google_storage_bucket` resource for the node catalog bucket. Wire required bucket input and optional bucket settings into the workflow.

- [ ] **Step 4: Run test to verify it passes**

Run: `terraform -chdir=deploy/terraform/stacks/bootstrap-infra init -backend=false && terraform -chdir=deploy/terraform/stacks/bootstrap-infra validate`
Expected: init and validate succeed

- [ ] **Step 5: Commit**

```bash
git add deploy/terraform/stacks/bootstrap-infra/main.tf deploy/terraform/stacks/bootstrap-infra/variables.tf deploy/terraform/stacks/bootstrap-infra/terraform.tfvars.example .github/workflows/bootstrap-infra.yml
git commit -m "feat: provision node catalog bucket in bootstrap infra"
```

### Task 3: Preserve adoption and operator guidance

**Files:**
- Modify: `.github/workflows/bootstrap-infra.yml`
- Modify: `deploy/terraform/README.md`
- Modify: `deploy/terraform/stacks/bootstrap-infra/README.md`
- Modify: `docs/deployment-checklist.md`

- [ ] **Step 1: Write the failing test**

Check adoption/docs for missing bucket and migration coverage:

```bash
rg -n "adopt_existing|tf_state_prefix|node catalog bucket|bootstrap-infra" .github/workflows/bootstrap-infra.yml deploy/terraform/README.md deploy/terraform/stacks/bootstrap-infra/README.md docs/deployment-checklist.md
```

- [ ] **Step 2: Run test to verify it fails**

Run: `rg -n "node catalog bucket|bootstrap-infra" .github/workflows/bootstrap-infra.yml deploy/terraform/README.md deploy/terraform/stacks/bootstrap-infra/README.md docs/deployment-checklist.md`
Expected: missing or incomplete coverage before updates

- [ ] **Step 3: Write minimal implementation**

Import the bucket in adoption mode as a required resource, fail plan if it still shows `create`, update artifact/input text to the new stack name, and document state-prefix migration plus bucket ownership.

- [ ] **Step 4: Run test to verify it passes**

Run: `python - <<'PY'\nimport sys, yaml\nfor path in ['.github/workflows/bootstrap-infra.yml']:\n    with open(path) as f:\n        yaml.safe_load(f)\nprint('ok')\nPY`
Expected: `ok`

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/bootstrap-infra.yml deploy/terraform/README.md deploy/terraform/stacks/bootstrap-infra/README.md docs/deployment-checklist.md
git commit -m "docs: update bootstrap infra adoption guidance"
```

### Task 4: Final verification

**Files:**
- Modify: none

- [ ] **Step 1: Run formatting**

Run: `terraform -chdir=deploy/terraform/stacks/bootstrap-infra fmt`

- [ ] **Step 2: Run stack validation**

Run: `terraform -chdir=deploy/terraform/stacks/bootstrap-infra init -backend=false`
Expected: provider initialization succeeds

- [ ] **Step 3: Run Terraform validate**

Run: `terraform -chdir=deploy/terraform/stacks/bootstrap-infra validate`
Expected: `Success! The configuration is valid.`

- [ ] **Step 4: Run workflow validation**

Run: `python - <<'PY'\nimport yaml\nwith open('.github/workflows/bootstrap-infra.yml') as f:\n    yaml.safe_load(f)\nprint('ok')\nPY`
Expected: `ok`

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "chore: verify bootstrap infra rename and bucket provisioning"
```
