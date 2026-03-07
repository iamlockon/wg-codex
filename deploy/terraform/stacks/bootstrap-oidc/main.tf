provider "google" {
  project = var.project_id
}

locals {
  repository_parts = split("/", var.github_repository)
  github_owner     = local.repository_parts[0]
  github_repo_name = local.repository_parts[1]
}

provider "github" {
  owner = local.github_owner
  token = var.github_token
}

data "google_service_account" "terraform" {
  account_id = var.terraform_service_account_id
}

removed {
  from = google_service_account.terraform

  lifecycle {
    destroy = false
  }
}

resource "google_project_iam_member" "terraform_sa_roles" {
  for_each = toset(var.terraform_service_account_roles)

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${data.google_service_account.terraform.email}"
}

resource "google_project_service" "iamcredentials" {
  count = var.enable_required_apis ? 1 : 0

  project            = var.project_id
  service            = "iamcredentials.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "sts" {
  count = var.enable_required_apis ? 1 : 0

  project            = var.project_id
  service            = "sts.googleapis.com"
  disable_on_destroy = false
}

resource "google_iam_workload_identity_pool" "github" {
  workload_identity_pool_id = var.workload_identity_pool_id
  display_name              = "GitHub Actions"
  description               = "OIDC trust for ${var.github_repository}"

  depends_on = [
    google_project_service.iamcredentials,
    google_project_service.sts,
  ]
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = var.workload_identity_provider_id
  display_name                       = "GitHub OIDC"

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.actor"      = "assertion.actor"
    "attribute.ref"        = "assertion.ref"
    "attribute.repository" = "assertion.repository"
  }

  attribute_condition = "assertion.repository == \"${var.github_repository}\""

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account_iam_member" "github_oidc_impersonation" {
  service_account_id = data.google_service_account.terraform.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository/${var.github_repository}"
}

resource "github_actions_secret" "workload_identity_provider" {
  repository      = local.github_repo_name
  secret_name     = var.github_secret_name_workload_identity_provider
  plaintext_value = google_iam_workload_identity_pool_provider.github.name
}

resource "github_actions_secret" "terraform_sa" {
  repository      = local.github_repo_name
  secret_name     = var.github_secret_name_terraform_sa
  plaintext_value = data.google_service_account.terraform.email
}
