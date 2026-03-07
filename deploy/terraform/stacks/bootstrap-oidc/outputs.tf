output "workload_identity_provider" {
  description = "Full resource name used by google-github-actions/auth workload_identity_provider input."
  value       = google_iam_workload_identity_pool_provider.github.name
}

output "terraform_service_account_email" {
  description = "Service account email used by google-github-actions/auth service_account input."
  value       = google_service_account.terraform.email
}
