variable "project_id" {
  description = "GCP project id where Workload Identity is created and the Terraform service account already exists."
  type        = string
  default     = "wg-stg"
}

variable "github_repository" {
  description = "GitHub repository in owner/name format."
  type        = string

  validation {
    condition     = length(split("/", var.github_repository)) == 2
    error_message = "github_repository must be in owner/name format."
  }
}

variable "github_token" {
  description = "Optional GitHub token override. If null, provider reads from GITHUB_TOKEN env var."
  type        = string
  sensitive   = true
  default     = null
}

variable "workload_identity_pool_id" {
  description = "Workload Identity Pool id."
  type        = string
  default     = "github-actions"
}

variable "workload_identity_provider_id" {
  description = "Workload Identity Provider id inside the pool."
  type        = string
  default     = "github-oidc"
}

variable "terraform_service_account_id" {
  description = "Existing service account id used by GitHub Actions Terraform workflows."
  type        = string
  default     = "gha-terraform"
}

variable "terraform_service_account_roles" {
  description = "Project roles granted to the Terraform service account."
  type        = list(string)
  default = [
    "roles/compute.admin",
    "roles/container.admin",
    "roles/cloudsql.admin",
    "roles/secretmanager.admin",
    "roles/storage.admin",
    "roles/serviceusage.serviceUsageAdmin",
    "roles/iam.serviceAccountAdmin",
    "roles/iam.serviceAccountUser",
    "roles/resourcemanager.projectIamAdmin",
  ]
}

variable "enable_required_apis" {
  description = "Enable APIs required for Workload Identity Federation bootstrap."
  type        = bool
  default     = true
}

variable "github_secret_name_workload_identity_provider" {
  description = "GitHub Actions secret name for the workload identity provider resource name."
  type        = string
  default     = "GCP_WORKLOAD_IDENTITY_PROVIDER"
}

variable "github_secret_name_terraform_sa" {
  description = "GitHub Actions secret name for the Terraform service account email."
  type        = string
  default     = "GCP_TERRAFORM_SA"
}
