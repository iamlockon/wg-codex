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

variable "app_google_oidc_client_id" {
  description = "Required GOOGLE_OIDC_CLIENT_ID value to write for app login."
  type        = string

  validation {
    condition     = trimspace(var.app_google_oidc_client_id) != ""
    error_message = "app_google_oidc_client_id must not be empty."
  }
}

variable "app_google_oidc_client_secret" {
  description = "Required GOOGLE_OIDC_CLIENT_SECRET value to write for app login."
  type        = string
  sensitive   = true

  validation {
    condition     = trimspace(var.app_google_oidc_client_secret) != ""
    error_message = "app_google_oidc_client_secret must not be empty."
  }
}

variable "app_google_oidc_redirect_uri" {
  description = "Required GOOGLE_OIDC_REDIRECT_URI value to write for app login."
  type        = string

  validation {
    condition     = trimspace(var.app_google_oidc_redirect_uri) != ""
    error_message = "app_google_oidc_redirect_uri must not be empty."
  }
}

variable "github_secret_name_google_oidc_client_id" {
  description = "GitHub Actions secret name for app login GOOGLE_OIDC_CLIENT_ID."
  type        = string
  default     = "GOOGLE_OIDC_CLIENT_ID"
}

variable "github_secret_name_google_oidc_client_secret" {
  description = "GitHub Actions secret name for app login GOOGLE_OIDC_CLIENT_SECRET."
  type        = string
  default     = "GOOGLE_OIDC_CLIENT_SECRET"
}

variable "github_secret_name_google_oidc_redirect_uri" {
  description = "GitHub Actions secret name for app login GOOGLE_OIDC_REDIRECT_URI."
  type        = string
  default     = "GOOGLE_OIDC_REDIRECT_URI"
}
