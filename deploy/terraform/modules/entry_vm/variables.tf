variable "project_id" { type = string }
variable "name" { type = string }
variable "region" { type = string }
variable "zone" { type = string }
variable "machine_type" { type = string }
variable "boot_image" { type = string }
variable "boot_disk_size_gb" { type = number }
variable "boot_disk_type" { type = string }
variable "network" { type = string }
variable "network_tags" {
  type = list(string)

  validation {
    condition     = length(var.network_tags) > 0 && alltrue([for tag in var.network_tags : trimspace(tag) != ""])
    error_message = "network_tags must contain at least one non-empty tag so firewall target_tags are always explicit."
  }
}

variable "metadata" {
  type    = map(string)
  default = {}
}

variable "rollout_artifact_ref" {
  type        = string
  description = "Optional startup rollout artifact reference for metadata key wg-entry-artifact-ref. Prefer a gs:// GCS object path for the entry binary."
  default     = null

  validation {
    condition     = var.rollout_artifact_ref == null || trimspace(var.rollout_artifact_ref) != ""
    error_message = "rollout_artifact_ref must be null or a non-empty reference string."
  }
}

variable "rollout_artifact_sha256" {
  type        = string
  description = "Optional SHA-256 checksum for the rollout artifact, mapped to metadata key wg-entry-artifact-sha256."
  default     = null

  validation {
    condition     = var.rollout_artifact_sha256 == null || can(regex("^[0-9a-fA-F]{64}$", var.rollout_artifact_sha256))
    error_message = "rollout_artifact_sha256 must be null or a 64-character hexadecimal SHA-256 digest."
  }
}

variable "rollout_env_ref" {
  type        = string
  description = "Optional startup env_ref for metadata key wg-entry-env-ref. Use a Secret Manager or GCS reference for the rendered entry env file."
  default     = null

  validation {
    condition     = var.rollout_env_ref == null || trimspace(var.rollout_env_ref) != ""
    error_message = "rollout_env_ref must be null or a non-empty reference string."
  }
}

variable "rollout_unit_ref" {
  type        = string
  description = "Optional startup unit reference for metadata key wg-entry-unit-ref when the default systemd unit should be replaced."
  default     = null

  validation {
    condition     = var.rollout_unit_ref == null || trimspace(var.rollout_unit_ref) != ""
    error_message = "rollout_unit_ref must be null or a non-empty reference string."
  }
}

variable "rollout_core_ca_secret_ref" {
  type        = string
  description = "Optional secret_ref for metadata key wg-entry-core-ca-ref so startup can fetch the core CA certificate from Secret Manager."
  default     = null

  validation {
    condition     = var.rollout_core_ca_secret_ref == null || trimspace(var.rollout_core_ca_secret_ref) != ""
    error_message = "rollout_core_ca_secret_ref must be null or a non-empty reference string."
  }
}

variable "rollout_core_client_cert_secret_ref" {
  type        = string
  description = "Optional secret_ref for metadata key wg-entry-core-client-cert-ref so startup can fetch the mTLS client certificate."
  default     = null

  validation {
    condition     = var.rollout_core_client_cert_secret_ref == null || trimspace(var.rollout_core_client_cert_secret_ref) != ""
    error_message = "rollout_core_client_cert_secret_ref must be null or a non-empty reference string."
  }
}

variable "rollout_core_client_key_secret_ref" {
  type        = string
  description = "Optional secret_ref for metadata key wg-entry-core-client-key-ref so startup can fetch the mTLS client private key."
  default     = null

  validation {
    condition     = var.rollout_core_client_key_secret_ref == null || trimspace(var.rollout_core_client_key_secret_ref) != ""
    error_message = "rollout_core_client_key_secret_ref must be null or a non-empty reference string."
  }
}

variable "startup_script" {
  type        = string
  description = "Optional GCE startup script override. When null, the module renders deploy/startup/entry-startup.sh.tmpl with the shared common startup library."
  default     = null

  validation {
    condition     = var.startup_script == null || trimspace(var.startup_script) != ""
    error_message = "startup_script must be null or a non-empty string."
  }
}

variable "service_account_email" {
  type    = string
  default = null
}

variable "service_account_scopes" {
  type    = list(string)
  default = ["https://www.googleapis.com/auth/cloud-platform"]
}

variable "create_firewall" {
  type    = bool
  default = true
}

variable "allow_entry_cidrs" {
  type    = list(string)
  default = ["0.0.0.0/0"]
}

variable "allow_wireguard_cidrs" {
  type    = list(string)
  default = ["0.0.0.0/0"]
}

variable "wireguard_port" {
  type    = number
  default = 51820

  validation {
    condition     = var.wireguard_port >= 1 && var.wireguard_port <= 65535
    error_message = "wireguard_port must be between 1 and 65535."
  }
}
