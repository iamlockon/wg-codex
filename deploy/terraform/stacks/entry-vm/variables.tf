variable "project_id" { type = string }
variable "region" { type = string }
variable "zone" { type = string }

variable "name" {
  type    = string
  default = "wg-entry-vm"
}

variable "machine_type" {
  type    = string
  default = "e2-micro"
}

variable "boot_image" {
  type    = string
  default = "projects/debian-cloud/global/images/family/debian-12"
}

variable "boot_disk_size_gb" {
  type    = number
  default = 20
}

variable "boot_disk_type" {
  type    = string
  default = "pd-balanced"
}

variable "network" {
  type    = string
  default = "default"
}

variable "network_tags" {
  type    = list(string)
  default = ["wg-entry"]
}

variable "metadata" {
  type        = map(string)
  description = "Instance metadata to attach to the VM, including startup rollout metadata overrides."
  default     = {}
}

variable "service_account_email" {
  type        = string
  description = "Optional service account email to attach to the VM."
  default     = null
}

variable "service_account_scopes" {
  type        = list(string)
  description = "OAuth scopes granted to the attached service account."
  default     = ["https://www.googleapis.com/auth/cloud-platform"]
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
  description = "Optional GCE startup script override passed through to the entry_vm module."
  default     = null

  validation {
    condition     = var.startup_script == null || trimspace(var.startup_script) != ""
    error_message = "startup_script must be null or a non-empty string."
  }
}
