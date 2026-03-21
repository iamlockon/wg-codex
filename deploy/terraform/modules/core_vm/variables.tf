variable "project_id" {
  type        = string
  description = "GCP project ID that owns the core VM resources."
}

variable "name" {
  type        = string
  description = "Name to use for the core VM instance and related resources."
}

variable "region" {
  type        = string
  description = "Region for regional resources such as the reserved external IP."
}

variable "zone" {
  type        = string
  description = "Zone where the core VM instance will be created."
}

variable "machine_type" {
  type        = string
  description = "Compute Engine machine type for the core VM."
}

variable "boot_image" {
  type        = string
  description = "Boot disk image or image family reference for the VM."
}

variable "boot_disk_size_gb" {
  type        = number
  description = "Boot disk size in GB."
}

variable "boot_disk_type" {
  type        = string
  description = "Boot disk type for the VM, such as pd-balanced."
}

variable "network" {
  type        = string
  description = "VPC network name or self-link to attach to the VM."
}

variable "network_tags" {
  type        = list(string)
  description = "Network tags applied to the VM and used as firewall targets."

  validation {
    condition     = length(var.network_tags) > 0 && alltrue([for tag in var.network_tags : trimspace(tag) != ""])
    error_message = "network_tags must contain at least one non-empty tag so firewall target_tags are always explicit."
  }
}

variable "metadata" {
  type        = map(string)
  description = "Instance metadata to attach to the VM, including future startup configuration."
  default     = {}
}

variable "rollout_artifact_ref" {
  type        = string
  description = "Optional startup rollout artifact reference for metadata key wg-core-artifact-ref. Prefer a gs:// GCS object path for the core binary."
  default     = null

  validation {
    condition     = var.rollout_artifact_ref == null || trimspace(var.rollout_artifact_ref) != ""
    error_message = "rollout_artifact_ref must be null or a non-empty reference string."
  }
}

variable "rollout_artifact_sha256" {
  type        = string
  description = "Optional SHA-256 checksum for the rollout artifact, mapped to metadata key wg-core-artifact-sha256."
  default     = null

  validation {
    condition     = var.rollout_artifact_sha256 == null || can(regex("^[0-9a-fA-F]{64}$", var.rollout_artifact_sha256))
    error_message = "rollout_artifact_sha256 must be null or a 64-character hexadecimal SHA-256 digest."
  }
}

variable "rollout_env_ref" {
  type        = string
  description = "Optional startup env_ref for metadata key wg-core-env-ref. Use a Secret Manager or GCS reference for the rendered core env file."
  default     = null

  validation {
    condition     = var.rollout_env_ref == null || trimspace(var.rollout_env_ref) != ""
    error_message = "rollout_env_ref must be null or a non-empty reference string."
  }
}

variable "rollout_unit_ref" {
  type        = string
  description = "Optional startup unit reference for metadata key wg-core-unit-ref when the default systemd unit should be replaced."
  default     = null

  validation {
    condition     = var.rollout_unit_ref == null || trimspace(var.rollout_unit_ref) != ""
    error_message = "rollout_unit_ref must be null or a non-empty reference string."
  }
}

variable "rollout_private_key_secret_ref" {
  type        = string
  description = "Optional secret_ref for metadata key wg-core-private-key-ref so startup can fetch the WireGuard private key from Secret Manager."
  default     = null

  validation {
    condition     = var.rollout_private_key_secret_ref == null || trimspace(var.rollout_private_key_secret_ref) != ""
    error_message = "rollout_private_key_secret_ref must be null or a non-empty reference string."
  }
}

variable "rollout_tls_cert_secret_ref" {
  type        = string
  description = "Optional secret_ref for metadata key wg-core-tls-cert-ref so startup can fetch the core TLS certificate from Secret Manager."
  default     = null

  validation {
    condition     = var.rollout_tls_cert_secret_ref == null || trimspace(var.rollout_tls_cert_secret_ref) != ""
    error_message = "rollout_tls_cert_secret_ref must be null or a non-empty reference string."
  }
}

variable "rollout_tls_key_secret_ref" {
  type        = string
  description = "Optional secret_ref for metadata key wg-core-tls-key-ref so startup can fetch the core TLS private key from Secret Manager."
  default     = null

  validation {
    condition     = var.rollout_tls_key_secret_ref == null || trimspace(var.rollout_tls_key_secret_ref) != ""
    error_message = "rollout_tls_key_secret_ref must be null or a non-empty reference string."
  }
}

variable "rollout_tls_ca_secret_ref" {
  type        = string
  description = "Optional secret_ref for metadata key wg-core-tls-ca-ref so startup can fetch the client CA bundle from Secret Manager."
  default     = null

  validation {
    condition     = var.rollout_tls_ca_secret_ref == null || trimspace(var.rollout_tls_ca_secret_ref) != ""
    error_message = "rollout_tls_ca_secret_ref must be null or a non-empty reference string."
  }
}

variable "startup_script" {
  type        = string
  description = "Optional GCE startup script override. When null, the module renders deploy/startup/core-startup.sh.tmpl with the shared common startup library."
  default     = null

  validation {
    condition     = var.startup_script == null || trimspace(var.startup_script) != ""
    error_message = "startup_script must be null or a non-empty string."
  }
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
  type        = bool
  description = "Whether this module should manage ingress firewall rules for the core VM."
  default     = true
}

variable "allow_wireguard_cidrs" {
  type        = list(string)
  description = "Source CIDRs allowed to reach the WireGuard UDP port."
  default     = ["0.0.0.0/0"]
}

variable "allow_core_grpc_cidrs" {
  type        = list(string)
  description = "Optional source CIDRs allowed to reach the core gRPC TCP port."
  default     = []
}

variable "wireguard_port" {
  type        = number
  description = "UDP port exposed for WireGuard traffic."
  default     = 51820

  validation {
    condition     = var.wireguard_port >= 1 && var.wireguard_port <= 65535
    error_message = "wireguard_port must be between 1 and 65535."
  }
}

variable "core_grpc_port" {
  type        = number
  description = "TCP port exposed for core gRPC traffic when allow_core_grpc_cidrs is non-empty."
  default     = 50051

  validation {
    condition     = var.core_grpc_port >= 1 && var.core_grpc_port <= 65535
    error_message = "core_grpc_port must be between 1 and 65535."
  }
}
