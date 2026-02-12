variable "project_id" {
  description = "GCP project ID."
  type        = string
}

variable "project_number" {
  description = "GCP project number used in Secret Manager resource paths."
  type        = string
}

variable "namespace" {
  description = "Kubernetes namespace for wg workloads."
  type        = string
  default     = "wg-vpn"
}

variable "manage_namespace" {
  description = "Create and manage the Kubernetes namespace."
  type        = bool
  default     = true
}

variable "entry_gsa_name" {
  description = "Service account ID for entry workload identity."
  type        = string
  default     = "entry-secrets"
}

variable "core_gsa_name" {
  description = "Service account ID for core workload identity."
  type        = string
  default     = "core-secrets"
}

variable "kubeconfig_path" {
  description = "Path to kubeconfig for Kubernetes provider."
  type        = string
  default     = "~/.kube/config"
}

variable "kubeconfig_context" {
  description = "Optional kubeconfig context override."
  type        = string
  default     = null
}

variable "google_oauth_client_id" {
  description = "Google Sign-In OAuth client ID from APIs & Services > Credentials."
  type        = string
  sensitive   = true

  validation {
    condition     = trimspace(var.google_oauth_client_id) != ""
    error_message = "google_oauth_client_id must be non-empty."
  }
}

variable "google_oauth_client_secret" {
  description = "Google Sign-In OAuth client secret from APIs & Services > Credentials."
  type        = string
  sensitive   = true

  validation {
    condition     = trimspace(var.google_oauth_client_secret) != ""
    error_message = "google_oauth_client_secret must be non-empty."
  }
}

variable "manage_postgres" {
  description = "When true, provision Cloud SQL Postgres and write entry-database-url secret."
  type        = bool
  default     = false
}

variable "postgres_instance_name" {
  description = "Cloud SQL instance name for entry database."
  type        = string
  default     = "wg-entry-postgres"
}

variable "postgres_region" {
  description = "Cloud SQL region."
  type        = string
  default     = "us-central1"
}

variable "postgres_tier" {
  description = "Cloud SQL machine tier."
  type        = string
  default     = "db-custom-1-3840"
}

variable "postgres_disk_size_gb" {
  description = "Cloud SQL disk size in GB."
  type        = number
  default     = 20
}

variable "postgres_database" {
  description = "App database name."
  type        = string
  default     = "wg_entry"
}

variable "postgres_username" {
  description = "App database user."
  type        = string
  default     = "wg_entry"
}

variable "postgres_deletion_protection" {
  description = "Enable deletion protection for Cloud SQL instance."
  type        = bool
  default     = true
}

variable "postgres_private_ip_enabled" {
  description = "Use private IP for Cloud SQL."
  type        = bool
  default     = true
}

variable "postgres_enable_public_ip" {
  description = "Enable public IPv4 on Cloud SQL."
  type        = bool
  default     = false
}

variable "postgres_private_path_for_google_cloud_services" {
  description = "Enable private path for Google Cloud services on Cloud SQL."
  type        = bool
  default     = true
}

variable "create_vpc" {
  description = "Create a dedicated VPC for private Cloud SQL networking."
  type        = bool
  default     = false
}

variable "vpc_name" {
  description = "Name of VPC to create when create_vpc=true."
  type        = string
  default     = "wg-vpc"
}

variable "vpc_self_link" {
  description = "Existing VPC self_link to use when create_vpc=false."
  type        = string
  default     = null
}

variable "create_private_service_networking" {
  description = "Create private service networking allocation and peering for Cloud SQL private IP."
  type        = bool
  default     = true
}

variable "private_service_range_name" {
  description = "Name of allocated range for private service networking."
  type        = string
  default     = "wg-sql-private-range"
}

variable "private_service_range_prefix_length" {
  description = "Prefix length for private service networking allocated range."
  type        = number
  default     = 16
}

variable "enable_required_apis" {
  description = "Enable required Google APIs for resources managed by this stack."
  type        = bool
  default     = true
}

variable "manage_gke" {
  description = "When true, provision GKE cluster and node pools."
  type        = bool
  default     = false
}

variable "gke_cluster_name" {
  description = "GKE cluster name."
  type        = string
  default     = "wg-cluster"
}

variable "gke_location" {
  description = "GKE cluster location (region recommended)."
  type        = string
  default     = "us-central1"
}

variable "gke_region" {
  description = "Region used for GKE subnet creation."
  type        = string
  default     = "us-central1"
}

variable "create_gke_subnetwork" {
  description = "Create a dedicated GKE subnetwork when manage_gke=true."
  type        = bool
  default     = true
}

variable "gke_subnetwork_name" {
  description = "Subnetwork name when create_gke_subnetwork=true."
  type        = string
  default     = "wg-gke-subnet"
}

variable "gke_subnetwork_cidr" {
  description = "Primary CIDR range for GKE nodes."
  type        = string
  default     = "10.20.0.0/20"
}

variable "gke_pods_secondary_range_name" {
  description = "Secondary range name for pods."
  type        = string
  default     = "wg-pods"
}

variable "gke_pods_secondary_cidr" {
  description = "Secondary CIDR range for pods."
  type        = string
  default     = "10.21.0.0/16"
}

variable "gke_services_secondary_range_name" {
  description = "Secondary range name for services."
  type        = string
  default     = "wg-services"
}

variable "gke_services_secondary_cidr" {
  description = "Secondary CIDR range for services."
  type        = string
  default     = "10.22.0.0/20"
}

variable "gke_subnetwork_self_link" {
  description = "Existing subnetwork self_link when create_gke_subnetwork=false."
  type        = string
  default     = null
}

variable "gke_entry_node_count" {
  description = "Node count for entry node pool."
  type        = number
  default     = 1
}

variable "gke_core_node_count" {
  description = "Node count for core node pool."
  type        = number
  default     = 2
}

variable "gke_entry_machine_type" {
  description = "Machine type for entry node pool."
  type        = string
  default     = "e2-standard-2"
}

variable "gke_core_machine_type" {
  description = "Machine type for core node pool."
  type        = string
  default     = "e2-standard-4"
}

variable "gke_release_channel" {
  description = "GKE release channel."
  type        = string
  default     = "REGULAR"
}

variable "install_secrets_store_csi_driver" {
  description = "Install Secrets Store CSI driver and GCP provider via Helm."
  type        = bool
  default     = true
}

variable "secret_values" {
  description = "Optional initial secret payloads keyed by secret name."
  type        = map(string)
  default     = {}
  sensitive   = true

  validation {
    condition = length(setsubtract(
      toset(keys(var.secret_values)),
      toset([
        "entry-database-url",
        "entry-admin-api-token",
        "entry-jwt-signing-keys",
        "entry-google-oidc-client-id",
        "entry-google-oidc-client-secret",
        "core-grpc-client-tls-ca",
        "core-grpc-client-tls-client-crt",
        "core-grpc-client-tls-client-key",
        "core-admin-api-token",
        "core-node-id",
        "core-wg-server-public-key",
        "core-tls-server-crt",
        "core-tls-server-key",
        "core-tls-ca",
        "wireguard-private-key",
      ])
    )) == 0
    error_message = "secret_values contains unknown keys."
  }
}
