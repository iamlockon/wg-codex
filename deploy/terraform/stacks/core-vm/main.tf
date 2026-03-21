provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

module "core_vm" {
  source = "../../modules/core_vm"

  project_id                     = var.project_id
  name                           = var.name
  region                         = var.region
  zone                           = var.zone
  machine_type                   = var.machine_type
  boot_image                     = var.boot_image
  boot_disk_size_gb              = var.boot_disk_size_gb
  boot_disk_type                 = var.boot_disk_type
  network                        = var.network
  network_tags                   = var.network_tags
  metadata                       = var.metadata
  service_account_email          = var.service_account_email
  service_account_scopes         = var.service_account_scopes
  create_firewall                = var.create_firewall
  allow_wireguard_cidrs          = var.allow_wireguard_cidrs
  allow_core_grpc_cidrs          = var.allow_core_grpc_cidrs
  wireguard_port                 = var.wireguard_port
  core_grpc_port                 = var.core_grpc_port
  rollout_artifact_ref           = var.rollout_artifact_ref
  rollout_artifact_sha256        = var.rollout_artifact_sha256
  rollout_env_ref                = var.rollout_env_ref
  rollout_unit_ref               = var.rollout_unit_ref
  rollout_private_key_secret_ref = var.rollout_private_key_secret_ref
  rollout_tls_cert_secret_ref    = var.rollout_tls_cert_secret_ref
  rollout_tls_key_secret_ref     = var.rollout_tls_key_secret_ref
  rollout_tls_ca_secret_ref      = var.rollout_tls_ca_secret_ref
  startup_script                 = var.startup_script
}
