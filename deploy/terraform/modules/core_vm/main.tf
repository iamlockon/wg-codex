locals {
  rendered_startup_script = var.startup_script != null ? var.startup_script : templatefile(
    "${path.module}/../../../startup/core-startup.sh.tmpl",
    {
      common_sh = templatefile("${path.module}/../../../startup/lib/common.sh.tmpl", {})
    }
  )

  rollout_metadata = {
    for key, value in {
      "wg-core-artifact-ref"    = var.rollout_artifact_ref
      "wg-core-artifact-sha256" = var.rollout_artifact_sha256
      "wg-core-env-ref"         = var.rollout_env_ref
      "wg-core-unit-ref"        = var.rollout_unit_ref
      "wg-core-private-key-ref" = var.rollout_private_key_secret_ref
      "wg-core-tls-cert-ref"    = var.rollout_tls_cert_secret_ref
      "wg-core-tls-key-ref"     = var.rollout_tls_key_secret_ref
      "wg-core-tls-ca-ref"      = var.rollout_tls_ca_secret_ref
    } : key => value if value != null
  }

  instance_metadata = merge(
    var.metadata,
    local.rollout_metadata,
    {
      "startup-script" = local.rendered_startup_script
    }
  )
}

resource "google_compute_address" "core" {
  name    = "${var.name}-ip"
  region  = var.region
  project = var.project_id
}

resource "google_compute_instance" "core" {
  name         = var.name
  machine_type = var.machine_type
  zone         = var.zone
  project      = var.project_id
  tags         = var.network_tags

  boot_disk {
    initialize_params {
      image = var.boot_image
      size  = var.boot_disk_size_gb
      type  = var.boot_disk_type
    }
  }

  network_interface {
    network = var.network
    access_config {
      nat_ip = google_compute_address.core.address
    }
  }

  metadata = local.instance_metadata

  service_account {
    email  = var.service_account_email
    scopes = var.service_account_scopes
  }
}

resource "google_compute_firewall" "wireguard" {
  count   = var.create_firewall ? 1 : 0
  name    = "${var.name}-allow-wireguard"
  network = var.network
  project = var.project_id

  allow {
    protocol = "udp"
    ports    = [tostring(var.wireguard_port)]
  }

  source_ranges = var.allow_wireguard_cidrs
  target_tags   = var.network_tags
}

resource "google_compute_firewall" "core_grpc" {
  count   = var.create_firewall && length(var.allow_core_grpc_cidrs) > 0 ? 1 : 0
  name    = "${var.name}-allow-core-grpc"
  network = var.network
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = [tostring(var.core_grpc_port)]
  }

  source_ranges = var.allow_core_grpc_cidrs
  target_tags   = var.network_tags
}
