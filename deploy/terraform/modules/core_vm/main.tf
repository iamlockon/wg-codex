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

  metadata = var.metadata

  service_account {
    email  = var.service_account_email
    scopes = var.service_account_scopes
  }
}

resource "google_compute_firewall" "entry" {
  count   = var.create_firewall ? 1 : 0
  name    = "${var.name}-allow-entry"
  network = var.network
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["8080"]
  }

  source_ranges = var.allow_entry_cidrs
  target_tags   = var.network_tags
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
