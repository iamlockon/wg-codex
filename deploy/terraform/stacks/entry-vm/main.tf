provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

module "entry_vm" {
  source = "../../modules/entry_vm"

  project_id           = var.project_id
  name                 = var.name
  region               = var.region
  zone                 = var.zone
  machine_type         = var.machine_type
  boot_image           = var.boot_image
  boot_disk_size_gb    = var.boot_disk_size_gb
  boot_disk_type       = var.boot_disk_type
  network              = var.network
  network_tags         = var.network_tags
  create_firewall      = var.create_firewall
  allow_entry_cidrs    = var.allow_entry_cidrs
  allow_wireguard_cidrs = var.allow_wireguard_cidrs
  wireguard_port       = var.wireguard_port
}
