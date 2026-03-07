variable "project_id" { type = string }
variable "region" { type = string }
variable "zone" { type = string }
variable "name" { type = string default = "wg-entry-vm" }
variable "machine_type" { type = string default = "e2-micro" }
variable "boot_image" { type = string default = "projects/debian-cloud/global/images/family/debian-12" }
variable "boot_disk_size_gb" { type = number default = 20 }
variable "boot_disk_type" { type = string default = "pd-balanced" }
variable "network" { type = string default = "default" }
variable "network_tags" { type = list(string) default = ["wg-entry"] }
variable "create_firewall" { type = bool default = true }
variable "allow_entry_cidrs" { type = list(string) default = ["0.0.0.0/0"] }
variable "allow_wireguard_cidrs" { type = list(string) default = ["0.0.0.0/0"] }
variable "wireguard_port" { type = number default = 51820 }
