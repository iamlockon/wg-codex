variable "project_id" { type = string }
variable "name" { type = string }
variable "region" { type = string }
variable "zone" { type = string }
variable "machine_type" { type = string }
variable "boot_image" { type = string }
variable "boot_disk_size_gb" { type = number }
variable "boot_disk_type" { type = string }
variable "network" { type = string }
variable "network_tags" { type = list(string) }
variable "metadata" { type = map(string) default = {} }
variable "service_account_email" { type = string default = null }
variable "service_account_scopes" { type = list(string) default = ["https://www.googleapis.com/auth/cloud-platform"] }
variable "create_firewall" { type = bool default = true }
variable "allow_entry_cidrs" { type = list(string) default = ["0.0.0.0/0"] }
variable "allow_wireguard_cidrs" { type = list(string) default = ["0.0.0.0/0"] }
variable "wireguard_port" { type = number default = 51820 }
