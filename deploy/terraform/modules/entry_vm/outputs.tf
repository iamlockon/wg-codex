output "instance_name" { value = google_compute_instance.core.name }
output "instance_self_link" { value = google_compute_instance.core.self_link }
output "public_ip" { value = google_compute_address.core.address }
output "zone" { value = google_compute_instance.core.zone }
output "region" { value = var.region }
