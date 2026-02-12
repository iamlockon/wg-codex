output "entry_gsa_email" {
  description = "GCP service account email used by entry workload identity."
  value       = google_service_account.entry.email
}

output "core_gsa_email" {
  description = "GCP service account email used by core workload identity."
  value       = google_service_account.core.email
}

output "managed_secret_ids" {
  description = "Secret Manager secrets managed by this stack."
  value       = sort([for s in google_secret_manager_secret.managed : s.secret_id])
}

output "postgres_instance_connection_name" {
  description = "Cloud SQL connection name when manage_postgres=true."
  value       = try(google_sql_database_instance.entry[0].connection_name, null)
}

output "postgres_public_ip" {
  description = "Cloud SQL public IP when manage_postgres=true."
  value       = try(google_sql_database_instance.entry[0].public_ip_address, null)
}

output "postgres_private_ip" {
  description = "Cloud SQL private IP when manage_postgres=true and private IP is enabled."
  value       = try(google_sql_database_instance.entry[0].private_ip_address, null)
}

output "sql_network_self_link" {
  description = "VPC network used by Cloud SQL private IP."
  value       = local.sql_network_self_link
}

output "oauth_client_id" {
  description = "OAuth client ID written to entry-google-oidc-client-id."
  value       = var.google_oauth_client_id
}

output "gke_cluster_name" {
  description = "GKE cluster name when manage_gke=true."
  value       = try(google_container_cluster.main[0].name, null)
}

output "gke_cluster_endpoint" {
  description = "GKE cluster endpoint when manage_gke=true."
  value       = try(google_container_cluster.main[0].endpoint, null)
}
