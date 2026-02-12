provider "google" {
  project = var.project_id
}

data "google_client_config" "default" {}

provider "kubernetes" {
  config_path            = var.manage_gke ? null : var.kubeconfig_path
  config_context         = var.manage_gke ? null : var.kubeconfig_context
  host                   = var.manage_gke ? "https://${google_container_cluster.main[0].endpoint}" : null
  token                  = var.manage_gke ? data.google_client_config.default.access_token : null
  cluster_ca_certificate = var.manage_gke ? base64decode(google_container_cluster.main[0].master_auth[0].cluster_ca_certificate) : null
}

provider "helm" {
  kubernetes {
    config_path            = var.manage_gke ? null : var.kubeconfig_path
    config_context         = var.manage_gke ? null : var.kubeconfig_context
    host                   = var.manage_gke ? "https://${google_container_cluster.main[0].endpoint}" : null
    token                  = var.manage_gke ? data.google_client_config.default.access_token : null
    cluster_ca_certificate = var.manage_gke ? base64decode(google_container_cluster.main[0].master_auth[0].cluster_ca_certificate) : null
  }
}

locals {
  managed_secret_ids = toset([
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

  entry_secret_bindings = [
    { id = "entry-database-url", path = "DATABASE_URL" },
    { id = "entry-admin-api-token", path = "ADMIN_API_TOKEN" },
    { id = "entry-jwt-signing-keys", path = "APP_JWT_SIGNING_KEYS" },
    { id = "entry-google-oidc-client-id", path = "GOOGLE_OIDC_CLIENT_ID" },
    { id = "entry-google-oidc-client-secret", path = "GOOGLE_OIDC_CLIENT_SECRET" },
    { id = "core-grpc-client-tls-ca", path = "ca.pem" },
    { id = "core-grpc-client-tls-client-crt", path = "client.crt" },
    { id = "core-grpc-client-tls-client-key", path = "client.key" },
  ]

  core_secret_bindings = [
    { id = "core-admin-api-token", path = "ADMIN_API_TOKEN" },
    { id = "core-node-id", path = "CORE_NODE_ID" },
    { id = "core-wg-server-public-key", path = "WG_SERVER_PUBLIC_KEY" },
    { id = "core-tls-server-crt", path = "server.crt" },
    { id = "core-tls-server-key", path = "server.key" },
    { id = "core-tls-ca", path = "ca.pem" },
    { id = "wireguard-private-key", path = "private.key" },
  ]

  sql_network_self_link = var.create_vpc ? google_compute_network.sql[0].self_link : var.vpc_self_link
  sql_host = var.postgres_private_ip_enabled ? try(google_sql_database_instance.entry[0].private_ip_address, null) : try(google_sql_database_instance.entry[0].public_ip_address, null)
  gke_network_self_link = var.create_vpc ? google_compute_network.sql[0].self_link : var.vpc_self_link
  gke_subnetwork_self_link = var.create_gke_subnetwork ? google_compute_subnetwork.gke[0].self_link : var.gke_subnetwork_self_link

  generated_database_url = try(
    format(
      "postgres://%s:%s@%s:5432/%s",
      var.postgres_username,
      urlencode(random_password.postgres[0].result),
      local.sql_host,
      var.postgres_database
    ),
    null
  )

  managed_secret_values = merge(
    var.secret_values,
    {
      "entry-google-oidc-client-id"     = var.google_oauth_client_id
      "entry-google-oidc-client-secret" = var.google_oauth_client_secret
    },
    var.manage_postgres ? {
      "entry-database-url" = local.generated_database_url
    } : {}
  )
}

resource "google_service_account" "entry" {
  account_id   = var.entry_gsa_name
  display_name = "wg-entry secrets access"
}

resource "google_service_account" "core" {
  account_id   = var.core_gsa_name
  display_name = "wg-core secrets access"
}

resource "google_project_service" "sqladmin" {
  count = var.enable_required_apis && var.manage_postgres ? 1 : 0

  service = "sqladmin.googleapis.com"
}

resource "google_project_service" "compute" {
  count = var.enable_required_apis && (var.manage_postgres || var.manage_gke) ? 1 : 0

  service = "compute.googleapis.com"
}

resource "google_project_service" "container" {
  count = var.enable_required_apis && var.manage_gke ? 1 : 0

  service = "container.googleapis.com"
}

resource "google_secret_manager_secret" "managed" {
  for_each = local.managed_secret_ids

  secret_id = each.key
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "managed" {
  for_each = local.managed_secret_values

  secret      = google_secret_manager_secret.managed[each.key].id
  secret_data = each.value
}

resource "google_compute_network" "sql" {
  count = var.create_vpc ? 1 : 0

  name                    = var.vpc_name
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "gke" {
  count = var.manage_gke && var.create_gke_subnetwork ? 1 : 0

  name          = var.gke_subnetwork_name
  ip_cidr_range = var.gke_subnetwork_cidr
  network       = local.gke_network_self_link
  region        = var.gke_region

  secondary_ip_range {
    range_name    = var.gke_pods_secondary_range_name
    ip_cidr_range = var.gke_pods_secondary_cidr
  }

  secondary_ip_range {
    range_name    = var.gke_services_secondary_range_name
    ip_cidr_range = var.gke_services_secondary_cidr
  }
}

resource "google_project_service" "service_networking" {
  count = var.enable_required_apis && var.manage_postgres && var.postgres_private_ip_enabled && var.create_private_service_networking ? 1 : 0

  service = "servicenetworking.googleapis.com"
}

resource "google_compute_global_address" "private_service_range" {
  count = var.manage_postgres && var.postgres_private_ip_enabled && var.create_private_service_networking ? 1 : 0

  name          = var.private_service_range_name
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = var.private_service_range_prefix_length
  network       = local.sql_network_self_link

  depends_on = [google_project_service.service_networking]
}

resource "google_service_networking_connection" "private_vpc_connection" {
  count = var.manage_postgres && var.postgres_private_ip_enabled && var.create_private_service_networking ? 1 : 0

  network                 = local.sql_network_self_link
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_service_range[0].name]
}

resource "random_password" "postgres" {
  count = var.manage_postgres ? 1 : 0

  length           = 32
  special          = true
  override_special = "_%@"
}

resource "google_sql_database_instance" "entry" {
  count = var.manage_postgres ? 1 : 0

  name                = var.postgres_instance_name
  region              = var.postgres_region
  database_version    = "POSTGRES_16"
  deletion_protection = var.postgres_deletion_protection

  settings {
    tier              = var.postgres_tier
    availability_type = "ZONAL"
    disk_size         = var.postgres_disk_size_gb
    disk_autoresize   = true

    backup_configuration {
      enabled = true
    }

    ip_configuration {
      ipv4_enabled                                  = var.postgres_enable_public_ip
      private_network                               = var.postgres_private_ip_enabled ? local.sql_network_self_link : null
      enable_private_path_for_google_cloud_services = var.postgres_private_path_for_google_cloud_services
      allocated_ip_range                            = var.postgres_private_ip_enabled && var.create_private_service_networking ? google_compute_global_address.private_service_range[0].name : null
    }
  }

  depends_on = [
    google_service_networking_connection.private_vpc_connection,
    google_project_service.sqladmin,
    google_project_service.compute,
  ]

  lifecycle {
    precondition {
      condition     = !var.postgres_private_ip_enabled || local.sql_network_self_link != null
      error_message = "postgres_private_ip_enabled=true requires either create_vpc=true or vpc_self_link."
    }
  }
}

resource "google_sql_database" "entry" {
  count = var.manage_postgres ? 1 : 0

  name     = var.postgres_database
  instance = google_sql_database_instance.entry[0].name
}

resource "google_sql_user" "entry" {
  count = var.manage_postgres ? 1 : 0

  name     = var.postgres_username
  instance = google_sql_database_instance.entry[0].name
  password = random_password.postgres[0].result
}

resource "google_container_cluster" "main" {
  count = var.manage_gke ? 1 : 0

  name                     = var.gke_cluster_name
  location                 = var.gke_location
  remove_default_node_pool = true
  initial_node_count       = 1
  network                  = local.gke_network_self_link
  subnetwork               = local.gke_subnetwork_self_link

  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  ip_allocation_policy {
    cluster_secondary_range_name  = var.gke_pods_secondary_range_name
    services_secondary_range_name = var.gke_services_secondary_range_name
  }

  release_channel {
    channel = var.gke_release_channel
  }

  lifecycle {
    precondition {
      condition     = local.gke_network_self_link != null
      error_message = "manage_gke=true requires either create_vpc=true or vpc_self_link."
    }
    precondition {
      condition     = var.create_gke_subnetwork || local.gke_subnetwork_self_link != null
      error_message = "manage_gke=true with create_gke_subnetwork=false requires gke_subnetwork_self_link."
    }
  }

  depends_on = [
    google_project_service.container,
    google_project_service.compute,
  ]
}

resource "google_container_node_pool" "entry" {
  count = var.manage_gke ? 1 : 0

  name       = "entry-pool"
  location   = var.gke_location
  cluster    = google_container_cluster.main[0].name
  node_count = var.gke_entry_node_count

  node_config {
    machine_type = var.gke_entry_machine_type
    oauth_scopes = ["https://www.googleapis.com/auth/cloud-platform"]
    labels = {
      workload = "entry"
    }
  }
}

resource "google_container_node_pool" "core" {
  count = var.manage_gke ? 1 : 0

  name       = "core-pool"
  location   = var.gke_location
  cluster    = google_container_cluster.main[0].name
  node_count = var.gke_core_node_count

  node_config {
    machine_type = var.gke_core_machine_type
    oauth_scopes = ["https://www.googleapis.com/auth/cloud-platform"]
    labels = {
      workload = "core"
    }
  }
}

resource "helm_release" "secrets_store_csi_driver" {
  count = var.install_secrets_store_csi_driver ? 1 : 0

  name             = "secrets-store-csi-driver"
  repository       = "https://kubernetes-sigs.github.io/secrets-store-csi-driver/charts"
  chart            = "secrets-store-csi-driver"
  namespace        = "kube-system"
  create_namespace = false

  set {
    name  = "syncSecret.enabled"
    value = "true"
  }

  depends_on = [
    google_container_cluster.main,
    google_container_node_pool.entry,
    google_container_node_pool.core,
  ]
}

resource "helm_release" "secrets_store_csi_driver_provider_gcp" {
  count = var.install_secrets_store_csi_driver ? 1 : 0

  name             = "secrets-store-csi-driver-provider-gcp"
  repository       = "https://kubernetes-sigs.github.io/secrets-store-csi-driver-provider-gcp/charts"
  chart            = "secrets-store-csi-driver-provider-gcp"
  namespace        = "kube-system"
  create_namespace = false

  depends_on = [
    helm_release.secrets_store_csi_driver,
    google_container_cluster.main,
    google_container_node_pool.entry,
    google_container_node_pool.core,
  ]
}

resource "kubernetes_service_account_v1" "entry" {
  depends_on = [kubernetes_namespace_v1.wg]

  metadata {
    name      = "entry-wi"
    namespace = var.namespace
    annotations = {
      "iam.gke.io/gcp-service-account" = google_service_account.entry.email
    }
  }
}

resource "kubernetes_service_account_v1" "core" {
  depends_on = [kubernetes_namespace_v1.wg]

  metadata {
    name      = "core-wi"
    namespace = var.namespace
    annotations = {
      "iam.gke.io/gcp-service-account" = google_service_account.core.email
    }
  }
}

resource "google_service_account_iam_member" "entry_workload_identity" {
  service_account_id = google_service_account.entry.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[${var.namespace}/${kubernetes_service_account_v1.entry.metadata[0].name}]"
}

resource "google_service_account_iam_member" "core_workload_identity" {
  service_account_id = google_service_account.core.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[${var.namespace}/${kubernetes_service_account_v1.core.metadata[0].name}]"
}

resource "google_secret_manager_secret_iam_member" "entry_secret_access" {
  for_each = toset([for b in local.entry_secret_bindings : b.id])

  project   = var.project_id
  secret_id = google_secret_manager_secret.managed[each.key].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.entry.email}"
}

resource "google_secret_manager_secret_iam_member" "core_secret_access" {
  for_each = toset([for b in local.core_secret_bindings : b.id])

  project   = var.project_id
  secret_id = google_secret_manager_secret.managed[each.key].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.core.email}"
}

resource "kubernetes_manifest" "entry_secret_provider_class" {
  depends_on = [kubernetes_namespace_v1.wg, helm_release.secrets_store_csi_driver_provider_gcp]

  manifest = {
    apiVersion = "secrets-store.csi.x-k8s.io/v1"
    kind       = "SecretProviderClass"
    metadata = {
      name      = "entry-gcp-secrets"
      namespace = var.namespace
    }
    spec = {
      provider = "gcp"
      parameters = {
        secrets = join("\n", [
          for b in local.entry_secret_bindings :
          "  - resourceName: \"projects/${var.project_number}/secrets/${b.id}/versions/latest\"\n    path: \"${b.path}\""
        ])
      }
    }
  }
}

resource "kubernetes_manifest" "core_secret_provider_class" {
  depends_on = [kubernetes_namespace_v1.wg, helm_release.secrets_store_csi_driver_provider_gcp]

  manifest = {
    apiVersion = "secrets-store.csi.x-k8s.io/v1"
    kind       = "SecretProviderClass"
    metadata = {
      name      = "core-gcp-secrets"
      namespace = var.namespace
    }
    spec = {
      provider = "gcp"
      parameters = {
        secrets = join("\n", [
          for b in local.core_secret_bindings :
          "  - resourceName: \"projects/${var.project_number}/secrets/${b.id}/versions/latest\"\n    path: \"${b.path}\""
        ])
      }
    }
  }
}

resource "kubernetes_namespace_v1" "wg" {
  count = var.manage_namespace ? 1 : 0

  metadata {
    name = var.namespace
  }

  depends_on = [
    google_container_cluster.main,
    google_container_node_pool.entry,
    google_container_node_pool.core,
  ]
}
