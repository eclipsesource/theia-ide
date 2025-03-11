variable "keycloak_admin_password" {
  description = "Keycloak Admin Password"
  sensitive   = true
}

variable "postgres_postgres_password" {
  description = "Keycloak Postgres DB Postgres (Admin) Password"
  sensitive   = true
}

variable "postgres_password" {
  description = "Keycloak Postgres DB Password"
  sensitive   = true
}

variable "clientsecret" {
  description = "OAuth2 Proxy Client Secret"
  sensitive   = true
}

variable "cookiesecret" {
  description = "OAuth2 Proxy Cookie Secret"
  sensitive   = true
}

variable "github_client_secret" {
  description = "Github Client Secret"
  sensitive   = true
}

# Storage bucket for storing terraform state on Google Cloud
#
resource "google_storage_bucket" "default" {
  name     = "github-theia-ide-preview-terraform-remote-backend"
  location = "EUROPE-WEST3"
  project  = "kubernetes-238012"

  force_destroy               = false
  public_access_prevention    = "enforced"
  uniform_bucket_level_access = true

  versioning {
    enabled = true
  }
}

# Required configuration file for storing terraform state on Google Cloud
# (You need to run terraform init -migrate-state after the very first creation to move local state to the cloud)
#
resource "local_file" "default" {
  file_permission = "0644"
  filename        = "${path.module}/backend.tf"
  content         = <<-EOT
  terraform {
    backend "gcs" {
      bucket = "${google_storage_bucket.default.name}"
    }
  }
  EOT
}

# Kubernetes cluster
#
resource "google_container_cluster" "primary" {
  name                     = "github-theia-ide-preview"
  location                 = "europe-west3-c"
  remove_default_node_pool = true
  initial_node_count       = 1
  project                  = "kubernetes-238012"
  workload_identity_config {
    workload_pool = "kubernetes-238012.svc.id.goog"
  }
}

# Node Pool
#
resource "google_container_node_pool" "primary_nodes" {
  name               = "default-node-pool"
  location           = "europe-west3-c"
  cluster            = "github-theia-ide-preview"
  initial_node_count = 1
  depends_on         = [google_container_cluster.primary]
  project            = "kubernetes-238012"

  autoscaling {
    max_node_count = 3
  }

  node_config {
    preemptible  = false
    machine_type = "e2-standard-2" # 2 vCPUs / 8GB RAM
    metadata = {
      disable-legacy-endpoints = "true"
    }
  }

  # Connect local CLI to the cluster
  provisioner "local-exec" {
    command = "gcloud container clusters get-credentials github-theia-ide-preview --zone europe-west3-c --project kubernetes-238012"
  }
}

# IP for nginx
# There will be a DNS entry for this ip to theia-ide-preview.eclipsesource-munich.com
#
resource "google_compute_address" "host_ip" {
  name    = "github-theia-ide-preview-nginx-ip"
  project = "kubernetes-238012"
  region  = "europe-west3"
}

# Google Client Config
#
data "google_client_config" "default" {
  depends_on = [google_container_cluster.primary, google_container_node_pool.primary_nodes]
}

# Connect Helm and Kubectl to the cluster
#
provider "helm" {
  kubernetes {
    host                   = "https://${google_container_cluster.primary.endpoint}"
    token                  = data.google_client_config.default.access_token
    cluster_ca_certificate = base64decode(google_container_cluster.primary.master_auth[0].cluster_ca_certificate)
    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "gke-gcloud-auth-plugin"
    }
  }
}
provider "kubectl" {
  load_config_file       = false
  host                   = "https://${google_container_cluster.primary.endpoint}"
  token                  = data.google_client_config.default.access_token
  cluster_ca_certificate = base64decode(google_container_cluster.primary.master_auth[0].cluster_ca_certificate)
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "gke-gcloud-auth-plugin"
  }
}

# Install cert-manager
#
resource "helm_release" "cert-manager" {
  name             = "cert-manager"
  repository       = "https://charts.jetstack.io"
  chart            = "cert-manager"
  version          = "v1.16.2"
  namespace        = "cert-manager"
  create_namespace = true

  set {
    name  = "installCRDs"
    value = "true"
  }
}

# Install NginX
#
resource "helm_release" "nginx-ingress-controller" {
  count            = 1
  name             = "nginx-ingress-controller"
  repository       = "https://kubernetes.github.io/ingress-nginx"
  chart            = "ingress-nginx"
  version          = "4.11.3"
  namespace        = "ingress-nginx"
  create_namespace = true

  set {
    name  = "fullnameOverride"
    value = "ingress-nginx"
  }

  set {
    name  = "controller.service.loadBalancerIP"
    value = google_compute_address.host_ip.address
  }

  set {
    name  = "controller.allowSnippetAnnotations"
    value = true
  }
}

# Install Theia Cloud Base
#
resource "helm_release" "theia-cloud-base" {
  count            = 1
  depends_on       = [helm_release.cert-manager, helm_release.nginx-ingress-controller] # we need to install cert issuers
  name             = "theia-cloud-base"
  repository       = "https://eclipse-theia.github.io/theia-cloud-helm"
  chart            = "theia-cloud-base"
  version          = "1.0.0"
  namespace        = "theia-cloud"
  create_namespace = true

  set {
    name  = "issuer.email"
    value = "jfaltermeier+githubtheiaidepreview@eclipsesource.com"
  }
}

# Install Theia Cloud CRDs
#
resource "helm_release" "theia-cloud-crds" {
  count            = 1
  depends_on       = [helm_release.theia-cloud-base]
  name             = "theia-cloud-crds"
  repository       = "https://eclipse-theia.github.io/theia-cloud-helm"
  chart            = "theia-cloud-crds"
  version          = "1.0.0"
  namespace        = "theia-cloud"
  create_namespace = true
}

locals {
  # local_exec_quotes is a helper function to deal with different handling of
  # quotes between linux and windows. On linux, it will output "'". On windows,
  # it will output "".
  local_exec_quotes = startswith(abspath(path.module), "/") ? "'" : ""
  jsonpatch = jsonencode([{
    "op"    = "add",
    "path"  = "/spec/template/spec/containers/0/args/-",
    "value" = "--default-ssl-certificate=keycloak/theia-ide-preview.eclipsesource-munich.com-tls"
  }])
}

# Install Keycloak
#
resource "helm_release" "keycloak" {
  depends_on       = [helm_release.theia-cloud-base]
  name             = "keycloak"
  repository       = "https://charts.bitnami.com/bitnami"
  chart            = "keycloak"
  version          = "15.1.8"
  namespace        = "keycloak"
  create_namespace = true

  values = [
    "${templatefile("${path.module}/keycloak.yaml", {})}"
  ]

  set_sensitive {
    name  = "auth.adminPassword"
    value = var.keycloak_admin_password
  }
  set_sensitive {
    name  = "postgresql.auth.postgresPassword"
    value = var.postgres_postgres_password
  }
  set_sensitive {
    name  = "postgresql.auth.password"
    value = var.postgres_password
  }

  # We expect that kubectl context was configured by a previous module.
  # After keycloak was set up with tls enabled, we use the created tls secret as the default ssl-secret of the nginx-ingress-controller. 
  # Below command connects to the cluster in the local environment and patches the ingress-controller accordingly. 
  # Theia Cloud is then installed with path based hosts reusing the same certificate. 
  provisioner "local-exec" {
    command = "kubectl patch deploy ingress-nginx-controller --type=${local.local_exec_quotes}json${local.local_exec_quotes} -n ingress-nginx -p ${local.local_exec_quotes}${local.jsonpatch}${local.local_exec_quotes} && kubectl wait pods -n ingress-nginx -l app.kubernetes.io/component=controller --for condition=Ready --timeout=90s && kubectl wait certificate -n keycloak theia-ide-preview.eclipsesource-munich.com-tls --for condition=Ready --timeout=90s"
  }
}

provider "keycloak" {
  client_id      = "admin-cli"
  username       = "admin"
  password       = var.keycloak_admin_password
  url            = "https://theia-ide-preview.eclipsesource-munich.com/keycloak"
  initial_login  = false
  client_timeout = 60
}

# Create Keycloak Realm
#
resource "keycloak_realm" "theia-cloud" {
  realm   = "TheiaCloud"
  enabled = true
}

# Create OpenID Client
#
resource "keycloak_openid_client" "theia-cloud" {
  realm_id                                  = keycloak_realm.theia-cloud.id
  client_id                                 = "theia-cloud"
  enabled                                   = true
  access_type                               = "PUBLIC"
  client_authenticator_type                 = "client-secret"
  direct_access_grants_enabled              = true
  implicit_flow_enabled                     = false
  oauth2_device_authorization_grant_enabled = false
  service_accounts_enabled                  = false
  standard_flow_enabled                     = true
  use_refresh_tokens                        = true
  use_refresh_tokens_client_credentials     = false
  valid_post_logout_redirect_uris = [
    "https://a.theia-ide-preview.eclipsesource-munich.com",
    "https://a.theia-ide-preview.eclipsesource-munich.com/*",
    "https://launch.theia-ide-preview.eclipsesource-munich.com",
    "https://launch.theia-ide-preview.eclipsesource-munich.com/*",
    "https://servicex.theia-ide-preview.eclipsesource-munich.com",
    "https://servicex.theia-ide-preview.eclipsesource-munich.com/*"
  ]
  valid_redirect_uris = [
    "https://a.theia-ide-preview.eclipsesource-munich.com",
    "https://a.theia-ide-preview.eclipsesource-munich.com/*",
    "https://launch.theia-ide-preview.eclipsesource-munich.com",
    "https://launch.theia-ide-preview.eclipsesource-munich.com/*",
    "https://servicex.theia-ide-preview.eclipsesource-munich.com",
    "https://servicex.theia-ide-preview.eclipsesource-munich.com/*"
  ]
  web_origins = [
    "https://a.theia-ide-preview.eclipsesource-munich.com",
    "https://a.theia-ide-preview.eclipsesource-munich.com/*",
    "https://launch.theia-ide-preview.eclipsesource-munich.com",
    "https://launch.theia-ide-preview.eclipsesource-munich.com/*",
    "https://servicex.theia-ide-preview.eclipsesource-munich.com",
    "https://servicex.theia-ide-preview.eclipsesource-munich.com/*"
  ]
}

# Authorization callback URL when creating your GitHub OAuth App:
# https://theia-ide-preview.eclipsesource-munich.com/keycloak/realms/TheiaCloud/broker/github/endpoint
#
resource "keycloak_oidc_identity_provider" "github" {
  realm        = keycloak_realm.theia-cloud.id
  alias        = "github"
  provider_id  = "github"
  display_name = "GitHub"
  enabled      = true

  client_id     = "Ov23li59YF8iauwvArI2"
  client_secret = var.github_client_secret

  authorization_url = "https://github.com/login/oauth/authorize"
  token_url         = "https://github.com/login/oauth/access_token"
  user_info_url     = "https://api.github.com/user"
  default_scopes    = "user:email"

  trust_email = true
}

# Create admin user group
#
resource "keycloak_group" "theia_cloud_admin" {
  realm_id = keycloak_realm.theia-cloud.id
  name     = "theia-cloud/admin"
}
resource "keycloak_openid_group_membership_protocol_mapper" "groups" {
  realm_id   = keycloak_realm.theia-cloud.id
  client_id  = keycloak_openid_client.theia-cloud.id
  name       = "groups"
  claim_name = "groups"
  # Disable full path for group names to just get the group name as configured
  # and avoid Keycloak prefixing them with a slash
  full_path = false
}

# Audience Protocol Mapper
#
resource "keycloak_openid_audience_protocol_mapper" "audience" {
  realm_id                 = keycloak_realm.theia-cloud.id
  client_id                = keycloak_openid_client.theia-cloud.id
  name                     = "audience"
  included_custom_audience = "theia-cloud"
}

# Imported (On a first run, you may have to remove contents and import the built-in, see README.md for hints)
#
resource "keycloak_authentication_execution" "browser" {
  authenticator     = "identity-provider-redirector"
  parent_flow_alias = "browser"
  realm_id          = keycloak_realm.theia-cloud.id
  requirement       = "ALTERNATIVE"
}

# Change browser flow config to use github provider as default
#
resource "keycloak_authentication_execution_config" "config" {
  realm_id     = keycloak_realm.theia-cloud.id
  execution_id = keycloak_authentication_execution.browser.id
  alias        = "github"
  config = {
    defaultProvider = "github"
  }
}

# Install Theia Cloud
#
resource "helm_release" "theia-cloud" {
  count            = 1
  depends_on       = [helm_release.keycloak, helm_release.theia-cloud-crds]
  name             = "theia-cloud"
  repository       = "https://eclipse-theia.github.io/theia-cloud-helm"
  chart            = "theia-cloud"
  version          = "1.0.0"
  namespace        = "theia-cloud"
  create_namespace = true

  values = [
    "${file("${path.module}/theia-cloud.yaml")}"
  ]

  set_sensitive {
    name  = "keycloak.clientSecret"
    value = var.clientsecret
  }

  set_sensitive {
    name  = "keycloak.cookieSecret"
    value = var.cookiesecret
  }
}

# Configure service account
#
resource "kubectl_manifest" "cluster-role" {
  depends_on = [helm_release.theia-cloud-crds]
  yaml_body  = <<-EOF
  apiVersion: rbac.authorization.k8s.io/v1
  kind: ClusterRole
  metadata:
    name: custom-resource-manager
  rules:
    - apiGroups: ["theia.cloud"]
      resources: ["appdefinitions", "sessions"]
      verbs: ["get", "list", "create", "delete"]
  EOF
}
resource "kubectl_manifest" "cluster-role-binding" {
  depends_on = [kubectl_manifest.cluster-role]
  yaml_body  = <<-EOF
  apiVersion: rbac.authorization.k8s.io/v1
  kind: ClusterRoleBinding
  metadata:
    name: custom-resource-binding
  subjects:
    - kind: User
      name: "github-theia-preview-deployer@kubernetes-238012.iam.gserviceaccount.com"
      apiGroup: rbac.authorization.k8s.io
  roleRef:
    kind: ClusterRole
    name: custom-resource-manager
    apiGroup: rbac.authorization.k8s.io
  EOF
}
resource "kubectl_manifest" "github-deployer-sa" {
  yaml_body = <<-EOF
  apiVersion: v1
  kind: ServiceAccount
  metadata:
    name: github-deployer
    namespace: theia-cloud
    annotations:
      iam.gke.io/gcp-service-account: github-theia-preview-deployer@kubernetes-238012.iam.gserviceaccount.com
  EOF
}
resource "google_service_account_iam_binding" "workload-identity-binding" {
  service_account_id = "projects/kubernetes-238012/serviceAccounts/github-theia-preview-deployer@kubernetes-238012.iam.gserviceaccount.com"
  role               = "roles/iam.workloadIdentityUser"
  members = [
    "serviceAccount:kubernetes-238012.svc.id.goog[theia-cloud/github-deployer]"
  ]
}
