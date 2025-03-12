output "nginx_ip" {
  value = google_compute_address.host_ip.address
}

output "keycloak" {
  value = "https://theia-ide-preview.eclipsesource-munich.com/keycloak"
}

output "launch_page" {
  value = "https://launch.theia-ide-preview.eclipsesource-munich.com"
}
