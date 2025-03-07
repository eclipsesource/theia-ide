terraform {
  backend "gcs" {
    bucket = "github-theia-ide-preview-terraform-remote-backend"
  }
}
