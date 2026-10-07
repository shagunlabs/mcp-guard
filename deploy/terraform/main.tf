# Skeleton only. No provider credentials, no backend, nothing applied.
terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}
variable "region" { default = "ap-south-1" }
module "control_plane" {
  source = "./modules/control-plane"
  region = var.region
}
