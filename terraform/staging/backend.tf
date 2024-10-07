terraform {
  backend "s3" {
    bucket = "global-terraform-state-storage"
    key    = "[key-name]/terraform.tfstate"
    region = "ap-south-1"
  }
}
