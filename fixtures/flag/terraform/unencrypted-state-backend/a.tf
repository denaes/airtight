terraform {
  backend "s3" {
    bucket = "state-a"
    key    = "p0.tfstate"
  }
}
