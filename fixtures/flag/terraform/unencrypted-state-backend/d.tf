terraform {
  backend "s3" {
    bucket = "state-d"
    key    = "p3.tfstate"
  }
}
