terraform {
  backend "s3" {
    bucket = "state-b"
    key    = "p1.tfstate"
  }
}
