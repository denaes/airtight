terraform {
  backend "s3" {
    bucket = "state-c"
    key    = "p2.tfstate"
  }
}
