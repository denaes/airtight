terraform {
  backend "s3" {
    bucket = "state"
    key = "p.tfstate"
    encrypt = true
    kms_key_id = "arn:aws:kms:::key/x"
  }
}
