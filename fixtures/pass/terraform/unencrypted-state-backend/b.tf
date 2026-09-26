terraform {
  backend "s3" {
    bucket = "state2"
    encrypt = true
    dynamodb_table = "locks"
  }
}
