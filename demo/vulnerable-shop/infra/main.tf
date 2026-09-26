resource "aws_security_group" "web" {
  name = "web"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "invoices" {
  bucket = "shop-invoices"
  acl    = "public-read"
}

resource "aws_db_instance" "main" {
  engine              = "postgres"
  publicly_accessible = true
  storage_encrypted   = false
  password            = "hunter2hunter2"
}

resource "aws_iam_policy" "app" {
  policy = <<POLICY
{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}
POLICY
}
