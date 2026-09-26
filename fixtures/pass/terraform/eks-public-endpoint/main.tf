resource "aws_eks_cluster" "a" {
  vpc_config {
    endpoint_public_access = false
    endpoint_private_access = true
  }
}
resource "aws_eks_cluster" "b" {
  vpc_config {
    endpoint_public_access = true
    public_access_cidrs = ["203.0.113.0/24"]
  }
}
resource "aws_eks_cluster" "c" {
  vpc_config {
    endpoint_private_access = true
  }
}
resource "aws_eks_cluster" "d" {
  vpc_config {
    public_access_cidrs = [var.office]
  }
}
resource "aws_eks_cluster" "e" {
  name = "c"
}
