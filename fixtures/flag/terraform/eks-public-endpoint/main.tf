resource "aws_eks_cluster" "a" {
  vpc_config {
    endpoint_public_access = true
    public_access_cidrs = ["0.0.0.0/0"]
  }
}
resource "aws_eks_cluster" "b" {
  vpc_config {
    endpoint_public_access = true
    public_access_cidrs = ["0.0.0.0/0"]
  }
}
resource "aws_eks_cluster" "c" {
  vpc_config {
    endpoint_public_access = true
    public_access_cidrs = ["0.0.0.0/0"]
  }
}
resource "aws_eks_cluster" "d" {
  vpc_config {
    endpoint_public_access = true
    public_access_cidrs = ["0.0.0.0/0"]
  }
}
