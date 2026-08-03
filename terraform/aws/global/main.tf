terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
  required_version = ">= 1.6"
}

# IAM is a global service — region is only used for the provider; us-east-1 is standard.
provider "aws" { region = "us-east-1" }
