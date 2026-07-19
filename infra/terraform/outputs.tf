output "attestor_kms_key_arn" {
  value = aws_kms_key.attestor.arn
}

output "private_receipts_bucket" {
  value = aws_s3_bucket.private_receipts.id
}

output "public_proofs_bucket" {
  value = aws_s3_bucket.public_proofs.id
}

output "database_endpoint" {
  value     = aws_db_instance.main.address
  sensitive = true
}

output "web_load_balancer_dns_name" {
  value = aws_lb.web.dns_name
}

output "gateway_load_balancer_dns_name" {
  value = aws_lb.gateway.dns_name
}

output "public_proof_distribution_domain" {
  value = aws_cloudfront_distribution.proofs.domain_name
}
