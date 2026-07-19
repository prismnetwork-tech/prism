variable "aws_region" {
  type    = string
  default = "eu-central-1"
}

variable "environment" {
  type    = string
  default = "production"
}

variable "availability_zones" {
  type = list(string)

  validation {
    condition     = length(var.availability_zones) == 2
    error_message = "Exactly two availability zones are required."
  }
}

variable "database_url_secret_arn" {
  type = string
}

variable "control_plane_rpc_url_secret_arn" {
  type = string
}

variable "control_plane_auth_key_secret_arn" {
  type = string
}

variable "access_credential_key_secret_arn" {
  type = string
}

variable "node_registry_address" {
  type = string

  validation {
    condition     = can(regex("^0x[0-9a-fA-F]{40}$", var.node_registry_address))
    error_message = "node_registry_address must be a 20-byte EVM address."
  }
}

variable "control_plane_image" {
  type = string
}

variable "web_image" {
  type = string
}

variable "gateway_ami_id" {
  type = string
}

variable "gateway_instance_type" {
  type    = string
  default = "c7i.large"
}

variable "gateway_domain_name" {
  type = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]+[a-z0-9]$", var.gateway_domain_name))
    error_message = "gateway_domain_name must be a valid DNS name."
  }
}

variable "operator_subjects" {
  type    = list(string)
  default = []

  validation {
    condition = alltrue([
      for subject in var.operator_subjects :
      length(subject) >= 3 && length(subject) <= 255 && !strcontains(subject, ",")
    ])
    error_message = "operator_subjects entries must be 3 to 255 characters and cannot contain commas."
  }
}

variable "gateway_control_token_secret_arn" {
  type = string
}

variable "gateway_hmac_secret_arn" {
  type = string
}

variable "gateway_redis_url_secret_arn" {
  type = string
}

variable "privy_app_id_secret_arn" {
  type = string
}

variable "privy_verification_key_secret_arn" {
  type = string
}

variable "alchemy_api_key_secret_arn" {
  type = string
}

variable "alchemy_policy_id_secret_arn" {
  type = string
}

variable "wallet_auth_key_secret_arn" {
  type = string
}

variable "web_certificate_arn" {
  type = string
}

variable "proof_certificate_arn" {
  type = string
}

variable "gateway_observer_token_secret_arn" {
  type = string
}

variable "gateway_tls_certificate_secret_arn" {
  type = string
}

variable "gateway_tls_key_secret_arn" {
  type = string
}

variable "node_ca_certificate_secret_arn" {
  type = string
}

variable "node_ca_key_secret_arn" {
  type = string
}

variable "proof_domain_name" {
  type = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]+[a-z0-9]$", var.proof_domain_name))
    error_message = "proof_domain_name must be a valid DNS name."
  }
}

variable "lease_escrow_address" {
  type = string

  validation {
    condition     = can(regex("^0x[0-9a-fA-F]{40}$", var.lease_escrow_address))
    error_message = "lease_escrow_address must be a 20-byte EVM address."
  }
}

variable "proof_index_url" {
  type = string

  validation {
    condition     = can(regex("^https://", var.proof_index_url))
    error_message = "proof_index_url must use HTTPS."
  }
}
