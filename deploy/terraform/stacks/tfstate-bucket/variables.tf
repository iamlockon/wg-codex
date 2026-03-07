variable "project_id" {
  description = "GCP project id where the Terraform state bucket is managed."
  type        = string
}

variable "bucket_name" {
  description = "Globally unique GCS bucket name for Terraform state."
  type        = string
}

variable "location" {
  description = "Bucket location/region."
  type        = string
  default     = "us-central1"
}

variable "enable_required_apis" {
  description = "Enable storage.googleapis.com if needed."
  type        = bool
  default     = true
}
