variable "region" {
  type        = string
  description = "AWS region for the instance and the image registry"
}

variable "profile" {
  type        = string
  description = "Local AWS CLI profile to deploy with"
  default     = null
}

variable "name" {
  type        = string
  description = "Name prefix and Project tag for everything created here"
  default     = "quantumguard"
}

variable "image_tag" {
  type        = string
  description = "Tag of the image pushed to the registry (the git commit)"
}

variable "instance_type" {
  type        = string
  description = "An arm64 instance type; the image is built for arm64"
  default     = "t4g.small"
}

variable "caddy_image" {
  type        = string
  description = "The reverse proxy image, pinned by digest (same digest as docker-compose.yml, from the AWS public mirror)"
  default     = "public.ecr.aws/docker/library/caddy@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d"
}

variable "demo" {
  type        = bool
  description = "Label the server as a demonstration server in the console"
  default     = true
}
