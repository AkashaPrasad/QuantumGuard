output "registry" {
  value = local.registry
}

output "repository_url" {
  value = aws_ecr_repository.app.repository_url
}

output "instance_id" {
  value = aws_instance.backend.id
}

output "api_origin" {
  description = "The API's only public address; the web edge forwards /api/* and /healthz here"
  value       = aws_apigatewayv2_api.api.api_endpoint
}

output "edge_key" {
  description = "Shared key the web edge sends with every forwarded request"
  value       = random_password.edge_key.result
  sensitive   = true
}
