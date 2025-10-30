# AWS Complete Example Outputs

output "cluster_name" {
  description = "EKS cluster name"
  value       = module.eks.cluster_name
}

output "cluster_endpoint" {
  description = "EKS cluster endpoint"
  value       = module.eks.cluster_endpoint
}

output "configure_kubectl" {
  description = "Command to configure kubectl"
  value       = module.eks.configure_kubectl
}

output "redis_endpoint" {
  description = "Redis primary endpoint"
  value       = module.redis.primary_endpoint_address
}

output "redis_port" {
  description = "Redis port"
  value       = module.redis.port
}

output "inferadb_namespace" {
  description = "Kubernetes namespace for InferaDB"
  value       = kubernetes_namespace.inferadb.metadata[0].name
}

output "inferadb_service_url" {
  description = "InferaDB service URL (after LoadBalancer is provisioned)"
  value       = "Check with: kubectl get svc -n inferadb inferadb -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'"
}

output "next_steps" {
  description = "Next steps after deployment"
  value = <<-EOT
    # Configure kubectl
    ${module.eks.configure_kubectl}

    # Verify cluster
    kubectl get nodes

    # Check InferaDB status
    kubectl get pods -n inferadb
    kubectl get svc -n inferadb

    # Get LoadBalancer URL
    kubectl get svc -n inferadb inferadb -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'

    # Test InferaDB
    curl -X POST http://<load-balancer-url>:8080/v1/check \
      -H "Content-Type: application/json" \
      -d '{"tuple": {"object": "doc:readme", "relation": "viewer", "subject": "user:alice"}}'
  EOT
}
