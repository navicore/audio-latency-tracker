#!/bin/bash
# Identify what system resources own the edge IPs where audio exits our cluster

echo "=== Identifying Edge IPs ==="
echo

# Extract unique edge IPs from logs
EDGE_IPS=$(grep -h "dst_pod.*unknown" tmp/log*.txt 2>/dev/null | grep -oE '"dst_ip":"[0-9.]+"' | cut -d'"' -f4 | sort -u)

echo "Edge IPs where audio exits the cluster:"
echo "$EDGE_IPS"
echo

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo "kubectl not found. Please run this on a machine with kubectl configured."
    exit 1
fi

echo "=== Checking Kubernetes Services ==="
kubectl get svc -A -o wide | grep -E "($(echo $EDGE_IPS | tr ' ' '|')|CLUSTER-IP)"
echo

echo "=== Checking Kubernetes Endpoints ==="
for ip in $EDGE_IPS; do
    echo "Checking endpoints for IP: $ip"
    kubectl get endpoints -A -o json | jq -r ".items[] | select(.subsets[]?.addresses[]?.ip == \"$ip\") | \"\(.metadata.namespace)/\(.metadata.name)\""
done
echo

echo "=== Checking Node IPs ==="
kubectl get nodes -o json | jq -r '.items[] | "\(.metadata.name): InternalIP=\(.status.addresses[] | select(.type=="InternalIP") | .address), ExternalIP=\(.status.addresses[] | select(.type=="ExternalIP") | .address // "none")"'
echo

echo "=== Checking AWS Load Balancers (if on AWS) ==="
# Check for AWS Load Balancer services
kubectl get svc -A -o json | jq -r '.items[] | select(.metadata.annotations."service.beta.kubernetes.io/aws-load-balancer-type" != null) | "\(.metadata.namespace)/\(.metadata.name): \(.spec.type) - \(.status.loadBalancer.ingress[]?.hostname // .status.loadBalancer.ingress[]?.ip // "pending")"'
echo

echo "=== Checking Ingress Controllers ==="
kubectl get ingress -A -o wide
echo

echo "=== Checking Services in audio-lab namespace ==="
kubectl get svc -n audio-lab -o wide
echo

echo "=== Checking if IPs are Service ClusterIPs ==="
for ip in $EDGE_IPS; do
    SERVICE=$(kubectl get svc -A -o json | jq -r ".items[] | select(.spec.clusterIP == \"$ip\") | \"\(.metadata.namespace)/\(.metadata.name) (ClusterIP)\"")
    if [ -n "$SERVICE" ]; then
        echo "$ip: $SERVICE"
    fi
done
echo

echo "=== Checking ConfigMaps for Load Balancer configs ==="
kubectl get cm -A | grep -E "(nginx|ingress|alb|elb|loadbalancer)" | head -10