#!/bin/bash
# Generate a summary of the complete audio flow from source to edge

echo "Audio Flow Summary"
echo "=================="
echo
echo "Ingress Configuration:"
kubectl get ingress -n audio-lab -o custom-columns=NAME:.metadata.name,HOST:.spec.rules[0].host,BACKEND:.spec.rules[0].http.paths[0].backend.service.name,PORT:.spec.rules[0].http.paths[0].backend.service.port.number,ADDRESS:.status.loadBalancer.ingress[0].hostname
echo

echo "Audio Flow Path:"
echo "1. Browser → AWS ALB (*.elb.amazonaws.com:443)"
echo "2. AWS ALB → audio-relay pod (192.168.47.221:8001)"
echo "3. audio-source → audio-relay (internal pod-to-pod)"
echo "4. audio-relay → AWS ALB Internal IPs:"
echo "   - 192.168.49.132 (primary - 1048 events)"
echo "   - 192.168.24.161 (secondary - 30 events)"
echo "5. AWS ALB → Internet → Browser"
echo

echo "Confirmed Audio Signatures Reaching Edge:"
grep -h "192.168.49.132\|192.168.24.161" tmp/log*.txt 2>/dev/null | grep "audio-relay" | grep -oE '"signature":[0-9]+' | cut -d: -f2 | sort -u | wc -l
echo

echo "Sample Audio Signatures at Edge:"
grep -h "192.168.49.132\|192.168.24.161" tmp/log*.txt 2>/dev/null | grep "audio-relay" | grep -oE '"signature":[0-9]+' | cut -d: -f2 | sort -u | head -10