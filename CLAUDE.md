# Audio Latency Tracker - Development Notes

## Project Overview
This project uses eBPF to capture audio signatures from network traffic and track latency between distributed audio processing components in Kubernetes.

## Current Architecture

### eBPF Component
- Captures TCP payload data
- Calculates audio signatures using rolling hash
- Reports events with: timestamp, signature, src_ip, dst_ip, src_port, dst_port

### Userspace Component
- Receives events from eBPF
- Logs structured JSON events
- Tracks signatures for local latency calculations

## Kubernetes Integration Plan

### Goal
Enrich audio signature logs with Kubernetes pod and workload information by maintaining a cluster-wide IP-to-pod mapping.

### Architecture Decision
- Watch ALL pods in the cluster (not just current node)
- Rationale: Both source and destination IPs could be any pod in the cluster
- Scale: ~30,000 pods = ~6MB memory (acceptable)

### Data Model
```rust
struct PodMetadata {
    pod_name: String,
    namespace: String,
    node_name: String,
    workload_kind: String,   // "Deployment", "DaemonSet", "StatefulSet"
    workload_name: String,   // Extracted from owner references
}

struct PodCache {
    ip_to_pod: HashMap<IpAddr, PodMetadata>,
}
```

### Implementation Steps
1. Add kube-rs dependency
2. Create PodWatcher component that:
   - Watches all pods in cluster
   - Maintains IP-to-pod cache
   - Handles pod lifecycle events (add/update/delete)
3. Extract workload info from owner references:
   - Pod → ReplicaSet → Deployment
   - Pod → DaemonSet
   - Pod → StatefulSet
4. Update event processing to enrich logs with pod/workload metadata

### Enhanced Log Format (Implemented)
With Kubernetes integration enabled, audio signature events now include pod metadata:

```json
{
  "timestamp": "2024-01-01T12:00:00.123456789Z",
  "level": "INFO",
  "fields": {
    "event_type": "audio_signature",
    "timestamp_ns": 1234567890,
    "signature": 12345,
    "node": "worker-1",
    "interface": "eth0",
    "src_ip": "10.0.1.5",
    "src_port": 8080,
    "src_pod": "audio-service-abc123",
    "src_namespace": "default",
    "src_workload": "Deployment/audio-service",
    "dst_ip": "10.0.2.7",
    "dst_port": 9090,
    "dst_pod": "audio-processor-def456",
    "dst_namespace": "default", 
    "dst_workload": "Deployment/audio-processor",
    "timestamp_human": "2024-01-01T12:00:00.123456789Z",
    "message": "Audio signature detected"
  }
}
```

### Implementation Details
- **Pod Watcher**: Watches all pods in the cluster (not just current node)
- **IP Cache**: Maintains in-memory map of IP addresses to pod metadata
- **Workload Extraction**: Automatically extracts Deployment/DaemonSet/StatefulSet names from owner references
- **Graceful Degradation**: If Kubernetes is unavailable or pod not found, logs continue without metadata
- **Auto-detection**: K8S_ENABLED automatically detects if running in Kubernetes

### Performance Considerations
- Pod watch is async and runs in separate task
- Cache lookups are O(1) HashMap operations
- Memory usage: ~200 bytes per pod × ~30k pods = ~6MB for large clusters

### Notes
- Ports help identify which container in multi-container pods (manual investigation)
- Pod IPs change slowly, watch events keep cache fresh
- Missing metadata handled gracefully (pod not found = log IP only)

## JSON Logging Format

All logs are now in JSONL format using tracing with JSON formatter. Each log line is a valid JSON object.

### Audio Signature Event Format
```json
{
  "timestamp": "2024-01-01T12:00:00.123456789Z",
  "level": "INFO",
  "fields": {
    "event_type": "audio_signature",
    "timestamp_ns": 1234567890,
    "signature": 12345,
    "node": "worker-1",
    "interface": "eth0",
    "src_ip": "10.0.1.5",
    "src_port": 8080,
    "dst_ip": "10.0.2.7",
    "dst_port": 9090,
    "timestamp_human": "2024-01-01T12:00:00.123456789Z",
    "message": "Audio signature detected"
  }
}
```

### Other Event Types
- `startup` - Application startup with configuration
- `startup_complete` - Application ready
- `tc_attached` - eBPF program attached to interface
- `latency_calculation` - Local latency calculation
- `metrics_server_error` - Metrics server errors
- `event_read_error` - eBPF event reading errors

This format makes it easy to:
- Filter by `event_type` 
- Parse and aggregate audio signatures
- Process with log aggregation tools (ELK, Loki, etc.)