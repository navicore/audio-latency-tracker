# Audio Latency Tracker

[![Docker Build](https://github.com/YOUR_USERNAME/audio-latency-tracker/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/YOUR_USERNAME/audio-latency-tracker/actions/workflows/docker-publish.yml)
[![Docker Hub](https://img.shields.io/docker/v/YOUR_DOCKERHUB_USERNAME/audio-latency-tracker?label=docker&sort=semver)](https://hub.docker.com/r/YOUR_DOCKERHUB_USERNAME/audio-latency-tracker)

An eBPF-based audio latency tracking system for Kubernetes that monitors audio streams across distributed components and exports metrics to Prometheus.

## Features

- 🎵 **Audio Signature Detection**: Identifies unique audio patterns using configurable hashing algorithms
- 📊 **Latency Tracking**: Measures end-to-end latency between components
- 🐳 **Kubernetes Native**: Runs as a DaemonSet with automatic pod/container identification
- 📈 **Prometheus Metrics**: Exports detailed latency histograms and counters
- 🔧 **Configurable**: Fully customizable via environment variables
- 🚀 **High Performance**: Written in Rust with eBPF for minimal overhead

## Quick Start

### Using Helm (Recommended)

```bash
helm repo add YOUR_CHARTS_REPO https://YOUR_USERNAME.github.io/charts
helm install audio-latency-tracker YOUR_CHARTS_REPO/audio-latency-tracker \
  --namespace audio-latency-tracker \
  --create-namespace \
  --set config.audioPorts="8080,8081,8082"
```

### Using Docker

```bash
docker run --rm -it \
  --privileged \
  --network host \
  -e INTERFACE=eth0 \
  -e AUDIO_PORTS=8080,8081 \
  YOUR_DOCKERHUB_USERNAME/audio-latency-tracker:latest
```

## Configuration

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `INTERFACE` | Network interface to monitor | `eth0` |
| `LOG_LEVEL` | Logging level | `info` |
| `METRICS_PORT` | Prometheus metrics port | `9090` |
| `AUDIO_PORTS` | Comma-separated list of ports | all ports |
| `SIGNATURE_ALGORITHM` | Algorithm: rolling_hash, crc32, xxhash | `xxhash` |
| `SILENCE_THRESHOLD` | PCM silence threshold | `256` |

See [Configuration Documentation](docs/CONFIGURATION.md) for full list.

## Metrics

The tracker exports the following Prometheus metrics:

- `audio_latency_seconds` - Histogram of latency between components
- `audio_signatures_total` - Counter of signatures detected
- `audio_signature_collisions_total` - Counter of hash collisions

Example query for p99 latency:
```promql
histogram_quantile(0.99, 
  sum(rate(audio_latency_seconds_bucket[5m])) 
  by (source_pod, dest_pod, le))
```

## Building from Source

### Prerequisites

- Rust 1.70+ with nightly toolchain
- bpf-linker (`cargo install bpf-linker`)
- Docker (for container builds)

### Build

```bash
make build
```

### Test Locally

```bash
sudo ./target/debug/audio-latency -i lo
```

## Architecture

The system consists of:

1. **eBPF Program**: Attaches to TC ingress to inspect packets
2. **Userspace Daemon**: Processes events and maintains state
3. **Metrics Exporter**: Provides Prometheus endpoint

See [Architecture Documentation](docs/ARCHITECTURE.md) for details.

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

## License

Apache License 2.0 - see [LICENSE](LICENSE) file.

## Security

This tool requires privileged access to load eBPF programs. In Kubernetes, it needs:
- `CAP_BPF` (or `CAP_SYS_ADMIN` on older kernels)
- `CAP_NET_ADMIN`

See [Security Considerations](docs/SECURITY.md) for details.