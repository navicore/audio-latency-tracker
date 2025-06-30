# Build stage for eBPF
FROM rust:1.80 AS ebpf-builder

# Install dependencies for eBPF compilation
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libelf-dev \
    linux-headers-generic \
    && rm -rf /var/lib/apt/lists/*

# Install bpf-linker
RUN cargo install bpf-linker

# Install nightly toolchain with rust-src
RUN rustup toolchain install nightly-2024-06-01 && \
    rustup component add rust-src --toolchain nightly-2024-06-01

WORKDIR /build

# Copy workspace files
COPY Cargo.toml ./
COPY audio-latency-ebpf ./audio-latency-ebpf
COPY audio-latency ./audio-latency

# Generate Cargo.lock if it doesn't exist
RUN cargo generate-lockfile

# Build eBPF program
RUN cd audio-latency-ebpf && \
    cargo +nightly-2024-06-01 build \
    --target bpfel-unknown-none \
    -Z build-std=core \
    --release

# Build stage for userspace
FROM rust:1.80 AS userspace-builder

WORKDIR /build

# Copy workspace files
COPY Cargo.toml ./
COPY audio-latency ./audio-latency
COPY audio-latency-ebpf ./audio-latency-ebpf

# Generate Cargo.lock if it doesn't exist
RUN cargo generate-lockfile

# Create dummy eBPF output to satisfy build
RUN mkdir -p target/bpf && \
    touch target/bpf/audio-latency-ebpf

# Build userspace binary
RUN cargo build --release --package audio-latency

# Runtime stage - use debian-slim for flexibility
FROM debian:12-slim

# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Create directory structure
RUN mkdir -p /opt/audio-latency/target/bpf

# Copy eBPF program
COPY --from=ebpf-builder /build/target/bpfel-unknown-none/release/audio-latency-ebpf /opt/audio-latency/target/bpf/

# Copy userspace binary  
COPY --from=userspace-builder /build/target/release/audio-latency /opt/audio-latency/

WORKDIR /opt/audio-latency

# Expose metrics port
EXPOSE 9090

# Note: In k8s we'll run as root with specific capabilities
# The container needs CAP_BPF and CAP_NET_ADMIN

ENTRYPOINT ["/opt/audio-latency/audio-latency"]