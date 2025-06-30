.PHONY: all build-ebpf build clean

all: build

build-ebpf:
	cargo build --package audio-latency-ebpf --target bpfel-unknown-none -Z build-std=core --release
	@mkdir -p target/bpf
	@cp target/bpfel-unknown-none/release/audio-latency-ebpf target/bpf/

build: build-ebpf
	cargo build --workspace --exclude audio-latency-ebpf

clean:
	cargo clean