.PHONY: all build-ebpf build clean test docker-build docker-run

all: build

build-ebpf:
	cargo build --package audio-latency-ebpf --target bpfel-unknown-none -Z build-std=core --release
	@mkdir -p target/bpf
	@cp target/bpfel-unknown-none/release/audio-latency-ebpf target/bpf/

build: build-ebpf
	cargo build --workspace --exclude audio-latency-ebpf

test:
	cargo test --workspace --exclude audio-latency-ebpf -- --nocapture

clean:
	cargo clean

docker-build:
	docker build -t audio-latency-tracker:local .

docker-run:
	docker run --rm -it \
		--privileged \
		--network host \
		-v /sys/kernel/debug:/sys/kernel/debug:ro \
		audio-latency-tracker:local