# cargo clean -p axon-runtime-ebpf
cargo build 

RUST_LOG=info cargo run --config 'target."cfg(all())".runner="sudo -E"'
RUST_LOG=info cargo run --config 'target."cfg(all())".runner="sudo -E"' -- -i wlp8s0
