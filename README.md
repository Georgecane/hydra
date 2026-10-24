# Hydra

A decentralized, Rust-powered Meshnet designed to explore resilient connectivity and privacy-preserving data transport across existing network infrastructure, including environments where public internet access is restricted.

Hydra is experimental. It does not claim that ordinary app connections can automatically act as generic relays. The project tests this question in controlled stages.

## Current milestone

The repository now contains two experiments:

1. A graph model that only recognizes edges with explicitly verified arbitrary-payload relay capability.
2. A real TCP payload test using three locally controlled nodes: a client, a relay, and an echo origin.

The TCP lab is loopback-only and does not connect to external hosts or third-party applications.

## Run the local test

Install stable Rust, then run:

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all-targets --all-features`
- `cargo run --bin hydra-lab -- help`

## Run a three-node experiment manually

Start an origin in terminal 1:

    cargo run --bin hydra-lab -- origin --listen 127.0.0.1:4000 --messages 4

Start a relay in terminal 2:

    cargo run --bin hydra-lab -- relay --listen 127.0.0.1:4001 --upstream 127.0.0.1:4000 --messages 4

Send a payload from terminal 3:

    cargo run --bin hydra-lab -- send --connect 127.0.0.1:4001 --payload "hello Hydra" --messages 4

Each origin and relay serves one TCP session and then exits. Use the same --messages value for every node; it defaults to 1 and is capped at 64 frames per session. The relay reuses one upstream TCP connection for all frames. The sender reports PASS only when every echoed frame exactly matches the original payload.

To test a binary file, use the sender's `--file ./payload.bin` option instead of `--payload`. Multi-message CLI sessions repeat the selected file or text payload; the automated test also covers distinct binary frames.

## Experiment guarantees and limits

- Only loopback IP addresses are accepted by this test harness.
- Payload and response lengths are bounded; the default maximum is 1 MiB and the hard cap is 16 MiB.
- Connection, read, and write timeouts are configured.
- Frames include CRC-32 checksums to detect accidental corruption. CRC-32 is not authentication or encryption.
- Relays forward data only to the explicitly configured local upstream.
- A service-specific API is not treated as an arbitrary data relay.
- This milestone does not prove that any third-party service or restricted network can relay arbitrary data.

See [the transport feasibility experiment](docs/transport-feasibility-experiment.md) for the test matrix and next steps.

## License

GPL-3.0-only. See LICENSE.
