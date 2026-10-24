# Hydra

A decentralized, Rust-powered Meshnet designed to explore resilient connectivity and privacy-preserving data transport across existing network infrastructure, including environments where public internet access is restricted.

Hydra is experimental. It does not claim that ordinary app connections can automatically act as generic relays. The project tests this question in controlled stages.

## Current milestone

The repository now contains five experimental components:

1. A graph model that only recognizes edges with explicitly verified arbitrary-payload relay capability.
2. A real TCP payload test using three locally controlled nodes: a client, a relay, and an echo origin.
3. Fault injection for delayed replies, truncated response frames, and deliberate mid-session disconnects.
4. A transport-adapter contract requiring explicit payload-capability and authorization metadata.
5. A scored route planner that considers observed availability, latency, payload limits, and failure history.

The TCP lab is loopback-only and does not connect to external hosts or third-party applications.

## Run the local test

Install stable Rust, then run:

- cargo fmt --all -- --check
- cargo clippy --all-targets --all-features -- -D warnings
- cargo test --all-targets --all-features
- cargo run --bin hydra-lab -- help

## Run a three-node experiment manually

Start an origin in terminal 1:

    cargo run --bin hydra-lab -- origin --listen 127.0.0.1:4000 --messages 4

Start a relay in terminal 2:

    cargo run --bin hydra-lab -- relay --listen 127.0.0.1:4001 --upstream 127.0.0.1:4000 --messages 4

Send a payload from terminal 3:

    cargo run --bin hydra-lab -- send --connect 127.0.0.1:4001 --payload "hello Hydra" --messages 4

Each origin and relay serves one TCP session and then exits. Use the same --messages value for every node; it defaults to 1 and is capped at 64 frames per session. The relay reuses one upstream TCP connection for all frames. The sender reports PASS only when every echoed frame exactly matches the original payload.

To test a binary file, use the sender's --file ./payload.bin option instead of --payload. Multi-message CLI sessions repeat the selected file or text payload; the automated test also covers distinct binary frames.

## Fault-injection experiments

These flags are intended for the loopback test harness only. Configure one fault per node.

- Delayed origin: start the origin with --messages 1 --delay-ms 700 --timeout-ms 2000, then run the relay with --messages 1 --timeout-ms 200. The client should receive a Timeout response rather than a false success.
- Truncated origin response: start the origin with --messages 1 --truncate-response-bytes 7. The relay should detect the incomplete frame and return UpstreamUnavailable.
- Relay disconnect after two frames: set the origin to --messages 2 and the relay to --messages 4 --close-after-messages 2, then send four messages. The client must report that the session ended early.

## Route-scoring model

The route planner accepts a link only when its arbitrary-payload capability is verified, its availability observation is fresh and marked Available, and its payload limit covers the requested message. It ranks eligible paths by estimated latency plus a failure-history penalty. A successful local transfer updates the loopback adapter's in-memory latency and success counters; failures update the failure history. Observations expire after 30 seconds, after which availability becomes Unknown.

Metrics are held in memory only and are not persisted across runs. Hydra does not probe external networks or infer that a third-party service can relay data.

## Experiment guarantees and limits

- Only loopback IP addresses are accepted by this test harness.
- Payload and response lengths are bounded; the default maximum is 1 MiB and the hard cap is 16 MiB.
- A TCP session accepts up to 64 frames and 64 MiB of cumulative request data.
- Connection, read, and write timeouts are configured.
- Frames include CRC-32 checksums to detect accidental corruption. CRC-32 is not authentication or encryption.
- Relays forward data only to the explicitly configured local upstream.
- Only the loopback TCP adapter is executable in this milestone.
- An adapter is routable as an arbitrary relay only when it is enabled, explicitly authorized, supports arbitrary payloads, and declares a non-zero payload limit.
- Fixed-service APIs, unknown capabilities, denied permissions, and disabled adapters cannot create generic-relay edges.
- This milestone does not prove that any third-party service or restricted network can relay arbitrary data.

See the transport feasibility experiment in docs/transport-feasibility-experiment.md for the test matrix and next steps.

## License

GPL-3.0-only. See LICENSE.
