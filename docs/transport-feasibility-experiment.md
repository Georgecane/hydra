# Hydra Transport Feasibility Experiment

## Question

Can a client send arbitrary bytes through a controlled intermediate node to a controlled origin, and can the test reliably detect blocked, corrupted, oversized, delayed, truncated, or prematurely disconnected paths?

This milestone demonstrates the data plane over a known, controlled TCP path, then injects deliberate failures to verify that no failure is reported as a successful transfer.

## Scope and boundaries

- Automated process tests use locally controlled nodes bound to loopback addresses only.
- The code rejects non-loopback listeners, destinations, and upstreams.
- It does not capture traffic, scan networks, log into third-party apps, or tunnel through third-party infrastructure.
- An application session or API connection does not establish permission or ability to forward arbitrary data.
- CRC-32 detects accidental corruption only. It is not authentication, encryption, or active-attacker protection.
- Exactly one fault-injection option may be active on a node during a run.

## Topology

Client process -> relay process -> origin process

The origin echoes each verified payload. The relay validates a bounded request frame, forwards it to an explicitly configured upstream, validates the upstream response, and relays the response to the client. The client checks that every returned payload is byte-for-byte identical to its corresponding input.

## Frame format

Request frame:

- 4 bytes: request marker HYD1
- 8 bytes: payload length, unsigned big-endian
- 4 bytes: CRC-32, unsigned big-endian
- N bytes: payload

Response frame:

- 4 bytes: response marker HYA1
- 1 byte: status code
- 8 bytes: payload length, unsigned big-endian
- 4 bytes: CRC-32, unsigned big-endian
- N bytes: echoed payload on success; an error response carries no body

Receivers check advertised lengths before allocating a payload buffer. The per-frame default limit is 1 MiB and the hard maximum is 16 MiB. A TCP session supports at most 64 frames and at most 64 MiB of cumulative request data. Read, write, and connect timeouts are configured. The origin or relay serves one session per process, then exits.

## Run a four-frame local session

Start an origin:

    cargo run --bin hydra-lab -- origin --listen 127.0.0.1:4000 --messages 4

Start a relay:

    cargo run --bin hydra-lab -- relay --listen 127.0.0.1:4001 --upstream 127.0.0.1:4000 --messages 4

Send four frames:

    cargo run --bin hydra-lab -- send --connect 127.0.0.1:4001 --payload "hello Hydra" --messages 4

All three commands must use the same message count. The integration test uses separate client, relay, and origin processes and transfers several different binary payloads over a single client-to-relay socket and a reused relay-to-origin socket.

## Fault-injection matrix

Fault injection is opt-in, local-only, and intended for tests. Use only one fault-injection flag per node.

| Experiment | Setup | Expected observable result |
|---|---|---|
| Delayed response | Origin: --messages 1 --delay-ms 700 --timeout-ms 2000; relay: --messages 1 --timeout-ms 200 | Relay returns Timeout; client must not report success |
| Truncated upstream response | Origin: --messages 1 --truncate-response-bytes 7; relay: --messages 1 | Relay detects an incomplete response frame and returns UpstreamUnavailable |
| Mid-session disconnect | Origin: --messages 2; relay: --messages 4 --close-after-messages 2; client sends four frames | Client returns an error instead of accepting a shortened session as successful |

The automated tests use separate processes and loopback sockets. Each fault has a bounded timeout so test runs cannot wait indefinitely.

## Procedure and success criteria

1. Verify that the graph model rejects service-specific API links and unknown links as generic relays.
2. Send several distinct binary payloads through client -> relay -> origin in one TCP session.
3. Verify per-frame checksums and exact byte equality for every response.
4. Verify that invalid markers, truncated frames, checksum mismatches, and over-limit lengths are rejected.
5. Verify that unavailable upstreams produce a framed error rather than a false success.
6. Verify that delayed, truncated, and prematurely disconnected sessions are reported as failures.
7. Verify that non-loopback destinations are refused by the experiment harness.
8. Run formatting, Clippy with warnings denied, and all unit/integration tests.

## Current limits

This local protocol validates data transport through an explicitly configured relay and verifies selected failure modes. It does not prove that any third-party app or restricted network can relay arbitrary data, or that such use is authorized. Every candidate transport requires a separate protocol, permission, and feasibility review.

## Next milestone

Add a reusable transport-adapter trait and an in-memory fault model so link capability, authorization, reliability, and restrictions are represented explicitly. Keep any real-world adapter disabled until a documented, authorized transport has passed its own feasibility test.
