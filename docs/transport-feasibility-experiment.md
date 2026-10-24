# Hydra Transport Feasibility Experiment

## Question

Can a client send arbitrary bytes through a controlled intermediate node to a controlled origin, and can the test reliably detect blocked, corrupted, oversized, or unavailable paths?

This milestone demonstrates the data plane over a known, controlled TCP path. Only after this baseline is stable should Hydra investigate whether any real-world transport adapter is documented, authorized, and technically able to provide equivalent forwarding.

## Scope and boundaries

- Automated process tests use locally controlled nodes bound to loopback addresses only.
- The code rejects non-loopback listeners, destinations, and upstreams.
- It does not capture traffic, scan networks, log into third-party apps, or tunnel through third-party infrastructure.
- An application session or API connection does not establish permission or ability to forward arbitrary data.
- CRC-32 detects accidental corruption only. It is not authentication, encryption, or active-attacker protection.

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

## Procedure and success criteria

1. Verify that the graph model rejects service-specific API links and unknown links as generic relays.
2. Send several distinct binary payloads through client -> relay -> origin in one TCP session.
3. Verify per-frame checksums and exact byte equality for every response.
4. Verify that invalid markers, truncated frames, checksum mismatches, and over-limit lengths are rejected.
5. Verify that unavailable upstreams produce a framed error rather than a false success.
6. Verify that non-loopback destinations are refused by the experiment harness.
7. Run formatting, Clippy with warnings denied, and all unit/integration tests.

## Current limits

This local protocol validates data transport through an explicitly configured relay. It does not prove that any third-party app or restricted network can relay arbitrary data, or that such use is authorized. Every candidate transport requires a separate protocol, permission, and feasibility review.

## Next milestone

Add controlled fault injection for delayed responses, upstream truncation, and relay termination during a transfer. Verify that failures are reported distinctly and cannot be mistaken for successful payload delivery. Then define a transport-adapter interface that records relay capability, authorization, reliability, and restrictions.
