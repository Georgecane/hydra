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

## Transport-adapter policy

The adapter contract separates connectivity from the permission and capability to relay arbitrary payloads.

- Payload capability is one of ArbitraryPayload, FixedServiceApi, or Unknown.
- Authorization is one of ExplicitlyGranted, Denied, or Unknown.
- An adapter must be enabled and declare a positive per-message payload limit.
- Only ArbitraryPayload plus ExplicitlyGranted plus enabled plus a positive limit maps to an ArbitraryPayloadRelay graph edge.
- Fixed-service APIs are represented as FixedServiceApi edges, which the generic route finder does not traverse. All unknown, denied, or disabled cases are conservative and do not create generic-relay edges.
- The only executable adapter in this milestone is loopback TCP. There is no third-party adapter.

The CLI sender and integration test use the LoopbackTcpAdapter through the common TransportAdapter interface. Metadata policy tests verify that an adapter without explicit authorization cannot open a route.

## Route scoring and observed quality

A link has separate capability metadata and quality observations.

- Availability is Available, Unavailable, or Unknown. Only Available edges can be selected by the scored planner.
- Latency is an optional observed millisecond estimate. Missing latency receives a conservative 1000 ms estimate.
- Every edge declares its maximum payload size. An edge smaller than the request is excluded.
- Success and failure counters affect the route penalty. The initial model uses a failure-rate penalty in milliseconds; no observations receive a neutral uncertainty penalty.
- A completed successful local session updates an EWMA latency estimate, marks the link Available, increments successes, and resets the consecutive-failure count.
- A failed local session increments failures. One consecutive failure makes availability Unknown; two or more mark the link Unavailable until a later success.
- Availability observations expire after 30 seconds. Stale or missing timestamps are treated as Unknown.
- Stable node-name tie-breaking makes equal-cost route choices deterministic.

The planner uses only edges marked ArbitraryPayloadRelay by adapter policy. Fixed-service APIs, unknown capability, unknown or expired availability, and unavailable edges cannot complete a generic payload route. The old arbitrary_relay_path method remains a topology-only query and deliberately does not claim that links are currently online.

Loopback TCP records quality only in memory while its adapter instance exists. This is not persistent history or automatic external network measurement, and a route score is not a guarantee of real-world performance.

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

## Application-message bridge probe

The service bridge module tests a separate hypothesis from the generic TCP lab: can a documented, explicitly authorized, bidirectional application-message API carry a bounded binary payload in a user-controlled field and return it intact?

The prototype defines a fixed envelope with protocol version, session identifier, zero-based chunk sequence, total chunk count, Base64 payload, and CRC-32 checksum. It limits each session to 1 MiB and 4096 messages. The configured field limit applies to encoded payload characters; the real adapter must separately account for the complete API request size, rate limits, encoding rules, and response behavior.

The channel profile is rejected before sending unless the adapter is enabled, the API is documented, authorization is explicitly granted, both directions are available, a user-controlled payload field exists, and that field can hold at least one Base64 quantum. Responses with a wrong version, session, sequence, chunk count, Base64 encoding, checksum, or payload are rejected.

Current verification uses only a mock channel in unit tests. The tests cover chunked binary round trips and rejection of unknown authorization, one-way APIs, reordered responses, corrupt checksums, invalid payload encoding, missing capabilities, and oversized data.

This is not yet a third-party service adapter, a multi-hop network route, or evidence that a service like Rubika accepts arbitrary payloads. An ordinary app session does not provide arbitrary relay capability by itself. Any real adapter must use a documented interface, remain within its authorized behavior, and prove end-to-end return traffic before it can be considered further.

## Next milestone

Run the mock conformance suite in CI, then design an isolated integration test against a deliberately controlled message API that implements the same documented contract. Do not enable a real-world adapter or classify a fixed-service API as a generic relay unless independent experiments prove the exact capability and authorization required.
