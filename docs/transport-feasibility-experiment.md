# Hydra Transport Feasibility Experiment

## Question

Can a client send arbitrary bytes through a controlled intermediate node to a controlled origin, and can the test reliably detect blocked, corrupted, oversized, or unavailable paths?

This milestone is intentionally more modest than a real Meshnet. First demonstrate the data-plane behavior over a known, controlled TCP path. Only then investigate whether any real-world transport adapter is permitted and technically able to provide equivalent forwarding.

## Scope and boundaries

- The automated tests use locally controlled processes bound to loopback addresses only.
- The code rejects non-loopback listeners, destinations, and upstreams.
- It does not capture traffic, scan networks, log into third-party apps, or tunnel through third-party infrastructure.
- The existence of an application session or API connection does not establish permission or ability to forward arbitrary data.
- CRC-32 is used for accidental-corruption detection only. It is not cryptographic authentication, confidentiality, or protection against an active attacker.

## Topology

Client process -> relay process -> origin process

The origin echoes the verified payload. The relay reads a bounded request frame, forwards the payload to its explicitly configured upstream, checks the upstream response frame, and relays the response to the client. The client verifies that the returned payload is byte-for-byte identical to the original.

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
- N bytes: echoed payload on success; error responses carry no body

The receiver checks the advertised size before allocating the payload buffer. The default limit is 1 MiB and the hard maximum is 16 MiB. Read, write, and connection timeouts are set for every TCP stream. Each origin or relay serves one client and exits, keeping test runs deterministic.

## Procedure

1. Start an origin bound to 127.0.0.1.
2. Start a relay bound to 127.0.0.1 and configured to forward to that origin.
3. Send a binary payload from a separate client process.
4. Verify status, checksum, and exact byte equality at the client.
5. Repeat with an unavailable upstream and confirm a framed error rather than a false success.
6. Configure a small maximum and confirm oversized payloads are rejected before body allocation.
7. Run corruption, truncation, route-model, formatting, Clippy, and test checks.

## Success criteria

- Multi-process client -> relay -> origin transfer preserves all bytes.
- Binary values such as zero bytes and bytes above 127 are preserved.
- Invalid markers, truncated frames, checksum mismatches, and over-limit lengths are rejected.
- An unavailable upstream is reported as an error, not a successful transfer.
- Non-loopback destinations are refused by the experiment harness.
- CI passes formatting, Clippy with warnings denied, and all unit/integration tests.

## What this does not prove

Passing these tests proves that Hydra's controlled local protocol can forward bytes across the tested topology. It does not establish that a particular domestic service, third-party app, or network during an outage exposes a legitimate arbitrary-payload relay. Every candidate transport must be evaluated using documented behavior, authorization, and a separate test plan.

## Next milestone

After the local baseline is stable, add observability and fault injection: relay termination mid-transfer, delayed response, truncated upstream response, and repeatable multi-message sessions. Then design a transport-adapter interface that can represent link capability, consent, reliability, and restrictions without assuming every reachable endpoint can relay data.
