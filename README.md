# Hydra

A decentralized, Rust-powered Meshnet designed to enable resilient connectivity and privacy-preserving data transport across existing network infrastructure, even when access to the public internet is restricted.

Hydra is experimental. Its first milestone tests a central assumption: **an existing connection is not automatically a general-purpose relay**.

## Current status

The repository contains a local transport-feasibility simulator. It does not yet build a live Meshnet, tunnel traffic, or integrate with third-party services.

## Run the experiment

Requires a stable Rust toolchain.

```sh
cargo run --bin hydra-lab
cargo test --all-targets
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
```

The demo models a service-specific API connection and reports that it cannot be treated as an arbitrary-payload route.

## Design principle

Hydra models each edge by what it is actually authorized and verified to do. A route is considered usable for arbitrary payloads only when every hop explicitly supports that behavior. A long graph of ordinary app connections does not, by itself, establish an end-to-end relay path.

## Experiment plan

See [the transport feasibility experiment](docs/transport-feasibility-experiment.md) for the hypothesis, graph model, test procedure, success criteria, and next milestone.

## License

Hydra is intended to use GPL-3.0-only. The full license text must be added before the first release.
