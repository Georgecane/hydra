# Hydra Transport Feasibility Experiment

## Question

Can a graph assembled from existing network relationships carry arbitrary end-to-end payloads when intermediate devices do not run Hydra?

This experiment separates **reachability** from **relay capability**. Seeing that a client can reach an application's service, and seeing that the service can reach another network, does not prove that the service will forward arbitrary data between those connections.

## Safety and scope

- Use a local simulator and endpoints you control or have explicit permission to test.
- Do not use a third-party app's session, API, or infrastructure as an undisclosed tunnel.
- Do not infer generic relay capability from a successful login, API call, or ordinary app connection.
- The current prototype performs no packet capture, network scanning, third-party integration, or real traffic forwarding.

## Model

Each directed edge has one of three capabilities:

- **ArbitraryPayloadRelay:** forwarding arbitrary opaque payloads has been explicitly verified and is authorized.
- **FixedServiceApi:** the connection supports only a documented, service-specific operation or schema.
- **Unknown:** the available evidence does not establish relay behavior.

The route finder uses only ArbitraryPayloadRelay edges. This conservative rule prevents the experiment from confusing an application-level connection with a general-purpose transport.

## Procedure

1. Model a source, a service endpoint, and an external origin.
2. Mark the source-to-service edge FixedServiceApi and the service-to-origin edge ArbitraryPayloadRelay.
3. Run the route finder. Expected result: no end-to-end arbitrary-payload route.
4. Replace every edge on a test path with an authorized, verified relay edge.
5. Run the route finder again. Expected result: the path is found.
6. Add an alternate verified path and confirm that the algorithm can find it when another branch is unusable.
7. Keep real-world testing separate and require explicit authorization for every relay endpoint.

## Current success criteria

- Fixed-service and unknown links are never treated as generic relays.
- A path is returned only if every hop is an authorized, verified arbitrary-payload relay.
- A longer graph with one non-relay edge is correctly rejected.
- An alternate verified path can be found.

## What this experiment cannot prove

This simulation does not prove that any particular app or domestic network can relay arbitrary payloads, that a route exists during a blackout, or that Hydra can reach an origin without a physical or logical data path. It validates only the graph model and its assumptions.

## Next experiment

Implement an in-memory, multi-hop payload test using three locally controlled processes. Give each relay an explicit opt-in protocol, bounded message sizes, end-to-end integrity checks, timeouts, and observable failure reporting. Only after this passes should the project compare authorized transport adapters.
