//! Hydra graph model, adapter policy, and conservative route planning.
//! All current executable transport experiments are restricted to local loopback endpoints.

pub mod adapter;
pub mod transport;

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

pub const DEFAULT_LINK_QUALITY_TTL: Duration = Duration::from_secs(30);

/// A node in the experiment graph. Nodes need not run Hydra.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct NodeId(pub String);

impl From<&str> for NodeId {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

/// What an observed connection actually permits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkCapability {
    /// Arbitrary opaque payload forwarding is explicitly verified and authorized.
    ArbitraryPayloadRelay,
    /// The link exposes only a fixed, service-specific API or message schema.
    FixedServiceApi,
    /// A route is visible, but payload forwarding has not been verified.
    Unknown,
}

/// Observed availability for route scoring. Unknown is never treated as available.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Availability {
    Available,
    Unavailable,
    Unknown,
}

/// Route-scoring evidence attached to a directed link.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkQuality {
    pub availability: Availability,
    /// Observed round-trip latency in milliseconds (EWMA after multiple samples).
    pub latency_ms: Option<u64>,
    /// Largest single payload supported on this edge.
    pub max_payload_bytes: usize,
    pub successes: u64,
    pub failures: u64,
    pub consecutive_failures: u32,
    /// Monotonic timestamp of the latest completed transfer observation.
    pub observed_at: Option<Instant>,
}

impl Default for LinkQuality {
    fn default() -> Self {
        Self {
            availability: Availability::Unknown,
            latency_ms: None,
            max_payload_bytes: 0,
            successes: 0,
            failures: 0,
            consecutive_failures: 0,
            observed_at: None,
        }
    }
}

impl LinkQuality {
    /// Record a fully successful transfer and update the latency estimate.
    pub fn record_success(&mut self, observed_at: Instant, latency_ms: u64) {
        let latency_ms = latency_ms.max(1);
        self.latency_ms = Some(match self.latency_ms {
            Some(previous) => previous
                .saturating_mul(7)
                .saturating_add(latency_ms)
                .checked_div(8)
                .unwrap_or(latency_ms)
                .max(1),
            None => latency_ms,
        });
        self.successes = self.successes.saturating_add(1);
        self.consecutive_failures = 0;
        self.availability = Availability::Available;
        self.observed_at = Some(observed_at);
    }

    /// Record a failed transfer. One failure makes availability Unknown; two
    /// consecutive failures mark the link Unavailable until a successful transfer.
    pub fn record_failure(&mut self, observed_at: Instant) {
        self.failures = self.failures.saturating_add(1);
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.availability = if self.consecutive_failures >= 2 {
            Availability::Unavailable
        } else {
            Availability::Unknown
        };
        self.observed_at = Some(observed_at);
    }

    /// Stale or missing observations never count as current availability evidence.
    pub fn effective_availability(&self, now: Instant, max_age: Duration) -> Availability {
        match self.observed_at {
            Some(observed_at) if now.saturating_duration_since(observed_at) <= max_age => {
                self.availability
            }
            _ => Availability::Unknown,
        }
    }

    /// Produces a conservative score in milliseconds from explicit observations.
    /// Unknown latency receives a 1000 ms estimate; failure history adds a penalty.
    fn estimated_cost_ms(&self) -> u64 {
        let latency = self.latency_ms.unwrap_or(1000).max(1);
        let trials = self.successes.saturating_add(self.failures);
        let failure_rate_per_mille = if trials == 0 {
            250
        } else {
            self.failures
                .saturating_mul(1000)
                .checked_div(trials)
                .unwrap_or(1000)
                .min(1000)
        };
        latency.saturating_add(failure_rate_per_mille.saturating_mul(5))
    }
}

/// A directed relationship between two nodes, with capability and observed quality.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Link {
    pub from: NodeId,
    pub to: NodeId,
    pub capability: LinkCapability,
    pub quality: LinkQuality,
}

/// Result of the best-path search, including its estimated cost and bottleneck size.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutePlan {
    pub nodes: Vec<NodeId>,
    pub estimated_cost_ms: u64,
    pub bottleneck_payload_bytes: usize,
}

/// Directed graph used by the feasibility experiment and route planner.
#[derive(Clone, Debug, Default)]
pub struct TransportGraph {
    links: Vec<Link>,
}

impl TransportGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a link whose live availability and quality have not yet been observed.
    pub fn add_link(
        &mut self,
        from: impl Into<NodeId>,
        to: impl Into<NodeId>,
        capability: LinkCapability,
    ) {
        self.add_observed_link(from, to, capability, LinkQuality::default());
    }

    pub fn add_observed_link(
        &mut self,
        from: impl Into<NodeId>,
        to: impl Into<NodeId>,
        capability: LinkCapability,
        quality: LinkQuality,
    ) {
        self.links.push(Link {
            from: from.into(),
            to: to.into(),
            capability,
            quality,
        });
    }

    /// Add an adapter edge based on its capability and authorization metadata.
    /// Its availability stays Unknown until a separate observation is recorded.
    pub fn add_adapter_link(
        &mut self,
        from: impl Into<NodeId>,
        to: impl Into<NodeId>,
        adapter: &dyn crate::adapter::TransportAdapter,
    ) {
        self.add_observed_adapter_link(from, to, adapter, LinkQuality::default());
    }

    /// Add an adapter edge with explicit, externally collected quality observations.
    pub fn add_observed_adapter_link(
        &mut self,
        from: impl Into<NodeId>,
        to: impl Into<NodeId>,
        adapter: &dyn crate::adapter::TransportAdapter,
        quality: LinkQuality,
    ) {
        self.add_observed_link(from, to, adapter.descriptor().link_capability(), quality);
    }

    pub fn links(&self) -> &[Link] {
        &self.links
    }

    /// Finds any path using only capability-verified arbitrary-payload links.
    /// This is a topology query and intentionally does not claim the links are online.
    pub fn arbitrary_relay_path(
        &self,
        source: &NodeId,
        destination: &NodeId,
    ) -> Option<Vec<NodeId>> {
        if source == destination {
            return Some(vec![source.clone()]);
        }

        let mut adjacency: HashMap<NodeId, Vec<NodeId>> = HashMap::new();
        for link in &self.links {
            if link.capability == LinkCapability::ArbitraryPayloadRelay {
                adjacency
                    .entry(link.from.clone())
                    .or_default()
                    .push(link.to.clone());
            }
        }

        let mut queue = VecDeque::from([source.clone()]);
        let mut previous: HashMap<NodeId, NodeId> = HashMap::new();
        let mut visited = HashSet::from([source.clone()]);

        while let Some(current) = queue.pop_front() {
            if let Some(neighbors) = adjacency.get(&current) {
                for neighbor in neighbors {
                    if visited.insert(neighbor.clone()) {
                        previous.insert(neighbor.clone(), current.clone());
                        if neighbor == destination {
                            let mut path = vec![destination.clone()];
                            let mut cursor = destination.clone();
                            while let Some(parent) = previous.get(&cursor) {
                                path.push(parent.clone());
                                cursor = parent.clone();
                            }
                            path.reverse();
                            return Some(path);
                        }
                        queue.push_back(neighbor.clone());
                    }
                }
            }
        }

        None
    }

    /// Find the least-cost route across observed, available, verified relay links.
    /// Edges that are Unknown, Unavailable, too small for the payload, or not
    /// authorized for arbitrary payloads are excluded.
    pub fn best_relay_path(
        &self,
        source: &NodeId,
        destination: &NodeId,
        required_payload_bytes: usize,
    ) -> Option<RoutePlan> {
        if source == destination {
            return Some(RoutePlan {
                nodes: vec![source.clone()],
                estimated_cost_ms: 0,
                bottleneck_payload_bytes: usize::MAX,
            });
        }
        if required_payload_bytes == 0 {
            return None;
        }

        let mut unvisited: HashSet<NodeId> = HashSet::from([source.clone(), destination.clone()]);
        for link in &self.links {
            unvisited.insert(link.from.clone());
            unvisited.insert(link.to.clone());
        }

        let observed_now = Instant::now();
        let mut distances: HashMap<NodeId, u64> = HashMap::new();
        let mut previous: HashMap<NodeId, (NodeId, usize)> = HashMap::new();
        distances.insert(source.clone(), 0);

        loop {
            let current = unvisited
                .iter()
                .filter_map(|node| distances.get(node).map(|cost| (node.clone(), *cost)))
                .min_by_key(|(node, cost)| (*cost, node.0.clone()));

            let Some((current, current_cost)) = current else {
                break;
            };
            unvisited.remove(&current);
            if current == *destination {
                break;
            }

            for (index, link) in self.links.iter().enumerate() {
                if link.from != current
                    || link.capability != LinkCapability::ArbitraryPayloadRelay
                    || link
                        .quality
                        .effective_availability(observed_now, DEFAULT_LINK_QUALITY_TTL)
                        != Availability::Available
                    || link.quality.max_payload_bytes < required_payload_bytes
                    || !unvisited.contains(&link.to)
                {
                    continue;
                }

                let candidate = current_cost.saturating_add(link.quality.estimated_cost_ms());
                let improves = distances
                    .get(&link.to)
                    .is_none_or(|existing| candidate < *existing);
                if improves {
                    distances.insert(link.to.clone(), candidate);
                    previous.insert(link.to.clone(), (current.clone(), index));
                }
            }
        }

        let total_cost = *distances.get(destination)?;
        let mut nodes = vec![destination.clone()];
        let mut edge_indices = Vec::new();
        let mut cursor = destination.clone();
        while cursor != *source {
            let (parent, edge_index) = previous.get(&cursor)?.clone();
            nodes.push(parent.clone());
            edge_indices.push(edge_index);
            cursor = parent;
        }
        nodes.reverse();
        edge_indices.reverse();

        let bottleneck_payload_bytes = edge_indices
            .iter()
            .map(|index| self.links[*index].quality.max_payload_bytes)
            .min()
            .unwrap_or(usize::MAX);

        Some(RoutePlan {
            nodes,
            estimated_cost_ms: total_cost,
            bottleneck_payload_bytes,
        })
    }

    pub fn unknown_link_count(&self) -> usize {
        self.links
            .iter()
            .filter(|link| link.capability == LinkCapability::Unknown)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quality(
        availability: Availability,
        latency_ms: u64,
        max_payload_bytes: usize,
        successes: u64,
        failures: u64,
    ) -> LinkQuality {
        LinkQuality {
            availability,
            latency_ms: Some(latency_ms),
            max_payload_bytes,
            successes,
            failures,
            consecutive_failures: 0,
            observed_at: Some(Instant::now()),
        }
    }

    #[test]
    fn fixed_service_api_is_not_a_generic_relay() {
        let mut graph = TransportGraph::new();
        graph.add_link("user-a", "service", LinkCapability::FixedServiceApi);
        graph.add_link(
            "service",
            "public-server",
            LinkCapability::ArbitraryPayloadRelay,
        );

        assert!(graph
            .arbitrary_relay_path(&NodeId::from("user-a"), &NodeId::from("public-server"))
            .is_none());
    }

    #[test]
    fn verified_relay_links_form_a_path() {
        let mut graph = TransportGraph::new();
        graph.add_link("user-a", "relay-b", LinkCapability::ArbitraryPayloadRelay);
        graph.add_link("relay-b", "relay-c", LinkCapability::ArbitraryPayloadRelay);
        graph.add_link("relay-c", "origin", LinkCapability::ArbitraryPayloadRelay);

        assert_eq!(
            graph.arbitrary_relay_path(&NodeId::from("user-a"), &NodeId::from("origin")),
            Some(vec![
                NodeId::from("user-a"),
                NodeId::from("relay-b"),
                NodeId::from("relay-c"),
                NodeId::from("origin")
            ])
        );
    }

    #[test]
    fn unknown_links_are_not_assumed_to_forward_payloads() {
        let mut graph = TransportGraph::new();
        graph.add_link("user-a", "service", LinkCapability::Unknown);

        assert!(graph
            .arbitrary_relay_path(&NodeId::from("user-a"), &NodeId::from("service"))
            .is_none());
        assert_eq!(graph.unknown_link_count(), 1);
    }

    #[test]
    fn source_to_itself_has_a_zero_hop_path() {
        let graph = TransportGraph::new();
        let source = NodeId::from("user-a");

        assert_eq!(
            graph.arbitrary_relay_path(&source, &source),
            Some(vec![source])
        );
    }

    #[test]
    fn best_route_prefers_the_lower_cost_available_path() {
        let mut graph = TransportGraph::new();
        graph.add_observed_link(
            "source",
            "origin",
            LinkCapability::ArbitraryPayloadRelay,
            quality(Availability::Available, 900, 4096, 100, 0),
        );
        graph.add_observed_link(
            "source",
            "relay",
            LinkCapability::ArbitraryPayloadRelay,
            quality(Availability::Available, 20, 2048, 100, 0),
        );
        graph.add_observed_link(
            "relay",
            "origin",
            LinkCapability::ArbitraryPayloadRelay,
            quality(Availability::Available, 30, 1024, 100, 0),
        );

        let plan = graph
            .best_relay_path(&NodeId::from("source"), &NodeId::from("origin"), 512)
            .unwrap();
        assert_eq!(
            plan.nodes,
            vec![
                NodeId::from("source"),
                NodeId::from("relay"),
                NodeId::from("origin")
            ]
        );
        assert_eq!(plan.estimated_cost_ms, 50);
        assert_eq!(plan.bottleneck_payload_bytes, 1024);
    }

    #[test]
    fn best_route_excludes_unknown_unavailable_and_undersized_links() {
        let mut graph = TransportGraph::new();
        graph.add_observed_link(
            "source",
            "unknown",
            LinkCapability::ArbitraryPayloadRelay,
            quality(Availability::Unknown, 1, 4096, 20, 0),
        );
        graph.add_observed_link(
            "source",
            "offline",
            LinkCapability::ArbitraryPayloadRelay,
            quality(Availability::Unavailable, 1, 4096, 10, 10),
        );
        graph.add_observed_link(
            "source",
            "small",
            LinkCapability::ArbitraryPayloadRelay,
            quality(Availability::Available, 1, 8, 10, 0),
        );
        graph.add_observed_link(
            "unknown",
            "origin",
            LinkCapability::ArbitraryPayloadRelay,
            quality(Availability::Available, 1, 4096, 10, 0),
        );
        graph.add_observed_link(
            "offline",
            "origin",
            LinkCapability::ArbitraryPayloadRelay,
            quality(Availability::Available, 1, 4096, 10, 0),
        );
        graph.add_observed_link(
            "small",
            "origin",
            LinkCapability::ArbitraryPayloadRelay,
            quality(Availability::Available, 1, 4096, 10, 0),
        );

        assert!(graph
            .best_relay_path(&NodeId::from("source"), &NodeId::from("origin"), 16)
            .is_none());
    }

    #[test]
    fn repeated_failures_increase_path_cost() {
        let mut graph = TransportGraph::new();
        graph.add_observed_link(
            "source",
            "origin",
            LinkCapability::ArbitraryPayloadRelay,
            quality(Availability::Available, 50, 4096, 0, 100),
        );
        graph.add_observed_link(
            "source",
            "relay",
            LinkCapability::ArbitraryPayloadRelay,
            quality(Availability::Available, 100, 4096, 100, 0),
        );
        graph.add_observed_link(
            "relay",
            "origin",
            LinkCapability::ArbitraryPayloadRelay,
            quality(Availability::Available, 100, 4096, 100, 0),
        );

        let plan = graph
            .best_relay_path(&NodeId::from("source"), &NodeId::from("origin"), 1024)
            .unwrap();
        assert_eq!(
            plan.nodes,
            vec![
                NodeId::from("source"),
                NodeId::from("relay"),
                NodeId::from("origin")
            ]
        );
    }

    #[test]
    fn link_quality_expires_to_unknown_after_the_ttl() {
        let mut quality = LinkQuality::default();
        quality.max_payload_bytes = 4096;
        let observed_at = Instant::now() - Duration::from_secs(31);
        quality.record_success(observed_at, 25);
        assert_eq!(
            quality.effective_availability(Instant::now(), DEFAULT_LINK_QUALITY_TTL),
            Availability::Unknown
        );
    }

    #[test]
    fn repeated_failures_mark_unavailable_and_success_restores_availability() {
        let mut quality = LinkQuality::default();
        quality.max_payload_bytes = 4096;
        let start = Instant::now();
        quality.record_failure(start);
        assert_eq!(quality.availability, Availability::Unknown);
        quality.record_failure(start + Duration::from_millis(1));
        assert_eq!(quality.availability, Availability::Unavailable);
        quality.record_success(start + Duration::from_millis(2), 100);
        assert_eq!(quality.availability, Availability::Available);
        assert_eq!(quality.consecutive_failures, 0);
        assert_eq!(quality.successes, 1);
        assert_eq!(quality.failures, 2);
        assert_eq!(quality.latency_ms, Some(100));
    }

    #[test]
    fn an_adapter_without_availability_observations_is_not_route_ready() {
        let mut graph = TransportGraph::new();
        let adapter = crate::adapter::LoopbackTcpAdapter::default();
        graph.add_adapter_link("source", "origin", &adapter);
        assert!(graph
            .best_relay_path(&NodeId::from("source"), &NodeId::from("origin"), 1)
            .is_none());
    }
}
