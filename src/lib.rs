//! Hydra's first experiment: distinguish network reachability from relay capability.
//! This is a local simulator only; it does not inspect or tunnel through third-party services.

use std::collections::{HashMap, HashSet, VecDeque};

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

/// A directed, observed relationship between two nodes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Link {
    pub from: NodeId,
    pub to: NodeId,
    pub capability: LinkCapability,
}

/// Graph used by the feasibility experiment.
#[derive(Clone, Debug, Default)]
pub struct TransportGraph {
    links: Vec<Link>,
}

impl TransportGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_link(
        &mut self,
        from: impl Into<NodeId>,
        to: impl Into<NodeId>,
        capability: LinkCapability,
    ) {
        self.links.push(Link {
            from: from.into(),
            to: to.into(),
            capability,
        });
    }

    pub fn links(&self) -> &[Link] {
        &self.links
    }

    /// Finds a path only across links verified to relay arbitrary payloads.
    /// Fixed-service and unknown links are never treated as generic tunnels.
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
}
