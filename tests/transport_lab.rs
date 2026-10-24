use hydra::{LinkCapability, NodeId, TransportGraph};

#[test]
fn a_long_graph_is_not_a_route_without_relay_capability_on_every_hop() {
    let mut graph = TransportGraph::new();
    graph.add_link("a", "b", LinkCapability::ArbitraryPayloadRelay);
    graph.add_link("b", "c", LinkCapability::FixedServiceApi);
    graph.add_link("c", "d", LinkCapability::ArbitraryPayloadRelay);
    graph.add_link("d", "origin", LinkCapability::ArbitraryPayloadRelay);

    assert!(graph
        .arbitrary_relay_path(&NodeId::from("a"), &NodeId::from("origin"))
        .is_none());
}

#[test]
fn alternate_verified_path_is_selected_when_available() {
    let mut graph = TransportGraph::new();
    graph.add_link("a", "b", LinkCapability::FixedServiceApi);
    graph.add_link("a", "c", LinkCapability::ArbitraryPayloadRelay);
    graph.add_link("c", "d", LinkCapability::ArbitraryPayloadRelay);
    graph.add_link("d", "origin", LinkCapability::ArbitraryPayloadRelay);

    assert_eq!(
        graph.arbitrary_relay_path(&NodeId::from("a"), &NodeId::from("origin")),
        Some(vec![
            NodeId::from("a"),
            NodeId::from("c"),
            NodeId::from("d"),
            NodeId::from("origin")
        ])
    );
}
