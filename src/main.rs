use hydra::{LinkCapability, NodeId, TransportGraph};

fn main() {
    let mut graph = TransportGraph::new();
    // A can use this service's ordinary API, but that alone does not make it a generic relay.
    graph.add_link("user-a", "internal-service", LinkCapability::FixedServiceApi);
    graph.add_link(
        "internal-service",
        "public-origin",
        LinkCapability::ArbitraryPayloadRelay,
    );

    let source = NodeId::from("user-a");
    let destination = NodeId::from("public-origin");

    println!("Hydra transport feasibility lab");
    println!("Observed links: {}", graph.links().len());
    println!("Links with unknown capability: {}", graph.unknown_link_count());

    match graph.arbitrary_relay_path(&source, &destination) {
        Some(path) => {
            let rendered = path
                .iter()
                .map(|node| node.0.as_str())
                .collect::<Vec<_>>()
                .join(" -> ");
            println!("Verified arbitrary-payload path: {rendered}");
        }
        None => {
            println!("No verified arbitrary-payload path exists.");
            println!(
                "A service-specific connection is not evidence that the service can relay arbitrary traffic."
            );
        }
    }
}
