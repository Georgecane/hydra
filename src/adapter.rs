//! Transport adapter contract and authorization-aware capability metadata.
//!
//! The only executable adapter in this milestone is loopback TCP. Other transport
//! backends must provide explicit capability and authorization metadata before they
//! can be represented as generic arbitrary-payload relays.

use crate::transport::{
    send_session as send_tcp_session, FrameError, Response, Status, MAX_PAYLOAD_BYTES,
};
use crate::LinkCapability;
use std::net::SocketAddr;
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadCapability {
    /// The transport can carry arbitrary opaque byte payloads.
    ArbitraryPayload,
    /// The transport only supports a service-specific API or fixed message schema.
    FixedServiceApi,
    /// Payload-forwarding behavior has not been verified.
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationStatus {
    /// The owner/operator has explicitly authorized this adapter to relay.
    ExplicitlyGranted,
    /// The adapter is not permitted to relay for this purpose.
    Denied,
    /// Permission is not established.
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdapterDescriptor {
    pub id: &'static str,
    pub payload_capability: PayloadCapability,
    pub authorization: AuthorizationStatus,
    pub enabled: bool,
    /// Maximum supported payload size per message.
    pub max_payload_bytes: usize,
}

impl AdapterDescriptor {
    /// An adapter is eligible for a generic payload route only when all conditions pass.
    pub fn permits_arbitrary_payloads(&self) -> bool {
        self.enabled
            && self.payload_capability == PayloadCapability::ArbitraryPayload
            && self.authorization == AuthorizationStatus::ExplicitlyGranted
            && self.max_payload_bytes > 0
    }

    /// Conservative translation from adapter metadata to the graph's edge model.
    pub fn link_capability(&self) -> LinkCapability {
        if !self.enabled {
            LinkCapability::Unknown
        } else if self.payload_capability == PayloadCapability::FixedServiceApi {
            LinkCapability::FixedServiceApi
        } else if self.permits_arbitrary_payloads() {
            LinkCapability::ArbitraryPayloadRelay
        } else {
            LinkCapability::Unknown
        }
    }
}

/// A transport backend must describe itself and implement a bounded session operation.
/// Authorization/capability metadata is evaluated separately from mere connectivity.
pub trait TransportAdapter: Send + Sync {
    fn descriptor(&self) -> &AdapterDescriptor;

    fn send_session(
        &self,
        destination: SocketAddr,
        payloads: &[Vec<u8>],
        requested_max_payload_bytes: usize,
        timeout: Duration,
    ) -> Result<Vec<Response>, FrameError>;
}

/// Concrete TCP adapter reserved for the local experiment. Its transport implementation
/// rejects non-loopback destinations; it is not an Internet-facing TCP tunnel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoopbackTcpAdapter {
    descriptor: AdapterDescriptor,
}

impl Default for LoopbackTcpAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl LoopbackTcpAdapter {
    pub fn new() -> Self {
        Self {
            descriptor: AdapterDescriptor {
                id: "loopback-tcp",
                payload_capability: PayloadCapability::ArbitraryPayload,
                authorization: AuthorizationStatus::ExplicitlyGranted,
                enabled: true,
                max_payload_bytes: MAX_PAYLOAD_BYTES,
            },
        }
    }

    /// Override metadata for policy and rejection tests. The underlying endpoint remains
    /// loopback-only TCP regardless of the supplied descriptor.
    pub fn with_descriptor(descriptor: AdapterDescriptor) -> Self {
        Self { descriptor }
    }
}

impl TransportAdapter for LoopbackTcpAdapter {
    fn descriptor(&self) -> &AdapterDescriptor {
        &self.descriptor
    }

    fn send_session(
        &self,
        destination: SocketAddr,
        payloads: &[Vec<u8>],
        requested_max_payload_bytes: usize,
        timeout: Duration,
    ) -> Result<Vec<Response>, FrameError> {
        if !self.descriptor.permits_arbitrary_payloads() {
            return Err(FrameError {
                status: Status::UpstreamRejected,
                message: format!(
                    "adapter {:?} is disabled or is not explicitly authorized for arbitrary payloads",
                    self.descriptor.id
                ),
            });
        }

        let limit = requested_max_payload_bytes
            .min(self.descriptor.max_payload_bytes)
            .min(MAX_PAYLOAD_BYTES);
        if limit == 0 {
            return Err(FrameError {
                status: Status::InvalidFrame,
                message: "adapter payload limit must be greater than zero".to_owned(),
            });
        }

        send_tcp_session(destination, payloads, limit, timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TransportGraph;

    fn descriptor(
        capability: PayloadCapability,
        authorization: AuthorizationStatus,
        enabled: bool,
    ) -> AdapterDescriptor {
        AdapterDescriptor {
            id: "test-adapter",
            payload_capability: capability,
            authorization,
            enabled,
            max_payload_bytes: 4096,
        }
    }

    #[test]
    fn loopback_tcp_is_explicitly_authorized_and_bounded() {
        let adapter = LoopbackTcpAdapter::default();
        assert!(adapter.descriptor().permits_arbitrary_payloads());
        assert_eq!(
            adapter.descriptor().link_capability(),
            LinkCapability::ArbitraryPayloadRelay
        );
        assert_eq!(
            adapter.descriptor().max_payload_bytes,
            MAX_PAYLOAD_BYTES
        );
    }

    #[test]
    fn arbitrary_payload_requires_an_explicit_authorization_grant() {
        let unknown = descriptor(
            PayloadCapability::ArbitraryPayload,
            AuthorizationStatus::Unknown,
            true,
        );
        let denied = descriptor(
            PayloadCapability::ArbitraryPayload,
            AuthorizationStatus::Denied,
            true,
        );
        assert!(!unknown.permits_arbitrary_payloads());
        assert!(!denied.permits_arbitrary_payloads());
        assert_eq!(unknown.link_capability(), LinkCapability::Unknown);
        assert_eq!(denied.link_capability(), LinkCapability::Unknown);
    }

    #[test]
    fn fixed_service_api_is_never_classified_as_a_generic_relay() {
        let fixed = descriptor(
            PayloadCapability::FixedServiceApi,
            AuthorizationStatus::ExplicitlyGranted,
            true,
        );
        assert!(!fixed.permits_arbitrary_payloads());
        assert_eq!(fixed.link_capability(), LinkCapability::FixedServiceApi);
    }

    #[test]
    fn disabled_adapter_is_not_routable() {
        let disabled = descriptor(
            PayloadCapability::ArbitraryPayload,
            AuthorizationStatus::ExplicitlyGranted,
            false,
        );
        assert_eq!(disabled.link_capability(), LinkCapability::Unknown);
    }

    #[test]
    fn unauthorized_adapter_refuses_before_attempting_a_connection() {
        let adapter = LoopbackTcpAdapter::with_descriptor(descriptor(
            PayloadCapability::ArbitraryPayload,
            AuthorizationStatus::Unknown,
            true,
        ));
        let destination = "127.0.0.1:1".parse().unwrap();
        let result = adapter.send_session(
            destination,
            &[b"must not be sent".to_vec()],
            1024,
            Duration::from_millis(100),
        );
        assert_eq!(result.unwrap_err().status, Status::UpstreamRejected);
    }

    #[test]
    fn adapter_metadata_controls_graph_route_eligibility() {
        let trusted = LoopbackTcpAdapter::default();
        let uncertain = LoopbackTcpAdapter::with_descriptor(descriptor(
            PayloadCapability::ArbitraryPayload,
            AuthorizationStatus::Unknown,
            true,
        ));
        let mut graph = TransportGraph::new();
        graph.add_adapter_link("source", "trusted", &trusted);
        graph.add_adapter_link("trusted", "uncertain", &uncertain);
        graph.add_link("uncertain", "origin", LinkCapability::ArbitraryPayloadRelay);
        assert!(graph
            .arbitrary_relay_path(&crate::NodeId::from("source"), &crate::NodeId::from("origin"))
            .is_none());
    }
}
