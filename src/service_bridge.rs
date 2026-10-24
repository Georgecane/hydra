//! Experimental application-message bridge contract.
//!
//! This module tests a narrow question: can an explicitly documented and authorized,
//! bidirectional application-message API carry bounded opaque bytes in a user-controlled
//! payload field and return them intact? It does not turn a service API into a generic
//! relay, and it ships no adapter for any third-party service.

use crate::adapter::AuthorizationStatus;
use crate::transport::checksum;

pub const MAX_BRIDGE_PAYLOAD_BYTES: usize = 1024 * 1024;
pub const MAX_BRIDGE_MESSAGES_PER_SESSION: usize = 4096;
const PROTOCOL_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceApiProfile {
    pub id: &'static str,
    pub enabled: bool,
    pub api_documented: bool,
    pub authorization: AuthorizationStatus,
    pub supports_outbound_messages: bool,
    pub supports_inbound_messages: bool,
    pub has_user_controlled_payload_field: bool,
    /// Maximum encoded characters in the user-controlled field, not the full API request.
    pub max_encoded_payload_chars: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeBlocker {
    Disabled,
    ApiNotDocumented,
    AuthorizationNotGranted,
    NotBidirectional,
    MissingUserControlledPayloadField,
    PayloadFieldTooSmall,
}

impl ServiceApiProfile {
    /// Return the first reason this channel cannot be used in the controlled bridge probe.
    pub fn bridge_blocker(&self) -> Option<BridgeBlocker> {
        if !self.enabled {
            Some(BridgeBlocker::Disabled)
        } else if !self.api_documented {
            Some(BridgeBlocker::ApiNotDocumented)
        } else if self.authorization != AuthorizationStatus::ExplicitlyGranted {
            Some(BridgeBlocker::AuthorizationNotGranted)
        } else if !self.supports_outbound_messages || !self.supports_inbound_messages {
            Some(BridgeBlocker::NotBidirectional)
        } else if !self.has_user_controlled_payload_field {
            Some(BridgeBlocker::MissingUserControlledPayloadField)
        } else if self.max_encoded_payload_chars < 4 {
            Some(BridgeBlocker::PayloadFieldTooSmall)
        } else {
            None
        }
    }

    /// Conservative raw-byte chunk limit for standard padded Base64.
    pub fn max_chunk_payload_bytes(&self) -> Option<usize> {
        if self.bridge_blocker().is_some() {
            return None;
        }
        Some((self.max_encoded_payload_chars / 4) * 3)
    }
}

/// Stable application-message fields for a bounded bridge experiment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceMessageEnvelope {
    pub protocol_version: u8,
    pub session_id: u64,
    /// Zero-based sequence number within the session.
    pub sequence: u32,
    pub total_chunks: u32,
    /// Base64 makes arbitrary binary input representable in a user-controlled text field.
    pub payload_base64: String,
    /// CRC-32 detects accidental corruption; it is not authentication.
    pub payload_checksum_crc32: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolViolation {
    WrongProtocolVersion,
    WrongSession,
    WrongSequence,
    WrongChunkCount,
    InvalidBase64,
    ChecksumMismatch,
    PayloadMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeError {
    Ineligible(BridgeBlocker),
    PayloadTooLarge,
    TooManyMessages,
    ChannelUnavailable,
    InvalidResponse(ProtocolViolation),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeResult {
    pub payload: Vec<u8>,
    pub messages_exchanged: usize,
}

/// Implement this only for an explicitly authorized, documented API.
///
/// A real adapter must encode the envelope into the actual documented schema, respect API
/// rate and size limits, and prove that replies can be received. The test suite uses a mock.
pub trait ServiceMessageChannel {
    fn profile(&self) -> &ServiceApiProfile;

    fn exchange(
        &mut self,
        envelope: &ServiceMessageEnvelope,
    ) -> Result<ServiceMessageEnvelope, BridgeError>;
}

/// Send a bounded payload through an application-message-shaped channel and reconstruct it
/// only if every reply has the expected session, order, chunk count, encoding and checksum.
pub fn round_trip_payload<C: ServiceMessageChannel>(
    channel: &mut C,
    session_id: u64,
    payload: &[u8],
) -> Result<BridgeResult, BridgeError> {
    let profile = *channel.profile();
    if let Some(reason) = profile.bridge_blocker() {
        return Err(BridgeError::Ineligible(reason));
    }
    if payload.len() > MAX_BRIDGE_PAYLOAD_BYTES {
        return Err(BridgeError::PayloadTooLarge);
    }
    if payload.is_empty() {
        return Ok(BridgeResult {
            payload: Vec::new(),
            messages_exchanged: 0,
        });
    }

    let chunk_limit = profile
        .max_chunk_payload_bytes()
        .ok_or(BridgeError::Ineligible(BridgeBlocker::PayloadFieldTooSmall))?;
    if chunk_limit == 0 {
        return Err(BridgeError::Ineligible(BridgeBlocker::PayloadFieldTooSmall));
    }
    let count = payload.len().div_ceil(chunk_limit);
    if count > MAX_BRIDGE_MESSAGES_PER_SESSION {
        return Err(BridgeError::TooManyMessages);
    }
    let total_chunks = u32::try_from(count).map_err(|_| BridgeError::TooManyMessages)?;
    let mut reconstructed = Vec::with_capacity(payload.len());

    for (index, chunk) in payload.chunks(chunk_limit).enumerate() {
        let request = ServiceMessageEnvelope {
            protocol_version: PROTOCOL_VERSION,
            session_id,
            sequence: u32::try_from(index).map_err(|_| BridgeError::TooManyMessages)?,
            total_chunks,
            payload_base64: encode_base64(chunk),
            payload_checksum_crc32: checksum(chunk),
        };
        let response = channel.exchange(&request)?;
        validate_response(&request, &response, chunk)?;
        let decoded = decode_base64(&response.payload_base64).ok_or(
            BridgeError::InvalidResponse(ProtocolViolation::InvalidBase64),
        )?;
        reconstructed.extend_from_slice(&decoded);
    }

    if reconstructed != payload {
        return Err(BridgeError::InvalidResponse(
            ProtocolViolation::PayloadMismatch,
        ));
    }

    Ok(BridgeResult {
        payload: reconstructed,
        messages_exchanged: count,
    })
}

fn validate_response(
    request: &ServiceMessageEnvelope,
    response: &ServiceMessageEnvelope,
    expected_payload: &[u8],
) -> Result<(), BridgeError> {
    if response.protocol_version != PROTOCOL_VERSION {
        return Err(BridgeError::InvalidResponse(
            ProtocolViolation::WrongProtocolVersion,
        ));
    }
    if response.session_id != request.session_id {
        return Err(BridgeError::InvalidResponse(
            ProtocolViolation::WrongSession,
        ));
    }
    if response.sequence != request.sequence {
        return Err(BridgeError::InvalidResponse(
            ProtocolViolation::WrongSequence,
        ));
    }
    if response.total_chunks != request.total_chunks {
        return Err(BridgeError::InvalidResponse(
            ProtocolViolation::WrongChunkCount,
        ));
    }

    let decoded = decode_base64(&response.payload_base64).ok_or(BridgeError::InvalidResponse(
        ProtocolViolation::InvalidBase64,
    ))?;
    if checksum(&decoded) != response.payload_checksum_crc32 {
        return Err(BridgeError::InvalidResponse(
            ProtocolViolation::ChecksumMismatch,
        ));
    }
    if decoded != expected_payload {
        return Err(BridgeError::InvalidResponse(
            ProtocolViolation::PayloadMismatch,
        ));
    }
    Ok(())
}

fn encode_base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);

    for chunk in input.chunks(3) {
        let a = chunk[0];
        let b = *chunk.get(1).unwrap_or(&0);
        let c = *chunk.get(2).unwrap_or(&0);
        output.push(TABLE[(a >> 2) as usize] as char);
        output.push(TABLE[(((a & 0x03) << 4) | (b >> 4)) as usize] as char);
        if chunk.len() > 1 {
            output.push(TABLE[(((b & 0x0f) << 2) | (c >> 6)) as usize] as char);
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(TABLE[(c & 0x3f) as usize] as char);
        } else {
            output.push('=');
        }
    }
    output
}

fn decode_base64(input: &str) -> Option<Vec<u8>> {
    fn value(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let bytes = input.as_bytes();
    let (blocks, remainder) = bytes.as_chunks::<4>();
    if !remainder.is_empty() {
        return None;
    }

    let mut output = Vec::with_capacity(blocks.len() * 3);
    let block_count = blocks.len();
    for (index, block) in blocks.iter().enumerate() {
        let last = index + 1 == block_count;
        if block[0] == b'=' || block[1] == b'=' {
            return None;
        }

        let a = value(block[0])?;
        let b = value(block[1])?;
        let pad_c = block[2] == b'=';
        let pad_d = block[3] == b'=';
        if pad_c && !pad_d {
            return None;
        }
        if !last && (pad_c || pad_d) {
            return None;
        }

        let c = if pad_c { 0 } else { value(block[2])? };
        let d = if pad_d { 0 } else { value(block[3])? };
        if pad_c && (b & 0x0f) != 0 {
            return None;
        }
        if !pad_c && pad_d && (c & 0x03) != 0 {
            return None;
        }

        output.push((a << 2) | (b >> 4));
        if !pad_c {
            output.push((b << 4) | (c >> 2));
        }
        if !pad_d {
            output.push((c << 6) | d);
        }
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    enum MockBehavior {
        Echo,
        WrongSequence,
        BadChecksum,
        CorruptPayload,
    }

    struct MockChannel {
        profile: ServiceApiProfile,
        behavior: MockBehavior,
        calls: usize,
    }

    impl MockChannel {
        fn authorized(max_encoded_payload_chars: usize) -> Self {
            Self {
                profile: ServiceApiProfile {
                    id: "mock-documented-message-api",
                    enabled: true,
                    api_documented: true,
                    authorization: AuthorizationStatus::ExplicitlyGranted,
                    supports_outbound_messages: true,
                    supports_inbound_messages: true,
                    has_user_controlled_payload_field: true,
                    max_encoded_payload_chars,
                },
                behavior: MockBehavior::Echo,
                calls: 0,
            }
        }
    }

    impl ServiceMessageChannel for MockChannel {
        fn profile(&self) -> &ServiceApiProfile {
            &self.profile
        }

        fn exchange(
            &mut self,
            envelope: &ServiceMessageEnvelope,
        ) -> Result<ServiceMessageEnvelope, BridgeError> {
            self.calls += 1;
            let mut response = envelope.clone();
            match self.behavior {
                MockBehavior::Echo => {}
                MockBehavior::WrongSequence => {
                    response.sequence = response.sequence.saturating_add(1)
                }
                MockBehavior::BadChecksum => response.payload_checksum_crc32 ^= 1,
                MockBehavior::CorruptPayload => response.payload_base64 = "!!!!".to_owned(),
            }
            Ok(response)
        }
    }

    #[test]
    fn application_shaped_channel_round_trips_binary_data_in_chunks() {
        let mut channel = MockChannel::authorized(8);
        let payload: Vec<u8> = (0..=255).collect();
        let result = round_trip_payload(&mut channel, 42, &payload).unwrap();

        assert_eq!(result.payload, payload);
        assert_eq!(result.messages_exchanged, 43);
        assert_eq!(channel.calls, result.messages_exchanged);
    }

    #[test]
    fn unknown_authorization_is_rejected_before_sending() {
        let mut channel = MockChannel::authorized(128);
        channel.profile.authorization = AuthorizationStatus::Unknown;

        assert_eq!(
            round_trip_payload(&mut channel, 1, b"never sent"),
            Err(BridgeError::Ineligible(
                BridgeBlocker::AuthorizationNotGranted
            ))
        );
        assert_eq!(channel.calls, 0);
    }

    #[test]
    fn one_way_api_is_not_a_bridge() {
        let mut channel = MockChannel::authorized(128);
        channel.profile.supports_inbound_messages = false;

        assert_eq!(
            round_trip_payload(&mut channel, 1, b"no return path"),
            Err(BridgeError::Ineligible(BridgeBlocker::NotBidirectional))
        );
        assert_eq!(channel.calls, 0);
    }

    #[test]
    fn wrong_sequence_is_rejected() {
        let mut channel = MockChannel::authorized(8);
        channel.behavior = MockBehavior::WrongSequence;

        assert_eq!(
            round_trip_payload(&mut channel, 7, b"sequence"),
            Err(BridgeError::InvalidResponse(
                ProtocolViolation::WrongSequence
            ))
        );
    }

    #[test]
    fn bad_checksum_is_rejected() {
        let mut channel = MockChannel::authorized(128);
        channel.behavior = MockBehavior::BadChecksum;

        assert_eq!(
            round_trip_payload(&mut channel, 7, b"checksum"),
            Err(BridgeError::InvalidResponse(
                ProtocolViolation::ChecksumMismatch
            ))
        );
    }

    #[test]
    fn invalid_payload_encoding_is_rejected() {
        let mut channel = MockChannel::authorized(128);
        channel.behavior = MockBehavior::CorruptPayload;

        assert_eq!(
            round_trip_payload(&mut channel, 7, b"base64"),
            Err(BridgeError::InvalidResponse(
                ProtocolViolation::InvalidBase64
            ))
        );
    }

    #[test]
    fn non_documented_or_missing_payload_fields_are_rejected() {
        let mut channel = MockChannel::authorized(128);
        channel.profile.api_documented = false;
        assert_eq!(
            channel.profile.bridge_blocker(),
            Some(BridgeBlocker::ApiNotDocumented)
        );

        channel.profile.api_documented = true;
        channel.profile.has_user_controlled_payload_field = false;
        assert_eq!(
            channel.profile.bridge_blocker(),
            Some(BridgeBlocker::MissingUserControlledPayloadField)
        );
    }

    #[test]
    fn oversized_payload_is_rejected_before_channel_use() {
        let mut channel = MockChannel::authorized(128);
        let payload = vec![0; MAX_BRIDGE_PAYLOAD_BYTES + 1];

        assert_eq!(
            round_trip_payload(&mut channel, 1, &payload),
            Err(BridgeError::PayloadTooLarge)
        );
        assert_eq!(channel.calls, 0);
    }
}
