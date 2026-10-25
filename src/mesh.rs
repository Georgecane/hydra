//! Encrypted, bounded Meshnet packet format and hop-by-hop router.
//!
//! Payloads are protected end-to-end with ChaCha20-Poly1305. Forwarding fields (previous
//! hop and hop limit) remain mutable so relays can forward ciphertext without the key.
//! CRC-32 is an early corruption check, not a security mechanism.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::time::{Duration, Instant};

use crate::transport::checksum;

const MAGIC: &[u8; 4] = b"HYM1";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 132;
const TRAILER_LEN: usize = 4;
pub const MAX_CIPHERTEXT_BYTES: usize = 60 * 1024;
pub const MAX_PLAINTEXT_BYTES: usize = MAX_CIPHERTEXT_BYTES - 16;
pub const DEFAULT_REPLAY_CACHE_CAPACITY: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MeshNodeId(pub [u8; 32]);

impl MeshNodeId {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn to_hex(self) -> String {
        let mut output = String::with_capacity(64);
        for byte in self.0 {
            use fmt::Write as _;
            let _ = write!(output, "{byte:02x}");
        }
        output
    }
}

impl fmt::Display for MeshNodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum FrameKind {
    Data = 1,
    Acknowledgement = 2,
    RouteAdvertisement = 3,
    Discovery = 4,
}

impl TryFrom<u8> for FrameKind {
    type Error = MeshError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Data),
            2 => Ok(Self::Acknowledgement),
            3 => Ok(Self::RouteAdvertisement),
            4 => Ok(Self::Discovery),
            _ => Err(MeshError::UnknownFrameKind),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeshFrame {
    pub kind: FrameKind,
    pub flags: u8,
    pub hop_limit: u8,
    pub source: MeshNodeId,
    pub destination: MeshNodeId,
    pub previous_hop: MeshNodeId,
    pub packet_id: u64,
    pub sequence: u32,
    pub nonce: [u8; 12],
    /// AEAD ciphertext including its 16-byte authentication tag.
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MeshError {
    RandomnessUnavailable,
    PayloadTooLarge,
    FrameTooShort,
    FrameTooLarge,
    InvalidMagic,
    UnsupportedVersion,
    UnknownFrameKind,
    LengthMismatch,
    ChecksumMismatch,
    AuthenticationFailed,
    HopLimitExceeded,
    NoRoute,
    InvalidRoute,
    RouteLoop,
    DuplicatePacket,
    InvalidReplayCacheCapacity,
}

impl fmt::Display for MeshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::RandomnessUnavailable => "secure random nonce generation failed",
            Self::PayloadTooLarge => "mesh payload exceeds the configured bound",
            Self::FrameTooShort => "mesh frame is shorter than its minimum size",
            Self::FrameTooLarge => "mesh frame exceeds the configured bound",
            Self::InvalidMagic => "mesh frame has an invalid magic marker",
            Self::UnsupportedVersion => "mesh frame protocol version is unsupported",
            Self::UnknownFrameKind => "mesh frame kind is unknown",
            Self::LengthMismatch => "mesh frame length does not match its header",
            Self::ChecksumMismatch => "mesh frame CRC-32 check failed",
            Self::AuthenticationFailed => "mesh packet authentication failed",
            Self::HopLimitExceeded => "mesh packet hop limit is exhausted",
            Self::NoRoute => "no fresh route is available for mesh destination",
            Self::InvalidRoute => "mesh route has invalid parameters",
            Self::RouteLoop => "mesh route would immediately return to its previous hop",
            Self::DuplicatePacket => "duplicate mesh packet was suppressed",
            Self::InvalidReplayCacheCapacity => "replay cache capacity must be non-zero",
        };
        f.write_str(message)
    }
}
impl std::error::Error for MeshError {}

/// A traffic key shared by the intended source and destination.
/// Key exchange, identity authentication, and key rotation are separate future work;
/// do not reuse the same key across unrelated peers.
pub struct MeshCipher {
    cipher: ChaCha20Poly1305,
}

impl MeshCipher {
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new_from_slice(key)
                .expect("ChaCha20-Poly1305 accepts exactly 32 key bytes"),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn seal(
        &self,
        kind: FrameKind,
        flags: u8,
        hop_limit: u8,
        source: MeshNodeId,
        destination: MeshNodeId,
        previous_hop: MeshNodeId,
        packet_id: u64,
        sequence: u32,
        plaintext: &[u8],
    ) -> Result<MeshFrame, MeshError> {
        if plaintext.len() > MAX_PLAINTEXT_BYTES {
            return Err(MeshError::PayloadTooLarge);
        }
        let mut nonce = [0_u8; 12];
        getrandom::fill(&mut nonce).map_err(|_| MeshError::RandomnessUnavailable)?;
        let aad = associated_data(kind, flags, source, destination, packet_id, sequence);
        let ciphertext = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| MeshError::AuthenticationFailed)?;

        Ok(MeshFrame {
            kind,
            flags,
            hop_limit,
            source,
            destination,
            previous_hop,
            packet_id,
            sequence,
            nonce,
            ciphertext,
        })
    }

    pub fn open(&self, frame: &MeshFrame) -> Result<Vec<u8>, MeshError> {
        if frame.ciphertext.len() > MAX_CIPHERTEXT_BYTES {
            return Err(MeshError::PayloadTooLarge);
        }
        let aad = associated_data(
            frame.kind,
            frame.flags,
            frame.source,
            frame.destination,
            frame.packet_id,
            frame.sequence,
        );
        self.cipher
            .decrypt(
                Nonce::from_slice(&frame.nonce),
                Payload {
                    msg: &frame.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| MeshError::AuthenticationFailed)
    }
}

fn associated_data(
    kind: FrameKind,
    flags: u8,
    source: MeshNodeId,
    destination: MeshNodeId,
    packet_id: u64,
    sequence: u32,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(83);
    aad.extend_from_slice(MAGIC);
    aad.push(VERSION);
    aad.push(kind as u8);
    aad.push(flags);
    aad.extend_from_slice(&source.0);
    aad.extend_from_slice(&destination.0);
    aad.extend_from_slice(&packet_id.to_be_bytes());
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad
}

impl MeshFrame {
    /// Forward unchanged end-to-end ciphertext while updating hop-local fields.
    pub fn forwarded_by(&self, relay: MeshNodeId) -> Result<Self, MeshError> {
        if self.hop_limit == 0 {
            return Err(MeshError::HopLimitExceeded);
        }
        let mut forwarded = self.clone();
        forwarded.hop_limit -= 1;
        forwarded.previous_hop = relay;
        Ok(forwarded)
    }

    /// Encode a bounded HYM1 frame. CRC covers the header and ciphertext.
    pub fn encode(&self) -> Result<Vec<u8>, MeshError> {
        if self.ciphertext.len() > MAX_CIPHERTEXT_BYTES {
            return Err(MeshError::PayloadTooLarge);
        }
        let payload_len =
            u32::try_from(self.ciphertext.len()).map_err(|_| MeshError::PayloadTooLarge)?;
        let mut wire = Vec::with_capacity(HEADER_LEN + self.ciphertext.len() + TRAILER_LEN);
        wire.extend_from_slice(MAGIC);
        wire.push(VERSION);
        wire.push(self.kind as u8);
        wire.push(self.hop_limit);
        wire.push(self.flags);
        wire.extend_from_slice(&self.source.0);
        wire.extend_from_slice(&self.destination.0);
        wire.extend_from_slice(&self.previous_hop.0);
        wire.extend_from_slice(&self.packet_id.to_be_bytes());
        wire.extend_from_slice(&self.sequence.to_be_bytes());
        wire.extend_from_slice(&self.nonce);
        wire.extend_from_slice(&payload_len.to_be_bytes());
        wire.extend_from_slice(&self.ciphertext);
        let crc = checksum(&wire);
        wire.extend_from_slice(&crc.to_be_bytes());
        Ok(wire)
    }

    pub fn decode(wire: &[u8]) -> Result<Self, MeshError> {
        if wire.len() < HEADER_LEN + TRAILER_LEN {
            return Err(MeshError::FrameTooShort);
        }
        if wire.len() > HEADER_LEN + MAX_CIPHERTEXT_BYTES + TRAILER_LEN {
            return Err(MeshError::FrameTooLarge);
        }
        if &wire[..4] != MAGIC {
            return Err(MeshError::InvalidMagic);
        }
        if wire[4] != VERSION {
            return Err(MeshError::UnsupportedVersion);
        }
        let kind = FrameKind::try_from(wire[5])?;
        let payload_len = u32::from_be_bytes(
            wire[128..132]
                .try_into()
                .map_err(|_| MeshError::LengthMismatch)?,
        ) as usize;
        if payload_len > MAX_CIPHERTEXT_BYTES {
            return Err(MeshError::FrameTooLarge);
        }
        let expected_len = HEADER_LEN
            .checked_add(payload_len)
            .and_then(|len| len.checked_add(TRAILER_LEN))
            .ok_or(MeshError::FrameTooLarge)?;
        if wire.len() != expected_len {
            return Err(MeshError::LengthMismatch);
        }

        let crc_offset = wire.len() - TRAILER_LEN;
        let expected_crc = u32::from_be_bytes(
            wire[crc_offset..]
                .try_into()
                .map_err(|_| MeshError::LengthMismatch)?,
        );
        if checksum(&wire[..crc_offset]) != expected_crc {
            return Err(MeshError::ChecksumMismatch);
        }

        let mut source = [0_u8; 32];
        source.copy_from_slice(&wire[8..40]);
        let mut destination = [0_u8; 32];
        destination.copy_from_slice(&wire[40..72]);
        let mut previous_hop = [0_u8; 32];
        previous_hop.copy_from_slice(&wire[72..104]);
        let mut nonce = [0_u8; 12];
        nonce.copy_from_slice(&wire[116..128]);

        Ok(Self {
            kind,
            hop_limit: wire[6],
            flags: wire[7],
            source: MeshNodeId(source),
            destination: MeshNodeId(destination),
            previous_hop: MeshNodeId(previous_hop),
            packet_id: u64::from_be_bytes(
                wire[104..112]
                    .try_into()
                    .map_err(|_| MeshError::LengthMismatch)?,
            ),
            sequence: u32::from_be_bytes(
                wire[112..116]
                    .try_into()
                    .map_err(|_| MeshError::LengthMismatch)?,
            ),
            nonce,
            ciphertext: wire[HEADER_LEN..crc_offset].to_vec(),
        })
    }
}

#[derive(Clone, Debug)]
struct Route {
    next_hop: MeshNodeId,
    hop_count: u8,
    expires_at: Instant,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ReplayKey {
    source: MeshNodeId,
    packet_id: u64,
    sequence: u32,
    kind: FrameKind,
}

pub struct MeshRouter {
    local_id: MeshNodeId,
    routes: HashMap<MeshNodeId, Route>,
    replay_capacity: usize,
    replay_set: HashSet<ReplayKey>,
    replay_order: VecDeque<ReplayKey>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MeshDecision {
    Deliver(MeshFrame),
    Forward {
        next_hop: MeshNodeId,
        frame: MeshFrame,
    },
}

impl MeshRouter {
    pub fn new(local_id: MeshNodeId, replay_capacity: usize) -> Result<Self, MeshError> {
        if replay_capacity == 0 {
            return Err(MeshError::InvalidReplayCacheCapacity);
        }
        Ok(Self {
            local_id,
            routes: HashMap::new(),
            replay_capacity,
            replay_set: HashSet::new(),
            replay_order: VecDeque::new(),
        })
    }

    pub fn local_id(&self) -> MeshNodeId {
        self.local_id
    }

    pub fn install_route(
        &mut self,
        destination: MeshNodeId,
        next_hop: MeshNodeId,
        hop_count: u8,
        ttl: Duration,
        now: Instant,
    ) -> Result<(), MeshError> {
        if destination == self.local_id
            || next_hop == self.local_id
            || destination == next_hop
            || hop_count == 0
            || ttl.is_zero()
        {
            return Err(MeshError::InvalidRoute);
        }
        let expires_at = now.checked_add(ttl).ok_or(MeshError::InvalidRoute)?;
        self.routes.insert(
            destination,
            Route {
                next_hop,
                hop_count,
                expires_at,
            },
        );
        Ok(())
    }

    pub fn route_hop_count(&mut self, destination: MeshNodeId, now: Instant) -> Option<u8> {
        let expired = self
            .routes
            .get(&destination)
            .map(|route| route.expires_at <= now)
            .unwrap_or(true);
        if expired {
            self.routes.remove(&destination);
            return None;
        }
        self.routes.get(&destination).map(|route| route.hop_count)
    }

    pub fn process(&mut self, frame: MeshFrame, now: Instant) -> Result<MeshDecision, MeshError> {
        if frame.source == self.local_id {
            return Err(MeshError::RouteLoop);
        }

        // Only consume a replay-cache entry after the packet has passed routing checks.
        // Otherwise a transient NoRoute/RouteLoop error would poison a valid retransmission
        // after the route table is repaired.
        if frame.destination == self.local_id {
            self.remember(&frame)?;
            return Ok(MeshDecision::Deliver(frame));
        }
        if frame.hop_limit == 0 {
            return Err(MeshError::HopLimitExceeded);
        }

        let route = self
            .routes
            .get(&frame.destination)
            .cloned()
            .ok_or(MeshError::NoRoute)?;
        if route.expires_at <= now {
            self.routes.remove(&frame.destination);
            return Err(MeshError::NoRoute);
        }
        if route.next_hop == frame.previous_hop || route.next_hop == self.local_id {
            return Err(MeshError::RouteLoop);
        }

        let forwarded = frame.forwarded_by(self.local_id)?;
        self.remember(&frame)?;
        Ok(MeshDecision::Forward {
            next_hop: route.next_hop,
            frame: forwarded,
        })
    }

    fn remember(&mut self, frame: &MeshFrame) -> Result<(), MeshError> {
        let key = ReplayKey {
            source: frame.source,
            packet_id: frame.packet_id,
            sequence: frame.sequence,
            kind: frame.kind,
        };
        if !self.replay_set.insert(key) {
            return Err(MeshError::DuplicatePacket);
        }
        self.replay_order.push_back(key);
        while self.replay_order.len() > self.replay_capacity {
            if let Some(oldest) = self.replay_order.pop_front() {
                self.replay_set.remove(&oldest);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(value: u8) -> MeshNodeId {
        MeshNodeId([value; 32])
    }
    fn cipher(value: u8) -> MeshCipher {
        MeshCipher::new(&[value; 32])
    }

    fn sample_frame(source: u8, destination: u8, hop_limit: u8) -> MeshFrame {
        cipher(7)
            .seal(
                FrameKind::Data,
                0,
                hop_limit,
                node(source),
                node(destination),
                node(source),
                19,
                2,
                b"hydra mesh payload",
            )
            .unwrap()
    }

    #[test]
    fn encrypted_frame_round_trips_over_wire_format() {
        let sender = cipher(7);
        let receiver = cipher(7);
        let frame = sender
            .seal(
                FrameKind::Data,
                0,
                12,
                node(1),
                node(3),
                node(1),
                123,
                4,
                &[0, 255, 128, 1, 0, 42],
            )
            .unwrap();
        let wire = frame.encode().unwrap();
        let decoded = MeshFrame::decode(&wire).unwrap();
        assert_eq!(decoded, frame);
        assert_eq!(
            receiver.open(&decoded).unwrap(),
            vec![0, 255, 128, 1, 0, 42]
        );
    }

    #[test]
    fn ciphertext_tampering_fails_authentication() {
        let sender = cipher(7);
        let receiver = cipher(7);
        let mut frame = sender
            .seal(
                FrameKind::Data,
                0,
                5,
                node(1),
                node(2),
                node(1),
                9,
                0,
                b"confidential",
            )
            .unwrap();
        frame.ciphertext[0] ^= 1;
        assert_eq!(receiver.open(&frame), Err(MeshError::AuthenticationFailed));
    }

    #[test]
    fn relays_can_update_hop_fields_without_decrypting() {
        let sender = cipher(7);
        let receiver = cipher(7);
        let frame = sender
            .seal(
                FrameKind::Data,
                0,
                5,
                node(1),
                node(3),
                node(1),
                10,
                0,
                b"end-to-end",
            )
            .unwrap();
        let forwarded = frame.forwarded_by(node(2)).unwrap();
        assert_eq!(forwarded.hop_limit, 4);
        assert_eq!(forwarded.previous_hop, node(2));
        assert_eq!(receiver.open(&forwarded).unwrap(), b"end-to-end");
    }

    #[test]
    fn corrupt_wire_bytes_fail_crc_check() {
        let mut wire = sample_frame(1, 2, 4).encode().unwrap();
        let index = wire.len() - 5;
        wire[index] ^= 0x80;
        assert_eq!(MeshFrame::decode(&wire), Err(MeshError::ChecksumMismatch));
    }

    #[test]
    fn router_forwards_and_decrements_hop_limit() {
        let now = Instant::now();
        let mut router = MeshRouter::new(node(2), 16).unwrap();
        router
            .install_route(node(3), node(4), 2, Duration::from_secs(60), now)
            .unwrap();
        match router.process(sample_frame(1, 3, 8), now).unwrap() {
            MeshDecision::Forward { next_hop, frame } => {
                assert_eq!(next_hop, node(4));
                assert_eq!(frame.previous_hop, node(2));
                assert_eq!(frame.hop_limit, 7);
            }
            MeshDecision::Deliver(_) => panic!("expected forwarding"),
        }
    }

    #[test]
    fn router_delivers_packets_for_itself() {
        let now = Instant::now();
        let mut router = MeshRouter::new(node(2), 16).unwrap();
        let packet = sample_frame(1, 2, 1);
        assert_eq!(
            router.process(packet.clone(), now),
            Ok(MeshDecision::Deliver(packet))
        );
    }

    #[test]
    fn duplicate_packets_are_suppressed() {
        let now = Instant::now();
        let mut router = MeshRouter::new(node(2), 16).unwrap();
        let packet = sample_frame(1, 3, 8);
        router
            .install_route(node(3), node(4), 2, Duration::from_secs(60), now)
            .unwrap();
        router.process(packet.clone(), now).unwrap();
        assert_eq!(router.process(packet, now), Err(MeshError::DuplicatePacket));
    }

    #[test]
    fn packet_can_be_retried_after_a_missing_route_is_installed() {
        let now = Instant::now();
        let mut router = MeshRouter::new(node(2), 16).unwrap();
        let packet = sample_frame(1, 3, 8);

        assert_eq!(router.process(packet.clone(), now), Err(MeshError::NoRoute));
        router
            .install_route(node(3), node(4), 2, Duration::from_secs(60), now)
            .unwrap();

        assert!(matches!(
            router.process(packet, now),
            Ok(MeshDecision::Forward { next_hop, .. }) if next_hop == node(4)
        ));
    }

    #[test]
    fn packet_can_be_retried_after_a_route_loop_is_corrected() {
        let now = Instant::now();
        let mut router = MeshRouter::new(node(2), 16).unwrap();
        let mut packet = sample_frame(1, 3, 8);
        packet.previous_hop = node(4);
        router
            .install_route(node(3), node(4), 2, Duration::from_secs(60), now)
            .unwrap();

        assert_eq!(router.process(packet.clone(), now), Err(MeshError::RouteLoop));
        router
            .install_route(node(3), node(5), 2, Duration::from_secs(60), now)
            .unwrap();

        assert!(matches!(
            router.process(packet, now),
            Ok(MeshDecision::Forward { next_hop, .. }) if next_hop == node(5)
        ));
    }

    #[test]
    fn expired_routes_and_immediate_loops_are_rejected() {
        let now = Instant::now();
        let mut router = MeshRouter::new(node(2), 16).unwrap();
        router
            .install_route(node(3), node(4), 2, Duration::from_secs(1), now)
            .unwrap();
        assert_eq!(
            router.process(sample_frame(1, 3, 4), now + Duration::from_secs(2)),
            Err(MeshError::NoRoute),
        );
        let mut second = MeshRouter::new(node(2), 16).unwrap();
        second
            .install_route(node(3), node(1), 2, Duration::from_secs(30), now)
            .unwrap();
        let mut packet = sample_frame(4, 3, 4);
        packet.previous_hop = node(1);
        assert_eq!(second.process(packet, now), Err(MeshError::RouteLoop));
    }

    #[test]
    fn frame_bounds_are_enforced() {
        let mut wire = sample_frame(1, 2, 4).encode().unwrap();
        wire[128..132].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(MeshFrame::decode(&wire), Err(MeshError::FrameTooLarge));
        assert_eq!(
            cipher(7).seal(
                FrameKind::Data,
                0,
                4,
                node(1),
                node(2),
                node(1),
                1,
                0,
                &vec![0; MAX_PLAINTEXT_BYTES + 1],
            ),
            Err(MeshError::PayloadTooLarge),
        );
    }
}
