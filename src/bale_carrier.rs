//! Client-side carrier over Bale's LiveKit call infrastructure.
//!
//! This is a peer-to-peer call carrier, not a chat bot or bot API. It creates a separate
//! call session through Bale signaling; it does NOT attach to or inject bytes into an already
//! running official Bale app socket.
//!
//! The carrier transports encoded HYM1 MeshFrame bytes through the public LkTunnel send_ip
//! and set_on_ip hooks. End-to-end confidentiality and authenticity remain the MeshCipher's job.

use crate::mesh::{MeshError, MeshFrame};
use async_trait::async_trait;
use bale_signaling::auth::{AuthOutcome, BaleAuth};
use bale_signaling::BaleSignaling;
use lk_signaling::{
    CallDecision, IncomingHandler, PeerId, Signaling, TokenStore, TransportSession, TunnelHooks,
};
use lktunnel::{LkTunnel, SendError, TunnelState};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};

pub const DEFAULT_INBOUND_QUEUE_CAPACITY: usize = 256;
pub const MAX_INBOUND_QUEUE_CAPACITY: usize = 4096;
pub const MAX_CARRIER_FRAME_BYTES: usize = 65_535;

#[derive(Debug)]
pub enum BaleCarrierError {
    Io(String),
    TokenMissing,
    QueueCapacityInvalid,
    AllowlistEmpty,
    Authentication(String),
    Signaling(String),
    PeerNotFound,
    Call(String),
    TunnelFailed(String),
    TunnelStateClosed,
    Timeout,
    Frame(MeshError),
    FrameTooLarge,
    Backpressure,
    NotConnected,
    Closed,
}

impl std::fmt::Display for BaleCarrierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(s) => write!(f, "Bale token file: {s}"),
            Self::TokenMissing => f.write_str("Bale access token is missing; sign in first"),
            Self::QueueCapacityInvalid => {
                f.write_str("carrier inbound queue capacity is outside the allowed range")
            }
            Self::AllowlistEmpty => {
                f.write_str("Bale listener requires at least one explicitly allowed peer ID")
            }
            Self::Authentication(s) => write!(f, "Bale authentication: {s}"),
            Self::Signaling(s) => write!(f, "Bale signaling: {s}"),
            Self::PeerNotFound => f.write_str("Bale peer ID could not be resolved"),
            Self::Call(s) => write!(f, "Bale call setup: {s}"),
            Self::TunnelFailed(s) => write!(f, "LiveKit tunnel failed: {s}"),
            Self::TunnelStateClosed => f.write_str("LiveKit tunnel state stream closed"),
            Self::Timeout => f.write_str("timed out waiting for LiveKit peer connection"),
            Self::Frame(e) => write!(f, "invalid Meshnet frame: {e}"),
            Self::FrameTooLarge => {
                f.write_str("Meshnet frame exceeds the carrier message-size limit")
            }
            Self::Backpressure => f.write_str("carrier send queue is full"),
            Self::NotConnected => f.write_str("carrier tunnel is not connected"),
            Self::Closed => f.write_str("carrier receive stream is closed"),
        }
    }
}

impl std::error::Error for BaleCarrierError {}

impl From<MeshError> for BaleCarrierError {
    fn from(value: MeshError) -> Self {
        Self::Frame(value)
    }
}

/// File-backed token storage. The file contains the access-token cookie expected by BaleSignaling.
#[derive(Clone, Debug)]
pub struct BaleFileTokenStore {
    path: PathBuf,
}

impl BaleFileTokenStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn write_token(&self, token: &str) -> Result<(), BaleCarrierError> {
        if token.trim().is_empty() {
            return Err(BaleCarrierError::TokenMissing);
        }
        write_token_file(&self.path, token.as_bytes())
            .map_err(|error| BaleCarrierError::Io(error.to_string()))
    }
}

impl TokenStore for BaleFileTokenStore {
    fn load(&self) -> Option<Vec<u8>> {
        let bytes = fs::read(&self.path).ok()?;
        (!bytes.is_empty()).then_some(bytes)
    }

    fn save(&self, bytes: &[u8]) {
        // Upstream TokenStore cannot return errors. Interactive sign-in uses write_token(),
        // which propagates failures instead of silently reporting success.
        let _ = write_token_file(&self.path, bytes);
    }

    fn clear(&self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn write_token_file(path: &Path, token: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let temp = path.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&temp, token)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o600))?;
    }
    fs::rename(&temp, path)?;
    Ok(())
}

/// Sign in with a normal Bale user account using an OTP and persist the access-token cookie.
/// This is for a regular user account, not a bot. New accounts may require signup_name.
pub async fn login_with_otp(
    token_path: &Path,
    phone: &str,
    otp: &str,
    signup_name: Option<&str>,
) -> Result<(), BaleCarrierError> {
    let auth = BaleAuth::new();
    let start = auth
        .start_phone_auth(phone)
        .await
        .map_err(|error| BaleCarrierError::Authentication(error.to_string()))?;
    let outcome = auth
        .submit_otp(&start.transaction_hash, otp)
        .await
        .map_err(|error| BaleCarrierError::Authentication(error.to_string()))?;

    let outcome = match outcome {
        AuthOutcome::Authenticated { .. } => outcome,
        AuthOutcome::NeedsSignupName { transaction_hash } => {
            let name = signup_name.ok_or_else(|| {
                BaleCarrierError::Authentication(
                    "new account requires signup_name after OTP verification".to_owned(),
                )
            })?;
            auth.submit_signup_name(&transaction_hash, name)
                .await
                .map_err(|error| BaleCarrierError::Authentication(error.to_string()))?
        }
    };

    match outcome {
        AuthOutcome::Authenticated { access_token } => {
            BaleFileTokenStore::new(token_path).write_token(&access_token)
        }
        AuthOutcome::NeedsSignupName { .. } => Err(BaleCarrierError::Authentication(
            "sign-in completed without an access token".to_owned(),
        )),
    }
}

/// A connected LiveKit call carrying encoded MeshFrames. The inbound queue is bounded;
/// malformed frames and queue overflow are counted and dropped.
pub struct BaleLiveKitCarrier {
    tunnel: Arc<LkTunnel>,
    inbound: mpsc::Receiver<MeshFrame>,
    _signaling: Option<Arc<BaleSignaling>>,
    malformed_frames: Arc<AtomicU64>,
    dropped_frames: Arc<AtomicU64>,
}

impl BaleLiveKitCarrier {
    /// Attach to a connected LkTunnel. Also used by the in-process carrier test.
    pub fn from_connected_tunnel(
        tunnel: Arc<LkTunnel>,
        queue_capacity: usize,
    ) -> Result<Self, BaleCarrierError> {
        Self::attach(tunnel, None, queue_capacity)
    }

    fn attach(
        tunnel: Arc<LkTunnel>,
        signaling: Option<Arc<BaleSignaling>>,
        queue_capacity: usize,
    ) -> Result<Self, BaleCarrierError> {
        if !(1..=MAX_INBOUND_QUEUE_CAPACITY).contains(&queue_capacity) {
            return Err(BaleCarrierError::QueueCapacityInvalid);
        }
        if !tunnel.is_connected() {
            return Err(BaleCarrierError::NotConnected);
        }

        let (tx, inbound) = mpsc::channel(queue_capacity);
        let malformed_frames = Arc::new(AtomicU64::new(0));
        let dropped_frames = Arc::new(AtomicU64::new(0));
        let malformed_for_callback = Arc::clone(&malformed_frames);
        let dropped_for_callback = Arc::clone(&dropped_frames);

        tunnel.set_on_ip(Some(Arc::new(move |bytes: &[u8]| {
            let frame = match MeshFrame::decode(bytes) {
                Ok(frame) => frame,
                Err(_) => {
                    malformed_for_callback.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            };
            if tx.try_send(frame).is_err() {
                dropped_for_callback.fetch_add(1, Ordering::Relaxed);
            }
        })));

        Ok(Self {
            tunnel,
            inbound,
            _signaling: signaling,
            malformed_frames,
            dropped_frames,
        })
    }

    pub fn send_frame(&self, frame: &MeshFrame) -> Result<(), BaleCarrierError> {
        let wire = frame.encode()?;
        if wire.len() > MAX_CARRIER_FRAME_BYTES {
            return Err(BaleCarrierError::FrameTooLarge);
        }
        self.tunnel.send_ip(&wire).map_err(|error| match error {
            SendError::Backpressure => BaleCarrierError::Backpressure,
            SendError::NotConnected => BaleCarrierError::NotConnected,
            SendError::Invalid => BaleCarrierError::FrameTooLarge,
        })
    }

    pub async fn receive_frame(&mut self) -> Result<MeshFrame, BaleCarrierError> {
        self.inbound.recv().await.ok_or(BaleCarrierError::Closed)
    }

    pub fn is_connected(&self) -> bool {
        self.tunnel.is_connected()
    }

    pub fn stats(&self) -> CarrierStats {
        CarrierStats {
            malformed_frames: self.malformed_frames.load(Ordering::Relaxed),
            dropped_frames: self.dropped_frames.load(Ordering::Relaxed),
        }
    }

    pub fn close(&self) {
        self.tunnel.disconnect();
    }
}

impl Drop for BaleLiveKitCarrier {
    fn drop(&mut self) {
        self.tunnel.disconnect();
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CarrierStats {
    pub malformed_frames: u64,
    pub dropped_frames: u64,
}

/// Establish a call to a peer through Bale signaling and return a MeshFrame carrier.
/// This creates a separate call session; it does not attach to the official app's existing
/// TLS socket or inject bytes into another running process.
pub async fn connect_to_peer(
    token_path: &Path,
    peer_id: &str,
    queue_capacity: usize,
    connect_timeout: Duration,
) -> Result<BaleLiveKitCarrier, BaleCarrierError> {
    let token_store = Arc::new(BaleFileTokenStore::new(token_path));
    if token_store.load().is_none() {
        return Err(BaleCarrierError::TokenMissing);
    }
    let signaling = Arc::new(BaleSignaling::new(token_store));
    signaling.auto_load_token();
    if !signaling.is_authenticated() {
        return Err(BaleCarrierError::TokenMissing);
    }
    signaling
        .connect()
        .await
        .map_err(|error| BaleCarrierError::Signaling(error.to_string()))?;

    let peer = signaling
        .resolve_peer(peer_id)
        .await
        .ok_or(BaleCarrierError::PeerNotFound)?;
    signaling.tunnel_hooks().activate();
    let session = signaling
        .tunnel_hooks()
        .place_call(peer)
        .await
        .map_err(|error| BaleCarrierError::Call(error.to_string()))?;

    let tunnel = LkTunnel::connect(session.url, session.token);
    wait_for_tunnel(&tunnel, connect_timeout).await?;
    BaleLiveKitCarrier::attach(tunnel, Some(signaling), queue_capacity)
}

/// Server-side listener accepting calls only from an explicit allowlist of Bale peer IDs.
pub struct BaleCarrierListener {
    signaling: Arc<BaleSignaling>,
    accepted: mpsc::UnboundedReceiver<(PeerId, TransportSession)>,
    queue_capacity: usize,
    connect_timeout: Duration,
}

impl BaleCarrierListener {
    pub async fn bind(
        token_path: &Path,
        allowed_peer_ids: impl IntoIterator<Item = String>,
        queue_capacity: usize,
        connect_timeout: Duration,
    ) -> Result<Self, BaleCarrierError> {
        if !(1..=MAX_INBOUND_QUEUE_CAPACITY).contains(&queue_capacity) {
            return Err(BaleCarrierError::QueueCapacityInvalid);
        }
        let allowlist: HashSet<String> = allowed_peer_ids.into_iter().collect();
        if allowlist.is_empty() {
            return Err(BaleCarrierError::AllowlistEmpty);
        }
        let token_store = Arc::new(BaleFileTokenStore::new(token_path));
        if token_store.load().is_none() {
            return Err(BaleCarrierError::TokenMissing);
        }
        let signaling = Arc::new(BaleSignaling::new(token_store));
        signaling.auto_load_token();
        if !signaling.is_authenticated() {
            return Err(BaleCarrierError::TokenMissing);
        }
        signaling
            .tunnel_hooks()
            .set_incoming_handler(Box::new(AllowlistIncomingHandler { allowed: allowlist }));
        let accepted = signaling.tunnel_hooks().accepted_sessions();
        signaling
            .connect()
            .await
            .map_err(|error| BaleCarrierError::Signaling(error.to_string()))?;

        Ok(Self {
            signaling,
            accepted,
            queue_capacity,
            connect_timeout,
        })
    }

    pub async fn accept_next(
        &mut self,
        accept_timeout: Duration,
    ) -> Result<(String, BaleLiveKitCarrier), BaleCarrierError> {
        let (peer, session) = tokio::time::timeout(accept_timeout, self.accepted.recv())
            .await
            .map_err(|_| BaleCarrierError::Timeout)?
            .ok_or(BaleCarrierError::Closed)?;
        let peer_id = peer.id_str().to_owned();
        let TransportSession { url, token, .. } = session;
        let tunnel = LkTunnel::connect_server(url, token);
        wait_for_tunnel(&tunnel, self.connect_timeout).await?;
        let carrier = BaleLiveKitCarrier::attach(
            tunnel,
            Some(Arc::clone(&self.signaling)),
            self.queue_capacity,
        )?;
        Ok((peer_id, carrier))
    }
}

struct AllowlistIncomingHandler {
    allowed: HashSet<String>,
}

#[async_trait]
impl IncomingHandler for AllowlistIncomingHandler {
    async fn decide(&self, peer: PeerId, _display_name: Option<String>) -> CallDecision {
        if self.allowed.contains(peer.id_str()) {
            CallDecision::Accept
        } else {
            CallDecision::Reject
        }
    }
}

async fn wait_for_tunnel(
    tunnel: &Arc<LkTunnel>,
    connect_timeout: Duration,
) -> Result<(), BaleCarrierError> {
    let mut state: watch::Receiver<TunnelState> = tunnel.state();
    tokio::time::timeout(connect_timeout, async {
        loop {
            match state.borrow_and_update().clone() {
                TunnelState::Connected => return Ok(()),
                TunnelState::Failed(reason) => return Err(BaleCarrierError::TunnelFailed(reason)),
                TunnelState::Disconnected => {
                    return Err(BaleCarrierError::TunnelFailed(
                        "disconnected before ready".to_owned(),
                    ));
                }
                TunnelState::Connecting => {}
            }
            state
                .changed()
                .await
                .map_err(|_| BaleCarrierError::TunnelStateClosed)?;
        }
    })
    .await
    .map_err(|_| BaleCarrierError::Timeout)?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::{FrameKind, MeshCipher, MeshNodeId};
    use lktunnel::connect_loopback;

    fn node(value: u8) -> MeshNodeId {
        MeshNodeId([value; 32])
    }

    #[tokio::test]
    async fn livekit_carrier_delivers_encrypted_mesh_frames_both_directions() {
        let (left_tunnel, right_tunnel) = connect_loopback();
        let mut left = BaleLiveKitCarrier::from_connected_tunnel(left_tunnel, 8).unwrap();
        let mut right = BaleLiveKitCarrier::from_connected_tunnel(right_tunnel, 8).unwrap();
        let sender = MeshCipher::new(&[7; 32]);
        let receiver = MeshCipher::new(&[7; 32]);

        let outbound = sender
            .seal(
                FrameKind::Data,
                0,
                8,
                node(1),
                node(2),
                node(1),
                10,
                1,
                b"carrier integration",
            )
            .unwrap();
        left.send_frame(&outbound).unwrap();
        let inbound = tokio::time::timeout(Duration::from_secs(2), right.receive_frame())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(receiver.open(&inbound).unwrap(), b"carrier integration");

        let reply = receiver
            .seal(
                FrameKind::Acknowledgement,
                0,
                8,
                node(2),
                node(1),
                node(2),
                11,
                2,
                b"ack",
            )
            .unwrap();
        right.send_frame(&reply).unwrap();
        let response = tokio::time::timeout(Duration::from_secs(2), left.receive_frame())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(sender.open(&response).unwrap(), b"ack");
        assert_eq!(left.stats(), CarrierStats::default());
        assert_eq!(right.stats(), CarrierStats::default());
    }
}
