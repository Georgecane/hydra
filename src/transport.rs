//! Bounded, loopback-only TCP transport experiment.
//! CRC-32 detects accidental corruption but does not authenticate peers.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

pub const DEFAULT_MAX_PAYLOAD_BYTES: usize = 1024 * 1024;
pub const MAX_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_TIMEOUT_MS: u64 = 3_000;
pub const MAX_MESSAGES_PER_SESSION: usize = 64;
pub const MAX_SESSION_BYTES: usize = 64 * 1024 * 1024;
const REQUEST_MAGIC: &[u8; 4] = b"HYD1";
const RESPONSE_MAGIC: &[u8; 4] = b"HYA1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Status {
    Ok = 0,
    PayloadTooLarge = 1,
    ChecksumMismatch = 2,
    InvalidFrame = 3,
    UpstreamUnavailable = 4,
    UpstreamRejected = 5,
    Timeout = 6,
}
impl Status {
    fn from_byte(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Ok),
            1 => Some(Self::PayloadTooLarge),
            2 => Some(Self::ChecksumMismatch),
            3 => Some(Self::InvalidFrame),
            4 => Some(Self::UpstreamUnavailable),
            5 => Some(Self::UpstreamRejected),
            6 => Some(Self::Timeout),
            _ => None,
        }
    }
}
impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Response {
    pub status: Status,
    pub payload: Vec<u8>,
    pub checksum: u32,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerReport {
    pub status: Status,
    pub bytes_received: usize,
    pub messages_processed: usize,
    pub relayed: bool,
}

/// Explicit fault injection for loopback-only experiments.
/// Configure one fault at a time to keep results deterministic.
#[derive(Clone, Debug, Default)]
pub struct FaultInjection {
    pub response_delay: Duration,
    pub truncate_response_after_bytes: Option<usize>,
    pub disconnect_after_messages: Option<usize>,
}
#[derive(Debug)]
pub struct FrameError {
    pub status: Status,
    pub message: String,
}
impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.status, self.message)
    }
}
impl std::error::Error for FrameError {}

fn frame_error(status: Status, message: impl Into<String>) -> FrameError {
    FrameError {
        status,
        message: message.into(),
    }
}
fn status_for_io(error: &io::Error) -> Status {
    match error.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => Status::Timeout,
        io::ErrorKind::UnexpectedEof | io::ErrorKind::InvalidData => Status::InvalidFrame,
        _ => Status::UpstreamUnavailable,
    }
}

/// CRC-32/ISO-HDLC. This is for accidental-corruption detection only.
pub fn checksum(payload: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for byte in payload {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

fn validate_limit(limit: usize) -> io::Result<()> {
    if limit == 0 || limit > MAX_PAYLOAD_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("payload limit must be 1..={MAX_PAYLOAD_BYTES}"),
        ));
    }
    Ok(())
}
fn validate_loopback(address: SocketAddr, label: &str) -> io::Result<()> {
    if !address.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{label} must be a loopback address in this experiment"),
        ));
    }
    Ok(())
}
fn configure_stream(stream: &TcpStream, timeout: Duration) -> io::Result<()> {
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))
}
fn read_u64<R: Read>(reader: &mut R) -> Result<u64, FrameError> {
    let mut bytes = [0; 8];
    reader
        .read_exact(&mut bytes)
        .map_err(|e| frame_error(status_for_io(&e), e.to_string()))?;
    Ok(u64::from_be_bytes(bytes))
}
fn read_u32<R: Read>(reader: &mut R) -> Result<u32, FrameError> {
    let mut bytes = [0; 4];
    reader
        .read_exact(&mut bytes)
        .map_err(|e| frame_error(status_for_io(&e), e.to_string()))?;
    Ok(u32::from_be_bytes(bytes))
}

fn write_request<W: Write>(writer: &mut W, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "payload exceeds protocol limit",
        ));
    }
    writer.write_all(REQUEST_MAGIC)?;
    writer.write_all(&(payload.len() as u64).to_be_bytes())?;
    writer.write_all(&checksum(payload).to_be_bytes())?;
    writer.write_all(payload)?;
    writer.flush()
}
fn read_request<R: Read>(reader: &mut R, limit: usize) -> Result<Vec<u8>, FrameError> {
    let mut magic = [0; 4];
    reader
        .read_exact(&mut magic)
        .map_err(|e| frame_error(status_for_io(&e), e.to_string()))?;
    if &magic != REQUEST_MAGIC {
        return Err(frame_error(Status::InvalidFrame, "invalid request marker"));
    }
    let length = read_u64(reader)?;
    let expected = read_u32(reader)?;
    if length > limit as u64 || length > MAX_PAYLOAD_BYTES as u64 {
        // Consume an over-limit body only when its declared size is still bounded by
        // the protocol hard cap. This allows a framed rejection to reach the client
        // instead of closing a TCP socket with unread bytes and triggering a reset.
        if length <= MAX_PAYLOAD_BYTES as u64 {
            let mut remaining = length;
            let mut discard = [0_u8; 8192];
            while remaining > 0 {
                let take = remaining.min(discard.len() as u64) as usize;
                reader
                    .read_exact(&mut discard[..take])
                    .map_err(|e| frame_error(status_for_io(&e), e.to_string()))?;
                remaining -= take as u64;
            }
        }
        return Err(frame_error(
            Status::PayloadTooLarge,
            format!("request length {length} exceeds configured limit {limit}"),
        ));
    }
    let length = usize::try_from(length).map_err(|_| {
        frame_error(
            Status::PayloadTooLarge,
            "request length does not fit this platform",
        )
    })?;
    let mut payload = vec![0; length];
    reader
        .read_exact(&mut payload)
        .map_err(|e| frame_error(status_for_io(&e), e.to_string()))?;
    if checksum(&payload) != expected {
        return Err(frame_error(
            Status::ChecksumMismatch,
            "request checksum mismatch",
        ));
    }
    Ok(payload)
}
fn write_response<W: Write>(writer: &mut W, status: Status, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_PAYLOAD_BYTES || (status != Status::Ok && !payload.is_empty()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid response payload",
        ));
    }
    writer.write_all(RESPONSE_MAGIC)?;
    writer.write_all(&[status as u8])?;
    writer.write_all(&(payload.len() as u64).to_be_bytes())?;
    writer.write_all(&checksum(payload).to_be_bytes())?;
    writer.write_all(payload)?;
    writer.flush()
}
fn read_response<R: Read>(reader: &mut R, limit: usize) -> Result<Response, FrameError> {
    let mut magic = [0; 4];
    reader
        .read_exact(&mut magic)
        .map_err(|e| frame_error(status_for_io(&e), e.to_string()))?;
    if &magic != RESPONSE_MAGIC {
        return Err(frame_error(Status::InvalidFrame, "invalid response marker"));
    }
    let mut code = [0; 1];
    reader
        .read_exact(&mut code)
        .map_err(|e| frame_error(status_for_io(&e), e.to_string()))?;
    let status = Status::from_byte(code[0])
        .ok_or_else(|| frame_error(Status::InvalidFrame, "unknown response status"))?;
    let length = read_u64(reader)?;
    let expected = read_u32(reader)?;
    if length > limit as u64 || length > MAX_PAYLOAD_BYTES as u64 {
        return Err(frame_error(
            Status::PayloadTooLarge,
            "response exceeds configured limit",
        ));
    }
    if status != Status::Ok && length != 0 {
        return Err(frame_error(
            Status::InvalidFrame,
            "error response has a payload",
        ));
    }
    let length = usize::try_from(length).map_err(|_| {
        frame_error(
            Status::PayloadTooLarge,
            "response length does not fit this platform",
        )
    })?;
    let mut payload = vec![0; length];
    reader
        .read_exact(&mut payload)
        .map_err(|e| frame_error(status_for_io(&e), e.to_string()))?;
    let actual = checksum(&payload);
    if actual != expected {
        return Err(frame_error(
            Status::ChecksumMismatch,
            "response checksum mismatch",
        ));
    }
    Ok(Response {
        status,
        payload,
        checksum: actual,
    })
}
fn write_error<W: Write>(writer: &mut W, status: Status) -> io::Result<()> {
    write_response(writer, status, &[])
}
fn accept_with_timeout(listener: &TcpListener, timeout: Duration) -> io::Result<TcpStream> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((stream, peer)) => {
                validate_loopback(peer, "client")?;
                return Ok(stream);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "waiting for client timed out",
                    ));
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(e) => return Err(e),
        }
    }
}

/// Serve exactly one TCP client. No non-loopback endpoint is accepted by this lab.
/// No upstream means the node is the echo origin; an upstream makes it a relay.
/// Serve exactly one framed message. Kept as a convenience wrapper for one-shot tests.
pub fn serve_once(
    listener: &TcpListener,
    upstream: Option<SocketAddr>,
    limit: usize,
    timeout: Duration,
) -> io::Result<ServerReport> {
    serve_session(listener, upstream, limit, timeout, 1)
}

/// Serve one TCP connection carrying multiple length-prefixed messages.
///
/// Each individual message is bounded by limit, the message count is capped, and
/// cumulative request bytes are capped for the lifetime of the session. An upstream
/// relay reuses one TCP connection to its origin for the entire session.
pub fn serve_session(
    listener: &TcpListener,
    upstream: Option<SocketAddr>,
    limit: usize,
    timeout: Duration,
    max_messages: usize,
) -> io::Result<ServerReport> {
    serve_session_with_faults(
        listener,
        upstream,
        limit,
        timeout,
        max_messages,
        &FaultInjection::default(),
    )
}

/// Serve a session with an optional, single deterministic fault injection.
pub fn serve_session_with_faults(
    listener: &TcpListener,
    upstream: Option<SocketAddr>,
    limit: usize,
    timeout: Duration,
    max_messages: usize,
    faults: &FaultInjection,
) -> io::Result<ServerReport> {
    validate_limit(limit)?;
    if !(1..=MAX_MESSAGES_PER_SESSION).contains(&max_messages) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("messages per session must be 1..={MAX_MESSAGES_PER_SESSION}"),
        ));
    }
    if faults.truncate_response_after_bytes == Some(0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "truncate-response-bytes must be greater than zero",
        ));
    }
    if let Some(count) = faults.disconnect_after_messages {
        if count == 0 || count >= max_messages {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "close-after-messages must be less than the configured session message count",
            ));
        }
    }
    validate_loopback(listener.local_addr()?, "listener")?;
    if let Some(address) = upstream {
        validate_loopback(address, "upstream")?;
    }

    let mut client = accept_with_timeout(listener, timeout)?;
    configure_stream(&client, timeout)?;
    let mut upstream_stream: Option<TcpStream> = None;
    let mut bytes_received = 0_usize;
    let mut messages_processed = 0_usize;

    for _ in 0..max_messages {
        let request = match read_request(&mut client, limit) {
            Ok(payload) => payload,
            Err(error) => {
                let _ = write_error(&mut client, error.status);
                return Ok(ServerReport {
                    status: error.status,
                    bytes_received,
                    messages_processed,
                    relayed: upstream.is_some(),
                });
            }
        };
        messages_processed += 1;
        bytes_received = bytes_received.saturating_add(request.len());

        if bytes_received > MAX_SESSION_BYTES {
            let _ = write_error(&mut client, Status::PayloadTooLarge);
            return Ok(ServerReport {
                status: Status::PayloadTooLarge,
                bytes_received,
                messages_processed,
                relayed: upstream.is_some(),
            });
        }

        let response = if let Some(address) = upstream {
            let mut connection_error = None;
            if upstream_stream.is_none() {
                match TcpStream::connect_timeout(&address, timeout) {
                    Ok(stream) => match configure_stream(&stream, timeout) {
                        Ok(()) => upstream_stream = Some(stream),
                        Err(error) => connection_error = Some(status_for_io(&error)),
                    },
                    Err(error) => connection_error = Some(status_for_io(&error)),
                }
            }

            let outcome = if let Some(stream) = upstream_stream.as_mut() {
                forward_frame(stream, &request, limit)
            } else {
                Err(connection_error.unwrap_or(Status::UpstreamUnavailable))
            };
            match outcome {
                Ok(response) => response,
                Err(status) => {
                    upstream_stream = None;
                    error_response(status)
                }
            }
        } else {
            Response {
                status: Status::Ok,
                checksum: checksum(&request),
                payload: request,
            }
        };

        if !faults.response_delay.is_zero() {
            thread::sleep(faults.response_delay);
        }

        if let Some(truncate_after) = faults.truncate_response_after_bytes {
            let mut encoded = Vec::new();
            write_response(&mut encoded, response.status, &response.payload)?;
            if truncate_after >= encoded.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "truncate-response-bytes must be smaller than the encoded response",
                ));
            }
            client.write_all(&encoded[..truncate_after])?;
            client.shutdown(Shutdown::Write)?;
            return Ok(ServerReport {
                status: Status::InvalidFrame,
                bytes_received,
                messages_processed,
                relayed: upstream.is_some(),
            });
        }

        write_response(&mut client, response.status, &response.payload)?;

        if faults.disconnect_after_messages == Some(messages_processed) {
            client.shutdown(Shutdown::Both)?;
            return Ok(ServerReport {
                status: Status::Ok,
                bytes_received,
                messages_processed,
                relayed: upstream.is_some(),
            });
        }

        if response.status != Status::Ok {
            return Ok(ServerReport {
                status: response.status,
                bytes_received,
                messages_processed,
                relayed: upstream.is_some(),
            });
        }
    }

    Ok(ServerReport {
        status: Status::Ok,
        bytes_received,
        messages_processed,
        relayed: upstream.is_some(),
    })
}

fn error_response(status: Status) -> Response {
    Response {
        status,
        payload: Vec::new(),
        checksum: checksum(&[]),
    }
}

fn forward_frame(
    upstream: &mut TcpStream,
    request: &[u8],
    limit: usize,
) -> Result<Response, Status> {
    write_request(upstream, request).map_err(|error| status_for_io(&error))?;
    read_response(upstream, limit).map_err(|error| {
        if error.status == Status::Timeout {
            Status::Timeout
        } else {
            Status::UpstreamUnavailable
        }
    })
}

/// Send exactly one payload to a loopback node.
pub fn send_payload(
    address: SocketAddr,
    payload: &[u8],
    limit: usize,
    timeout: Duration,
) -> Result<Response, FrameError> {
    let responses = send_session(address, &[payload.to_vec()], limit, timeout)?;
    Ok(responses
        .into_iter()
        .next()
        .expect("single-message session returns one response"))
}

/// Send several payloads over one TCP connection and validate each framed response.
pub fn send_session(
    address: SocketAddr,
    payloads: &[Vec<u8>],
    limit: usize,
    timeout: Duration,
) -> Result<Vec<Response>, FrameError> {
    validate_limit(limit).map_err(|error| frame_error(Status::InvalidFrame, error.to_string()))?;
    validate_loopback(address, "destination")
        .map_err(|error| frame_error(Status::InvalidFrame, error.to_string()))?;
    if payloads.is_empty() || payloads.len() > MAX_MESSAGES_PER_SESSION {
        return Err(frame_error(
            Status::InvalidFrame,
            format!("message count must be 1..={MAX_MESSAGES_PER_SESSION}"),
        ));
    }

    let mut total_bytes = 0_usize;
    for payload in payloads {
        if payload.len() > limit || payload.len() > MAX_PAYLOAD_BYTES {
            return Err(frame_error(
                Status::PayloadTooLarge,
                "client payload exceeds configured limit",
            ));
        }
        total_bytes = total_bytes.saturating_add(payload.len());
        if total_bytes > MAX_SESSION_BYTES {
            return Err(frame_error(
                Status::PayloadTooLarge,
                "session payloads exceed the cumulative byte limit",
            ));
        }
    }

    let mut stream = TcpStream::connect_timeout(&address, timeout).map_err(|error| {
        frame_error(
            status_for_io(&error),
            format!("connect to {address}: {error}"),
        )
    })?;
    configure_stream(&stream, timeout)
        .map_err(|error| frame_error(status_for_io(&error), error.to_string()))?;

    let mut responses = Vec::with_capacity(payloads.len());
    for payload in payloads {
        write_request(&mut stream, payload)
            .map_err(|error| frame_error(status_for_io(&error), error.to_string()))?;
        let response = read_response(&mut stream, limit)?;
        let is_error = response.status != Status::Ok;
        responses.push(response);
        if is_error {
            break;
        }
    }
    Ok(responses)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn crc32_standard_check_value() {
        assert_eq!(checksum(b"123456789"), 0xcbf4_3926);
    }
    #[test]
    fn binary_request_and_response_round_trip() {
        let payload = [0, 255, 0, 1, 128, 10, 13];
        let mut request = Vec::new();
        write_request(&mut request, &payload).unwrap();
        assert_eq!(
            read_request(&mut Cursor::new(request), 64).unwrap(),
            payload
        );
        let mut response = Vec::new();
        write_response(&mut response, Status::Ok, &payload).unwrap();
        let decoded = read_response(&mut Cursor::new(response), 64).unwrap();
        assert_eq!(decoded.payload, payload);
        assert_eq!(decoded.checksum, checksum(&payload));
    }
    #[test]
    fn oversized_request_rejected_before_body_allocation() {
        let mut bytes = Vec::new();
        write_request(&mut bytes, &[7; 32]).unwrap();
        assert_eq!(
            read_request(&mut Cursor::new(bytes), 16)
                .unwrap_err()
                .status,
            Status::PayloadTooLarge
        );
    }
    #[test]
    fn corrupted_request_rejected() {
        let mut bytes = Vec::new();
        write_request(&mut bytes, b"correct").unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        assert_eq!(
            read_request(&mut Cursor::new(bytes), 64)
                .unwrap_err()
                .status,
            Status::ChecksumMismatch
        );
    }
    #[test]
    fn truncated_frame_rejected() {
        assert_eq!(
            read_request(&mut Cursor::new(b"HYD1\\x00"), 64)
                .unwrap_err()
                .status,
            Status::InvalidFrame
        );
    }
    #[test]
    fn non_loopback_target_rejected() {
        let address: SocketAddr = "192.0.2.1:1234".parse().unwrap();
        assert!(validate_loopback(address, "test").is_err());
    }
    #[test]
    fn relay_reports_closed_upstream() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let relay = listener.local_addr().unwrap();
        let closed = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let upstream = closed.local_addr().unwrap();
        drop(closed);
        let worker = thread::spawn(move || {
            serve_once(&listener, Some(upstream), 1024, Duration::from_secs(1)).unwrap()
        });
        let response = send_payload(relay, b"test", 1024, Duration::from_secs(1)).unwrap();
        assert_eq!(response.status, Status::UpstreamUnavailable);
        assert!(response.payload.is_empty());
        assert_eq!(worker.join().unwrap().status, Status::UpstreamUnavailable);
    }
    #[test]
    fn origin_enforces_configured_limit() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let worker =
            thread::spawn(move || serve_once(&listener, None, 8, Duration::from_secs(1)).unwrap());
        let response = send_payload(
            address,
            b"nine bytes",
            MAX_PAYLOAD_BYTES,
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(response.status, Status::PayloadTooLarge);
        assert_eq!(worker.join().unwrap().status, Status::PayloadTooLarge);
    }
}
