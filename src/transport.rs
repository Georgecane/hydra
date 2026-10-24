//! Bounded, loopback-only TCP transport experiment.
//! CRC-32 detects accidental corruption but does not authenticate peers.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

pub const DEFAULT_MAX_PAYLOAD_BYTES: usize = 1024 * 1024;
pub const MAX_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_TIMEOUT_MS: u64 = 3_000;
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
    pub relayed: bool,
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
pub fn serve_once(
    listener: &TcpListener,
    upstream: Option<SocketAddr>,
    limit: usize,
    timeout: Duration,
) -> io::Result<ServerReport> {
    validate_limit(limit)?;
    validate_loopback(listener.local_addr()?, "listener")?;
    if let Some(address) = upstream {
        validate_loopback(address, "upstream")?;
    }

    let mut client = accept_with_timeout(listener, timeout)?;
    configure_stream(&client, timeout)?;
    let request = match read_request(&mut client, limit) {
        Ok(payload) => payload,
        Err(e) => {
            let _ = write_error(&mut client, e.status);
            return Ok(ServerReport {
                status: e.status,
                bytes_received: 0,
                relayed: upstream.is_some(),
            });
        }
    };

    let response = if let Some(address) = upstream {
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(mut stream) => {
                if configure_stream(&stream, timeout).is_err()
                    || write_request(&mut stream, &request).is_err()
                {
                    Response {
                        status: Status::UpstreamUnavailable,
                        payload: Vec::new(),
                        checksum: checksum(&[]),
                    }
                } else {
                    match read_response(&mut stream, limit) {
                        Ok(response) => response,
                        Err(e) => Response {
                            status: if e.status == Status::Timeout {
                                Status::Timeout
                            } else {
                                Status::UpstreamUnavailable
                            },
                            payload: Vec::new(),
                            checksum: checksum(&[]),
                        },
                    }
                }
            }
            Err(e) => Response {
                status: if e.kind() == io::ErrorKind::TimedOut {
                    Status::Timeout
                } else {
                    Status::UpstreamUnavailable
                },
                payload: Vec::new(),
                checksum: checksum(&[]),
            },
        }
    } else {
        Response {
            status: Status::Ok,
            checksum: checksum(&request),
            payload: request.clone(),
        }
    };

    write_response(&mut client, response.status, &response.payload)?;
    Ok(ServerReport {
        status: response.status,
        bytes_received: request.len(),
        relayed: upstream.is_some(),
    })
}

/// Send one payload to a loopback lab node and validate the framed response.
pub fn send_payload(
    address: SocketAddr,
    payload: &[u8],
    limit: usize,
    timeout: Duration,
) -> Result<Response, FrameError> {
    validate_limit(limit).map_err(|e| frame_error(Status::InvalidFrame, e.to_string()))?;
    validate_loopback(address, "destination")
        .map_err(|e| frame_error(Status::InvalidFrame, e.to_string()))?;
    if payload.len() > limit || payload.len() > MAX_PAYLOAD_BYTES {
        return Err(frame_error(
            Status::PayloadTooLarge,
            "client payload exceeds configured limit",
        ));
    }
    let mut stream = TcpStream::connect_timeout(&address, timeout)
        .map_err(|e| frame_error(status_for_io(&e), format!("connect to {address}: {e}")))?;
    configure_stream(&stream, timeout)
        .map_err(|e| frame_error(status_for_io(&e), e.to_string()))?;
    write_request(&mut stream, payload)
        .map_err(|e| frame_error(status_for_io(&e), e.to_string()))?;
    read_response(&mut stream, limit)
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
