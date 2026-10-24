use hydra::transport::{
    send_payload, send_session, Status, DEFAULT_MAX_PAYLOAD_BYTES, DEFAULT_TIMEOUT_MS,
};
use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpListener};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::time::Duration;

struct RunningServer {
    child: Child,
    stdout: BufReader<ChildStdout>,
    address: SocketAddr,
}
impl RunningServer {
    fn start(args: &[&str]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_hydra-lab"))
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn controlled Hydra node");
        let stdout = child.stdout.take().expect("piped stdout");
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        reader.read_line(&mut line).expect("read readiness marker");
        assert!(line.starts_with("READY "), "node failed to start: {line:?}");
        let address = line.trim_start_matches("READY ").trim().parse().unwrap();
        Self {
            child,
            stdout: reader,
            address,
        }
    }

    fn wait_success(&mut self) {
        let status = self.child.wait().expect("wait for child node");
        assert!(status.success(), "node exited with {status}");
    }

    fn wait_failure(&mut self) {
        let status = self.child.wait().expect("wait for child node");
        assert!(!status.success(), "node should report a failed request");
    }

    fn wait_any(&mut self) {
        let _ = self.child.wait().expect("wait for child node");
    }
}
impl Drop for RunningServer {
    fn drop(&mut self) {
        let _keep_pipe_open = &self.stdout;
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_loopback_address() -> SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.local_addr().unwrap()
}

#[test]
fn three_process_route_transfers_binary_payload_through_relay() {
    let mut origin = RunningServer::start(&[
        "origin",
        "--listen",
        "127.0.0.1:0",
        "--timeout-ms",
        "5000",
        "--messages",
        "4",
    ]);
    let upstream = origin.address.to_string();
    let mut relay = RunningServer::start(&[
        "relay",
        "--listen",
        "127.0.0.1:0",
        "--upstream",
        &upstream,
        "--timeout-ms",
        "5000",
        "--messages",
        "4",
    ]);

    let payloads: Vec<Vec<u8>> = vec![
        (0..256 * 1024)
            .map(|index| ((index * 31 + index / 7) % 256) as u8)
            .collect(),
        (0..17 * 1024).map(|index| (index % 251) as u8).collect(),
        vec![0, 255, 0, 1, 128, 10, 13],
        b"fourth message in the same TCP session".to_vec(),
    ];
    let responses = send_session(
        relay.address,
        &payloads,
        DEFAULT_MAX_PAYLOAD_BYTES,
        Duration::from_millis(DEFAULT_TIMEOUT_MS),
    )
    .expect("send multiple frames over one client -> relay -> origin session");

    assert_eq!(responses.len(), payloads.len());
    for (response, payload) in responses.iter().zip(payloads.iter()) {
        assert_eq!(response.status, Status::Ok);
        assert_eq!(
            &response.payload, payload,
            "each session message must be byte-identical"
        );
        assert_eq!(response.checksum, hydra::transport::checksum(payload));
    }
    relay.wait_success();
    origin.wait_success();
}

#[test]
fn relay_reports_when_upstream_is_unavailable() {
    let unavailable = free_loopback_address();
    let mut relay = RunningServer::start(&[
        "relay",
        "--listen",
        "127.0.0.1:0",
        "--upstream",
        &unavailable.to_string(),
        "--timeout-ms",
        "1500",
    ]);
    let response = send_payload(
        relay.address,
        b"upstream failure probe",
        DEFAULT_MAX_PAYLOAD_BYTES,
        Duration::from_millis(1500),
    )
    .expect("relay should send a framed error response");
    assert_eq!(response.status, Status::UpstreamUnavailable);
    assert!(response.payload.is_empty());
    relay.wait_failure();
}

#[test]
fn origin_rejects_payload_larger_than_configured_limit() {
    let mut origin = RunningServer::start(&[
        "origin",
        "--listen",
        "127.0.0.1:0",
        "--max-bytes",
        "32",
        "--timeout-ms",
        "1500",
    ]);
    let response = send_payload(
        origin.address,
        &[0x5a; 33],
        128,
        Duration::from_millis(1500),
    )
    .expect("origin should send a framed size rejection");
    assert_eq!(response.status, Status::PayloadTooLarge);
    assert!(response.payload.is_empty());
    origin.wait_failure();
}

#[test]
fn truncated_upstream_response_is_not_reported_as_success() {
    let mut origin = RunningServer::start(&[
        "origin",
        "--listen",
        "127.0.0.1:0",
        "--timeout-ms",
        "2000",
        "--messages",
        "1",
        "--truncate-response-bytes",
        "7",
    ]);
    let upstream = origin.address.to_string();
    let mut relay = RunningServer::start(&[
        "relay",
        "--listen",
        "127.0.0.1:0",
        "--upstream",
        &upstream,
        "--timeout-ms",
        "2000",
        "--messages",
        "1",
    ]);

    let response = send_payload(
        relay.address,
        b"trigger truncated upstream frame",
        DEFAULT_MAX_PAYLOAD_BYTES,
        Duration::from_millis(2000),
    )
    .expect("relay should return a framed error after detecting truncation");
    assert_eq!(response.status, Status::UpstreamUnavailable);
    assert!(response.payload.is_empty());
    origin.wait_failure();
    relay.wait_failure();
}

#[test]
fn delayed_origin_is_reported_as_timeout() {
    let mut origin = RunningServer::start(&[
        "origin",
        "--listen",
        "127.0.0.1:0",
        "--timeout-ms",
        "2000",
        "--messages",
        "1",
        "--delay-ms",
        "700",
    ]);
    let upstream = origin.address.to_string();
    let mut relay = RunningServer::start(&[
        "relay",
        "--listen",
        "127.0.0.1:0",
        "--upstream",
        &upstream,
        "--timeout-ms",
        "200",
        "--messages",
        "1",
    ]);

    let response = send_payload(
        relay.address,
        b"this response should time out at the relay",
        DEFAULT_MAX_PAYLOAD_BYTES,
        Duration::from_millis(2000),
    )
    .expect("relay should send a framed timeout response");
    assert_eq!(response.status, Status::Timeout);
    assert!(response.payload.is_empty());
    relay.wait_failure();
    origin.wait_any();
}

#[test]
fn relay_disconnect_mid_session_is_reported_to_client() {
    let mut origin = RunningServer::start(&[
        "origin",
        "--listen",
        "127.0.0.1:0",
        "--timeout-ms",
        "1500",
        "--messages",
        "2",
    ]);
    let upstream = origin.address.to_string();
    let mut relay = RunningServer::start(&[
        "relay",
        "--listen",
        "127.0.0.1:0",
        "--upstream",
        &upstream,
        "--timeout-ms",
        "1500",
        "--messages",
        "4",
        "--close-after-messages",
        "2",
    ]);

    let payloads = vec![
        b"first complete frame".to_vec(),
        b"second complete frame".to_vec(),
        b"frame after injected disconnect".to_vec(),
        b"final frame".to_vec(),
    ];
    let outcome = send_session(
        relay.address,
        &payloads,
        DEFAULT_MAX_PAYLOAD_BYTES,
        Duration::from_millis(1500),
    );
    assert!(
        outcome.is_err(),
        "client must detect that the session ended early"
    );
    relay.wait_success();
    origin.wait_success();
}

#[test]
fn command_line_refuses_non_loopback_destinations() {
    let result = Command::new(env!("CARGO_BIN_EXE_hydra-lab"))
        .args([
            "send",
            "--connect",
            "192.0.2.1:3000",
            "--payload",
            "not sent",
        ])
        .output()
        .expect("run argument validation");
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("loopback"));
}
