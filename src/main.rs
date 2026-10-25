use hydra::adapter::{LoopbackTcpAdapter, TransportAdapter};
#[cfg(feature = "bale-carrier")]
use hydra::bale_carrier::{
    connect_to_peer, BaleCarrierListener, BaleLoginChallenge, BaleOtpProgress,
};
#[cfg(feature = "bale-carrier")]
use hydra::mesh::{FrameKind, MeshCipher, MeshNodeId};
use hydra::transport::{
    checksum, serve_session_with_faults, FaultInjection, Status, DEFAULT_MAX_PAYLOAD_BYTES,
    DEFAULT_TIMEOUT_MS, MAX_MESSAGES_PER_SESSION, MAX_PAYLOAD_BYTES,
};
use hydra::{LinkCapability, NodeId, TransportGraph};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process;
use std::time::Duration;
#[cfg(feature = "bale-carrier")]
use std::time::Instant;

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        return run_graph_demo();
    }

    let command = args[0].as_str();
    if matches!(command, "help" | "--help" | "-h") {
        print_help();
        return Ok(());
    }

    let options = parse_options(&args[1..])?;
    match command {
        "origin" => run_server(&options, false),
        "relay" => run_server(&options, true),
        "send" => run_client(&options),
        "keygen" => run_keygen(&options),
        #[cfg(feature = "bale-carrier")]
        "bale-login" => run_bale_login(&options),
        #[cfg(feature = "bale-carrier")]
        "bale-listen" => run_bale_listen(&options),
        #[cfg(feature = "bale-carrier")]
        "bale-connect" => run_bale_connect(&options),
        _ => Err(format!("unknown command {command:?}; run hydra-lab help")),
    }
}

fn run_graph_demo() -> Result<(), String> {
    let mut graph = TransportGraph::new();
    graph.add_link(
        "user-a",
        "internal-service",
        LinkCapability::FixedServiceApi,
    );
    graph.add_link(
        "internal-service",
        "public-origin",
        LinkCapability::ArbitraryPayloadRelay,
    );

    let source = NodeId::from("user-a");
    let destination = NodeId::from("public-origin");
    println!("Hydra transport feasibility lab");
    println!("Observed links: {}", graph.links().len());
    println!(
        "Links with unknown capability: {}",
        graph.unknown_link_count()
    );

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
    Ok(())
}

fn run_server(options: &HashMap<String, String>, is_relay: bool) -> Result<(), String> {
    let allowed: &[&str] = if is_relay {
        &[
            "listen",
            "upstream",
            "timeout-ms",
            "max-bytes",
            "messages",
            "delay-ms",
            "truncate-response-bytes",
            "close-after-messages",
        ]
    } else {
        &[
            "listen",
            "timeout-ms",
            "max-bytes",
            "messages",
            "delay-ms",
            "truncate-response-bytes",
            "close-after-messages",
        ]
    };
    ensure_keys(options, allowed)?;

    let listen = parse_loopback_addr(required(options, "listen")?, "listen")?;
    let timeout = parse_timeout(options)?;
    let max_bytes = parse_max_bytes(options)?;
    let max_messages = parse_messages(options)?;
    let faults = parse_faults(options, max_messages)?;
    let upstream = if is_relay {
        Some(parse_loopback_addr(
            required(options, "upstream")?,
            "upstream",
        )?)
    } else {
        None
    };

    let listener = TcpListener::bind(listen).map_err(|error| format!("bind {listen}: {error}"))?;
    let actual_address = listener
        .local_addr()
        .map_err(|error| format!("get bound address: {error}"))?;
    println!("READY {actual_address}");
    io::stdout()
        .flush()
        .map_err(|error| format!("flush readiness notification: {error}"))?;

    let report = serve_session_with_faults(
        &listener,
        upstream,
        max_bytes,
        timeout,
        max_messages,
        &faults,
    )
    .map_err(|error| format!("serve session: {error}"))?;
    let fault_label = if !faults.response_delay.is_zero() {
        format!("delay-{}ms", faults.response_delay.as_millis())
    } else if let Some(bytes) = faults.truncate_response_after_bytes {
        format!("truncate-after-{bytes}-bytes")
    } else if let Some(count) = faults.disconnect_after_messages {
        format!("disconnect-after-{count}-messages")
    } else {
        "none".to_owned()
    };
    println!(
        "RESULT status={} bytes={} messages={} relayed={} fault={}",
        report.status,
        report.bytes_received,
        report.messages_processed,
        report.relayed,
        fault_label
    );

    if report.status != Status::Ok {
        return Err(format!("node finished with status {}", report.status));
    }
    Ok(())
}

fn run_client(options: &HashMap<String, String>) -> Result<(), String> {
    ensure_keys(
        options,
        &[
            "connect",
            "timeout-ms",
            "max-bytes",
            "payload",
            "file",
            "messages",
        ],
    )?;
    if options.contains_key("payload") && options.contains_key("file") {
        return Err("choose either --payload or --file, not both".to_owned());
    }

    let address = parse_loopback_addr(required(options, "connect")?, "connect")?;
    let timeout = parse_timeout(options)?;
    let max_bytes = parse_max_bytes(options)?;
    let max_messages = parse_messages(options)?;
    let payload = if let Some(path) = options.get("file") {
        fs::read(path).map_err(|error| format!("read payload file {path:?}: {error}"))?
    } else if let Some(text) = options.get("payload") {
        text.as_bytes().to_vec()
    } else {
        b"Hydra local transport test".to_vec()
    };

    let payloads = vec![payload; max_messages];
    let adapter = LoopbackTcpAdapter::default();
    let responses = adapter
        .send_session(address, &payloads, max_bytes, timeout)
        .map_err(|error| error.to_string())?;

    for (index, response) in responses.iter().enumerate() {
        if response.status != Status::Ok {
            return Err(format!("message {index} returned {}", response.status));
        }
        if response.payload != payloads[index] {
            return Err(format!("integrity check failed for message {index}"));
        }
    }
    if responses.len() != payloads.len() {
        return Err(format!(
            "session ended early: expected {} responses, received {}",
            payloads.len(),
            responses.len()
        ));
    }

    let total_bytes: usize = responses
        .iter()
        .map(|response| response.payload.len())
        .sum();
    let quality = adapter.quality_snapshot();
    println!(
        "PASS status=Ok messages={} bytes={} checksum_last={:08x} latency_ms={} successes={} failures={} timeout_ms={}",
        responses.len(),
        total_bytes,
        checksum(&responses.last().expect("non-empty session").payload),
        quality.latency_ms.unwrap_or(0),
        quality.successes,
        quality.failures,
        timeout.as_millis()
    );
    Ok(())
}

#[cfg(feature = "bale-carrier")]
fn run_bale_login(options: &HashMap<String, String>) -> Result<(), String> {
    ensure_keys(options, &["phone", "token-file", "signup-name"])?;
    let phone = required(options, "phone")?.to_owned();
    let token_path = PathBuf::from(required(options, "token-file")?);
    let configured_name = options.get("signup-name").cloned();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("create Tokio runtime: {error}"))?;

    runtime.block_on(async move {
        let challenge = BaleLoginChallenge::begin(&token_path, &phone)
            .await
            .map_err(|error| error.to_string())?;
        let otp = prompt_line("Enter the one-time code received from Bale: ")?;
        match challenge
            .verify_otp(&otp)
            .await
            .map_err(|error| error.to_string())?
        {
            BaleOtpProgress::Authenticated => {
                println!("AUTHENTICATED token_file={}", token_path.display());
            }
            BaleOtpProgress::NeedsSignupName(challenge) => {
                let name = match configured_name {
                    Some(name) => name,
                    None => prompt_line("Bale requires a display name for this account: ")?,
                };
                challenge
                    .submit(&name)
                    .await
                    .map_err(|error| error.to_string())?;
                println!("AUTHENTICATED token_file={}", token_path.display());
            }
        }
        Ok(())
    })
}

#[cfg(feature = "bale-carrier")]
fn run_bale_listen(options: &HashMap<String, String>) -> Result<(), String> {
    ensure_keys(
        options,
        &[
            "token-file",
            "allow-peer",
            "key-file",
            "node-id-hex",
            "timeout-ms",
            "queue",
        ],
    )?;
    let token_path = PathBuf::from(required(options, "token-file")?);
    let allowed_peers = required(options, "allow-peer")?
        .split(',')
        .map(str::trim)
        .filter(|peer| !peer.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if allowed_peers.is_empty() {
        return Err("--allow-peer must contain at least one user peer ID".to_owned());
    }
    let key = load_mesh_key(required(options, "key-file")?)?;
    let local_node = MeshNodeId(parse_hex_32(
        required(options, "node-id-hex")?,
        "--node-id-hex",
    )?);
    let queue_capacity = parse_bale_queue(options)?;
    let timeout = parse_bale_timeout(options)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("create Tokio runtime: {error}"))?;

    runtime.block_on(async move {
        let mut listener =
            BaleCarrierListener::bind(&token_path, allowed_peers, queue_capacity, timeout)
                .await
                .map_err(|error| error.to_string())?;
        println!("READY carrier=bale-livekit mode=allowlisted-listener");
        loop {
            let (peer_id, carrier) = listener
                .accept_next(Duration::from_secs(24 * 60 * 60))
                .await
                .map_err(|error| error.to_string())?;
            println!("PEER_CONNECTED peer_id={peer_id}");
            tokio::spawn(serve_bale_echo(carrier, key, local_node));
        }
    })
}

#[cfg(feature = "bale-carrier")]
async fn serve_bale_echo(
    mut carrier: hydra::bale_carrier::BaleLiveKitCarrier,
    key: [u8; 32],
    local_node: MeshNodeId,
) {
    let cipher = MeshCipher::new(&key);
    loop {
        let frame = match carrier.receive_frame().await {
            Ok(frame) => frame,
            Err(error) => {
                eprintln!("Bale peer closed: {error}");
                break;
            }
        };
        if frame.kind != FrameKind::Data || frame.destination != local_node {
            continue;
        }
        let payload = match cipher.open(&frame) {
            Ok(payload) => payload,
            Err(error) => {
                eprintln!("Dropped unauthenticated MeshFrame: {error}");
                continue;
            }
        };
        let response = match cipher.seal(
            FrameKind::Acknowledgement,
            0,
            8,
            local_node,
            frame.source,
            local_node,
            frame.packet_id,
            frame.sequence,
            &payload,
        ) {
            Ok(response) => response,
            Err(error) => {
                eprintln!("Could not seal MeshFrame response: {error}");
                break;
            }
        };
        if let Err(error) = carrier.send_frame(&response) {
            eprintln!("Bale carrier send failed: {error}");
            break;
        }
    }
}

#[cfg(feature = "bale-carrier")]
fn run_bale_connect(options: &HashMap<String, String>) -> Result<(), String> {
    ensure_keys(
        options,
        &[
            "token-file",
            "peer-id",
            "key-file",
            "node-id-hex",
            "destination-node-id-hex",
            "message",
            "timeout-ms",
            "queue",
        ],
    )?;
    let token_path = PathBuf::from(required(options, "token-file")?);
    let peer_id = required(options, "peer-id")?.to_owned();
    let key = load_mesh_key(required(options, "key-file")?)?;
    let local_node = MeshNodeId(parse_hex_32(
        required(options, "node-id-hex")?,
        "--node-id-hex",
    )?);
    let destination = MeshNodeId(parse_hex_32(
        required(options, "destination-node-id-hex")?,
        "--destination-node-id-hex",
    )?);
    let message = options
        .get("message")
        .cloned()
        .unwrap_or_else(|| "Hydra carrier probe".to_owned());
    let queue_capacity = parse_bale_queue(options)?;
    let timeout = parse_bale_timeout(options)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("create Tokio runtime: {error}"))?;

    runtime.block_on(async move {
        let mut carrier = connect_to_peer(&token_path, &peer_id, queue_capacity, timeout)
            .await
            .map_err(|error| error.to_string())?;
        let cipher = MeshCipher::new(&key);
        let request = cipher
            .seal(
                FrameKind::Data,
                0,
                8,
                local_node,
                destination,
                local_node,
                1,
                0,
                message.as_bytes(),
            )
            .map_err(|error| error.to_string())?;
        let started = Instant::now();
        carrier
            .send_frame(&request)
            .map_err(|error| error.to_string())?;
        let response = tokio::time::timeout(timeout, carrier.receive_frame())
            .await
            .map_err(|_| "timed out waiting for encrypted Meshnet acknowledgement".to_owned())?
            .map_err(|error| error.to_string())?;
        if response.kind != FrameKind::Acknowledgement
            || response.source != destination
            || response.destination != local_node
            || response.packet_id != request.packet_id
            || response.sequence != request.sequence
        {
            return Err("received an unexpected Meshnet acknowledgement".to_owned());
        }
        let returned = cipher.open(&response).map_err(|error| error.to_string())?;
        if returned != message.as_bytes() {
            return Err("the returned payload did not match the sent payload".to_owned());
        }
        println!(
            "PASS carrier=bale-livekit authenticated_mesh_frame=true bytes={} rtt_ms={} peer_id={}",
            returned.len(),
            started.elapsed().as_millis(),
            peer_id
        );
        Ok(())
    })
}

#[cfg(feature = "bale-carrier")]
fn parse_hex_32(value: &str, label: &str) -> Result<[u8; 32], String> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if !value.is_ascii() || value.len() != 64 {
        return Err(format!(
            "{label} must be exactly 64 hexadecimal characters (32 bytes)"
        ));
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let pair =
            std::str::from_utf8(pair).map_err(|error| format!("invalid {label}: {error}"))?;
        bytes[index] = u8::from_str_radix(pair, 16)
            .map_err(|_| format!("{label} contains invalid hexadecimal data"))?;
    }
    Ok(bytes)
}

#[cfg(feature = "bale-carrier")]
fn parse_bale_queue(options: &HashMap<String, String>) -> Result<usize, String> {
    let queue = options
        .get("queue")
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|error| format!("invalid --queue: {error}"))?
        .unwrap_or(hydra::bale_carrier::DEFAULT_INBOUND_QUEUE_CAPACITY);
    if !(1..=hydra::bale_carrier::MAX_INBOUND_QUEUE_CAPACITY).contains(&queue) {
        return Err(format!(
            "--queue must be between 1 and {}",
            hydra::bale_carrier::MAX_INBOUND_QUEUE_CAPACITY
        ));
    }
    Ok(queue)
}

#[cfg(feature = "bale-carrier")]
fn parse_bale_timeout(options: &HashMap<String, String>) -> Result<Duration, String> {
    let millis = options
        .get("timeout-ms")
        .map(|value| value.parse::<u64>())
        .transpose()
        .map_err(|error| format!("invalid --timeout-ms: {error}"))?
        .unwrap_or(30_000);
    if !(1..=120_000).contains(&millis) {
        return Err("--timeout-ms must be between 1 and 120000".to_owned());
    }
    Ok(Duration::from_millis(millis))
}

#[cfg(feature = "bale-carrier")]
fn prompt_line(prompt: &str) -> Result<String, String> {
    use std::io::Write as _;
    print!("{prompt}");
    io::stdout()
        .flush()
        .map_err(|error| format!("flush prompt: {error}"))?;
    let mut value = String::new();
    io::stdin()
        .read_line(&mut value)
        .map_err(|error| format!("read terminal input: {error}"))?;
    let value = value.trim().to_owned();
    if value.is_empty() {
        Err("input must not be empty".to_owned())
    } else {
        Ok(value)
    }
}

fn run_keygen(options: &HashMap<String, String>) -> Result<(), String> {
    ensure_keys(options, &["key-file"])?;
    let path = PathBuf::from(required(options, "key-file")?);
    let mut key = [0_u8; 32];
    getrandom::fill(&mut key).map_err(|error| format!("generate secure random key: {error}"))?;

    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = Vec::with_capacity(65);
    for byte in key {
        encoded.push(HEX[(byte >> 4) as usize]);
        encoded.push(HEX[(byte & 0x0f) as usize]);
    }
    encoded.push(b'\n');

    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create key directory {}: {error}", parent.display()))?;
    }

    let mut file_options = fs::OpenOptions::new();
    file_options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        file_options.mode(0o600);
    }
    let mut file = file_options
        .open(&path)
        .map_err(|error| format!("create key file {}: {error}", path.display()))?;
    if let Err(error) = file.write_all(&encoded).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(&path);
        return Err(format!("write key file {}: {error}", path.display()));
    }
    println!(
        "KEY_CREATED path={} bytes=32 permissions=owner-only-on-unix",
        path.display()
    );
    Ok(())
}

#[cfg(feature = "bale-carrier")]
fn load_mesh_key(path: &str) -> Result<[u8; 32], String> {
    let encoded = fs::read_to_string(path)
        .map_err(|error| format!("read mesh key file {path:?}: {error}"))?;
    parse_hex_32(encoded.trim(), "mesh key file")
}

fn parse_options(args: &[String]) -> Result<HashMap<String, String>, String> {
    let mut options = HashMap::new();
    let mut index = 0;
    while index < args.len() {
        let key = args[index].as_str();
        if !key.starts_with("--") {
            return Err(format!("expected an option, got {key:?}"));
        }
        let value = args
            .get(index + 1)
            .ok_or_else(|| format!("missing value for {key}"))?;
        if value.starts_with("--") {
            return Err(format!("missing value for {key}"));
        }
        if options
            .insert(key.trim_start_matches("--").to_owned(), value.clone())
            .is_some()
        {
            return Err(format!("duplicate option {key}"));
        }
        index += 2;
    }
    Ok(options)
}

fn ensure_keys(options: &HashMap<String, String>, allowed: &[&str]) -> Result<(), String> {
    for key in options.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(format!("unknown option --{key}"));
        }
    }
    Ok(())
}

fn required<'a>(options: &'a HashMap<String, String>, key: &str) -> Result<&'a str, String> {
    options
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("missing required option --{key}"))
}

fn parse_loopback_addr(value: &str, label: &str) -> Result<SocketAddr, String> {
    let address: SocketAddr = value
        .parse()
        .map_err(|error| format!("invalid --{label} socket address {value:?}: {error}"))?;
    if !address.ip().is_loopback() {
        return Err(format!(
            "--{label} must use a loopback IP for this local-only experiment"
        ));
    }
    Ok(address)
}

fn parse_timeout(options: &HashMap<String, String>) -> Result<Duration, String> {
    let millis = match options.get("timeout-ms") {
        Some(value) => value
            .parse::<u64>()
            .map_err(|error| format!("invalid --timeout-ms value {value:?}: {error}"))?,
        None => DEFAULT_TIMEOUT_MS,
    };
    if !(1..=60_000).contains(&millis) {
        return Err("--timeout-ms must be between 1 and 60000".to_owned());
    }
    Ok(Duration::from_millis(millis))
}

fn parse_messages(options: &HashMap<String, String>) -> Result<usize, String> {
    let value = match options.get("messages") {
        Some(value) => value
            .parse::<usize>()
            .map_err(|error| format!("invalid --messages value {value:?}: {error}"))?,
        None => 1,
    };
    if !(1..=MAX_MESSAGES_PER_SESSION).contains(&value) {
        return Err(format!(
            "--messages must be between 1 and {MAX_MESSAGES_PER_SESSION}"
        ));
    }
    Ok(value)
}

fn parse_faults(
    options: &HashMap<String, String>,
    max_messages: usize,
) -> Result<FaultInjection, String> {
    let delay_ms = match options.get("delay-ms") {
        Some(value) => value
            .parse::<u64>()
            .map_err(|error| format!("invalid --delay-ms value {value:?}: {error}"))?,
        None => 0,
    };
    if delay_ms > 60_000 {
        return Err("--delay-ms must be between 0 and 60000".to_owned());
    }

    let truncate_response_after_bytes = match options.get("truncate-response-bytes") {
        Some(value) => {
            let bytes = value.parse::<usize>().map_err(|error| {
                format!("invalid --truncate-response-bytes value {value:?}: {error}")
            })?;
            if bytes == 0 || bytes > MAX_PAYLOAD_BYTES + 17 {
                return Err(format!(
                    "--truncate-response-bytes must be between 1 and {}",
                    MAX_PAYLOAD_BYTES + 17
                ));
            }
            Some(bytes)
        }
        None => None,
    };

    let disconnect_after_messages = match options.get("close-after-messages") {
        Some(value) => {
            let count = value.parse::<usize>().map_err(|error| {
                format!("invalid --close-after-messages value {value:?}: {error}")
            })?;
            if count == 0 || count >= max_messages {
                return Err(
                    "--close-after-messages must be at least 1 and less than --messages".to_owned(),
                );
            }
            Some(count)
        }
        None => None,
    };

    let mut enabled_faults = 0;
    if delay_ms > 0 {
        enabled_faults += 1;
    }
    if truncate_response_after_bytes.is_some() {
        enabled_faults += 1;
    }
    if disconnect_after_messages.is_some() {
        enabled_faults += 1;
    }
    if enabled_faults > 1 {
        return Err("configure only one fault-injection option per node".to_owned());
    }

    Ok(FaultInjection {
        response_delay: Duration::from_millis(delay_ms),
        truncate_response_after_bytes,
        disconnect_after_messages,
    })
}

fn parse_max_bytes(options: &HashMap<String, String>) -> Result<usize, String> {
    let value = match options.get("max-bytes") {
        Some(value) => value
            .parse::<usize>()
            .map_err(|error| format!("invalid --max-bytes value {value:?}: {error}"))?,
        None => DEFAULT_MAX_PAYLOAD_BYTES,
    };
    if !(1..=MAX_PAYLOAD_BYTES).contains(&value) {
        return Err(format!(
            "--max-bytes must be between 1 and {MAX_PAYLOAD_BYTES}"
        ));
    }
    Ok(value)
}

fn print_help() {
    println!("Hydra local transport experiment (loopback only)");
    println!();
    println!("Commands:");
    println!("  hydra-lab");
    println!("  hydra-lab origin --listen 127.0.0.1:4000 --messages 4");
    println!("  hydra-lab origin --listen 127.0.0.1:4000 --messages 1 --delay-ms 700");
    println!("  hydra-lab origin --listen 127.0.0.1:4000 --messages 1 --truncate-response-bytes 7");
    println!("  hydra-lab relay --listen 127.0.0.1:4001 --upstream 127.0.0.1:4000 --messages 4");
    println!("  hydra-lab relay --listen 127.0.0.1:4001 --upstream 127.0.0.1:4000 --messages 4 --close-after-messages 2");
    println!("  hydra-lab send --connect 127.0.0.1:4001 --payload 'hello Hydra'");
    println!("  hydra-lab send --connect 127.0.0.1:4001 --file ./payload.bin");
    println!("  hydra-lab keygen --key-file ~/.config/hydra/mesh.key");
    #[cfg(feature = "bale-carrier")]
    {
        println!("  hydra-lab bale-login --phone +<country-code><number> --token-file ~/.config/hydra/bale.token");
        println!("  hydra-lab bale-listen --token-file ~/.config/hydra/bale.token --allow-peer <user-id> --key-file <64-hex> --node-id-hex <64-hex>");
        println!("  hydra-lab bale-connect --token-file ~/.config/hydra/bale.token --peer-id <user-id> --key-file <64-hex> --node-id-hex <64-hex> --destination-node-id-hex <64-hex> --message 'hello Hydra'");
    }
    println!();
    println!("Each origin or relay serves one client connection and exits.");
    println!("Optional flags: --timeout-ms N --max-bytes N --messages N (1..={MAX_MESSAGES_PER_SESSION})");
    println!("Fault-injection flags (local tests only; choose one): --delay-ms N, --truncate-response-bytes N, --close-after-messages N");
    println!("Only loopback addresses are accepted. CRC-32 detects corruption; it is not authentication.");
}

#[cfg(test)]
mod keygen_tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn keygen_creates_private_key_without_overwriting() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after UNIX epoch")
            .as_nanos();
        let root = env::temp_dir().join(format!("hydra-keygen-{}-{unique}", process::id()));
        let key_path = root.join("nested").join("mesh.key");
        let mut options = HashMap::new();
        options.insert(
            "key-file".to_owned(),
            key_path.to_string_lossy().into_owned(),
        );

        run_keygen(&options).expect("keygen should create missing parent directories");
        let content = fs::read_to_string(&key_path).expect("read generated key file");
        let encoded = content.trim();
        assert_eq!(encoded.len(), 64);
        assert!(encoded.bytes().all(|byte| byte.is_ascii_hexdigit()));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        assert!(
            run_keygen(&options).is_err(),
            "keygen must not overwrite an existing key file"
        );
        fs::remove_dir_all(root).expect("remove keygen test directory");
    }
}
