use hydra::adapter::{LoopbackTcpAdapter, TransportAdapter};
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
use std::process;
use std::time::Duration;

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
    println!();
    println!("Each origin or relay serves one client connection and exits.");
    println!("Optional flags: --timeout-ms N --max-bytes N --messages N (1..={MAX_MESSAGES_PER_SESSION})");
    println!("Fault-injection flags (local tests only; choose one): --delay-ms N, --truncate-response-bytes N, --close-after-messages N");
    println!("Only loopback addresses are accepted. CRC-32 detects corruption; it is not authentication.");
}
