use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::ToSocketAddrs;
use std::process::{Command, Stdio};

fn resolve_to_ipv4(domain: &str) -> Vec<String> {
    let host = if domain.contains(':') { domain.to_string() } else { format!("{}:80", domain) };
    match host.to_socket_addrs() {
        Ok(addrs) => addrs
            .filter(|addr| addr.is_ipv4())
            .map(|addr| addr.ip().to_string())
            .collect(),
        Err(_) => Vec::new(),
    }
}

fn run_route_cmd(action: &str, ip: &str) {
    let _ = Command::new("sudo")
        .args(["route", action, "-host", ip, "reject"])
        .stderr(Stdio::null())
        .stdout(Stdio::null())
        .status();
}

fn stop_all_rejects() {
    // This parses the routing table for '!' or 'reject' flags and removes them
    let output = Command::new("netstat")
        .arg("-rn")
        .output()
        .expect("Failed to read routing table");

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        // Look for the '!' flag which signifies a 'reject' route on Linux
        if line.contains('!') || line.contains("reject") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if !parts.is_empty() {
                let ip = parts[0];
                println!("🧹 Clearing system-wide reject: {}", ip);
                run_route_cmd("del", ip);
            }
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 { return; }

    let mode = args.last().unwrap().as_str();

    match mode {
        "add" | "remove" => {
            let action = if mode == "add" { "add" } else { "del" };
            let ips = resolve_to_ipv4(&args[2]);
            for ip in ips {
                run_route_cmd(action, &ip);
                println!("{} {}: {}", if action == "add" { "🚫" } else { "✅" }, mode.to_uppercase(), ip);
            }
        }
        "file-add" | "file-remove" => {
            let action = if mode == "file-add" { "add" } else { "del" };
            if let Ok(file) = File::open(&args[2]) {
                for domain in BufReader::new(file).lines().filter_map(|l| l.ok()) {
                    let ips = resolve_to_ipv4(domain.trim());
                    for ip in ips {
                        run_route_cmd(action, &ip);
                        println!("{} {}: {} ({})", if action == "add" { "🚫" } else { "✅" }, action.to_uppercase(), domain, ip);
                    }
                }
            }
        }
        "stop" => {
            stop_all_rejects();
            println!("✨ All reject routes have been cleared from the system.");
        }
        _ => eprintln!("Unknown command: {}", mode),
    }
}