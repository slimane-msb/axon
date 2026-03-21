use std::collections::HashSet;
use std::sync::Arc;
use nfq::{Queue, Verdict};
use etherparse::{SlicedPacket, TransportSlice};

fn extract_http_host(payload: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(payload).ok()?;
    for line in text.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("host:") {
            let host = line[5..].trim().to_string();
            let host = host.split(':').next()?.trim().to_lowercase();
            return Some(host);
        }
    }
    None
}

fn extract_tls_sni(payload: &[u8]) -> Option<String> {
    if payload.len() < 5 || payload[0] != 0x16 {
        return None;
    }
    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if payload.len() < 5 + record_len {
        return None;
    }
    let handshake = &payload[5..5 + record_len];
    if handshake.is_empty() || handshake[0] != 0x01 || handshake.len() < 4 {
        return None;
    }
    let hs_len = u32::from_be_bytes([0, handshake[1], handshake[2], handshake[3]]) as usize;
    if handshake.len() < 4 + hs_len {
        return None;
    }
    let hello = &handshake[4..4 + hs_len];
    if hello.len() < 34 {
        return None;
    }
    let mut pos = 34;
    if pos >= hello.len() {
        return None;
    }
    let session_id_len = hello[pos] as usize;
    pos += 1 + session_id_len;
    if pos + 2 > hello.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
    pos += 2 + cs_len;
    if pos >= hello.len() {
        return None;
    }
    let cm_len = hello[pos] as usize;
    pos += 1 + cm_len;
    if pos + 2 > hello.len() {
        return None;
    }
    let ext_total_len = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_total_len;
    if ext_end > hello.len() {
        return None;
    }
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([hello[pos], hello[pos + 1]]);
        let ext_len = u16::from_be_bytes([hello[pos + 2], hello[pos + 3]]) as usize;
        pos += 4;
        if ext_type == 0x0000 {
            if pos + 2 > hello.len() {
                return None;
            }
            let list_len = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
            let mut sni_pos = pos + 2;
            let sni_end = sni_pos + list_len;
            while sni_pos + 3 <= sni_end {
                let name_type = hello[sni_pos];
                let name_len =
                    u16::from_be_bytes([hello[sni_pos + 1], hello[sni_pos + 2]]) as usize;
                sni_pos += 3;
                if name_type == 0 && sni_pos + name_len <= hello.len() {
                    let name =
                        std::str::from_utf8(&hello[sni_pos..sni_pos + name_len]).ok()?;
                    return Some(name.to_lowercase());
                }
                sni_pos += name_len;
            }
        }
        if pos + ext_len > ext_end {
            break;
        }
        pos += ext_len;
    }
    None
}

fn extract_dns_query_name(payload: &[u8]) -> Option<String> {
    if payload.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    if flags & 0x8000 != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut pos = 12;
    let mut labels: Vec<String> = Vec::new();
    loop {
        if pos >= payload.len() {
            return None;
        }
        let len = payload[pos] as usize;
        if len == 0 {
            break;
        }
        if len & 0xC0 == 0xC0 {
            return None;
        }
        pos += 1;
        if pos + len > payload.len() {
            return None;
        }
        let label = std::str::from_utf8(&payload[pos..pos + len]).ok()?;
        labels.push(label.to_string());
        pos += len;
    }
    if labels.is_empty() {
        return None;
    }
    Some(labels.join(".").to_lowercase())
}

fn normalize(host: &str) -> &str {
    host.trim_start_matches("www.")
}

fn is_blocked(hostname: &str, blocked: &HashSet<String>) -> bool {
    let bare = normalize(hostname);
    blocked.contains(bare)
        || blocked.contains(&format!("www.{}", bare))
        || blocked.contains(hostname)
}

fn handle_tcp(dport: u16, payload: &[u8], blocked: &Arc<HashSet<String>>) -> Verdict {
    if payload.is_empty() {
        return Verdict::Accept;
    }
    let hostname = match dport {
        80 => extract_http_host(payload),
        443 => extract_tls_sni(payload),
        _ => return Verdict::Accept,
    };
    match hostname {
        Some(ref h) if is_blocked(h, blocked) => {
            eprintln!("[DROP TCP:{}] {}", dport, h);
            Verdict::Drop
        }
        Some(ref h) => {
            eprintln!("[PASS TCP:{}] {}", dport, h);
            Verdict::Accept
        }
        None => Verdict::Accept,
    }
}

fn handle_udp(dport: u16, payload: &[u8], blocked: &Arc<HashSet<String>>) -> Verdict {
    match dport {
        53 => match extract_dns_query_name(payload) {
            Some(ref name) if is_blocked(name, blocked) => {
                eprintln!("[DROP DNS] {}", name);
                Verdict::Drop
            }
            Some(ref name) => {
                eprintln!("[PASS DNS] {}", name);
                Verdict::Accept
            }
            None => Verdict::Accept,
        },
        443 => {
            eprintln!("[DROP QUIC] forcing TCP fallback");
            Verdict::Drop
        }
        _ => Verdict::Accept,
    }
}

fn decide(raw_ip: &[u8], blocked: &Arc<HashSet<String>>) -> Verdict {
    let packet = match SlicedPacket::from_ip(raw_ip) {
        Ok(p) => p,
        Err(_) => return Verdict::Accept,
    };
    match &packet.transport {
        Some(TransportSlice::Tcp(tcp)) => {
            handle_tcp(tcp.destination_port(), tcp.payload(), blocked)
        }
        Some(TransportSlice::Udp(udp)) => {
            handle_udp(udp.destination_port(), udp.payload(), blocked)
        }
        _ => Verdict::Accept,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("Usage: l7block <domain> [domain2] ...");
        eprintln!();
        eprintln!("Setup (run as root):");
        eprintln!("  iptables -I OUTPUT  -p tcp --dport 80  -j NFQUEUE --queue-num 0");
        eprintln!("  iptables -I OUTPUT  -p tcp --dport 443 -j NFQUEUE --queue-num 0");
        eprintln!("  iptables -I OUTPUT  -p udp --dport 53  -j NFQUEUE --queue-num 0");
        eprintln!("  iptables -I OUTPUT  -p udp --dport 443 -j NFQUEUE --queue-num 0");
        eprintln!("  iptables -I FORWARD -p tcp --dport 80  -j NFQUEUE --queue-num 0");
        eprintln!("  iptables -I FORWARD -p tcp --dport 443 -j NFQUEUE --queue-num 0");
        eprintln!("  iptables -I FORWARD -p udp --dport 53  -j NFQUEUE --queue-num 0");
        eprintln!("  iptables -I FORWARD -p udp --dport 443 -j NFQUEUE --queue-num 0");
        std::process::exit(1);
    }

    let blocked: Arc<HashSet<String>> = Arc::new(
        args.iter()
            .map(|s| normalize(s.as_str()).to_string())
            .collect(),
    );

    eprintln!("L7 blocker active. Blocked: {:?}", blocked);

    let mut queue = Queue::open().expect("Failed to open NFQUEUE — run as root");
    queue.bind(0).expect("Failed to bind queue 0");

    loop {
        let mut msg = match queue.recv() {
            Ok(m) => m,
            Err(e) => {
                eprintln!("recv error: {}", e);
                continue;
            }
        };
        let verdict = decide(msg.get_payload(), &blocked);
        msg.set_verdict(verdict);
        if let Err(e) = queue.verdict(msg) {
            eprintln!("verdict error: {}", e);
        }
    }
}