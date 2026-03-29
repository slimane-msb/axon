use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

const LIST_FILE: &str = "/tmp/sinkhole-ctl.list";
const PID_FILE: &str = "/tmp/sinkhole-ctl.pid";
const SOCKET_PATH: &str = "/tmp/sinkhole-ctl.sock";

fn write_list(list: &[String]) {
    fs::write(LIST_FILE, list.join("\n") + "\n").expect("failed to write list");
}

fn normalize(host: &str) -> String {
    host.trim_start_matches("www.").to_string()
}

fn sinkhole_bin() -> std::path::PathBuf {
    std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .join("sinkhole")
}

fn spawn_sinkhole(list: &[String]) -> Child {
    let mut child = Command::new("sudo")
        .arg(sinkhole_bin())
        .args(list)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start sinkhole");

    if let Some(stderr) = child.stderr.take() {
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().flatten() {
                eprintln!("{}", line);
            }
        });
    }

    child
}

fn reload_sinkhole() {
    let pid_str = match fs::read_to_string(PID_FILE) {
        Ok(s) => s.trim().to_string(),
        Err(e) => {
            eprintln!("[ctl] cannot read pid file: {}", e);
            return;
        }
    };
    let status = Command::new("sudo")
        .args(["kill", "-USR1", &pid_str])
        .status();
    match status {
        Ok(s) if s.success() => eprintln!("[ctl] sent SIGUSR1 to pid {}", pid_str),
        Ok(s) => eprintln!("[ctl] kill -USR1 {} exited {}", pid_str, s),
        Err(e) => eprintln!("[ctl] kill -USR1 {} failed: {}", pid_str, e),
    }
    std::thread::sleep(std::time::Duration::from_millis(50));
}

fn run_supervisor(initial: Vec<String>) {
    write_list(&initial);

    let list = Arc::new(Mutex::new(initial.clone()));
    let child = Arc::new(Mutex::new(spawn_sinkhole(&initial)));

    std::thread::sleep(std::time::Duration::from_millis(500));

    let _ = fs::remove_file(SOCKET_PATH);
    let listener = UnixListener::bind(SOCKET_PATH).expect("failed to bind socket");

    for stream in listener.incoming().flatten() {
        let list = Arc::clone(&list);
        let _child = Arc::clone(&child);

        let mut reader = BufReader::new(&stream);
        let mut writer = &stream;
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() {
            continue;
        }

        let parts: Vec<&str> = line.trim().splitn(2, ' ').collect();
        let response = match parts.as_slice() {
            ["add", domain] => {
                let d = normalize(domain);
                let mut l = list.lock().unwrap();
                if !l.contains(&d) {
                    l.push(d.clone());
                }
                write_list(&l);
                drop(l);
                reload_sinkhole();
                format!("added: {}\n", d)
            }
            ["remove", domain] => {
                let d = normalize(domain);
                let mut l = list.lock().unwrap();
                l.retain(|x| x != &d);
                write_list(&l);
                drop(l);
                reload_sinkhole();
                format!("removed: {}\n", d)
            }
            ["file-add", path] => match fs::read_to_string(path) {
                Ok(contents) => {
                    let mut l = list.lock().unwrap();
                    for entry in contents.lines() {
                        let d = normalize(entry.trim());
                        if !d.is_empty() && !l.contains(&d) {
                            l.push(d);
                        }
                    }
                    write_list(&l);
                    drop(l);
                    reload_sinkhole();
                    format!("file-add done: {}\n", path)
                }
                Err(_) => format!("error: cannot read {}\n", path),
            },
            ["file-remove", path] => match fs::read_to_string(path) {
                Ok(contents) => {
                    let mut l = list.lock().unwrap();
                    let to_remove: Vec<String> = contents
                        .lines()
                        .map(|e| normalize(e.trim()))
                        .filter(|e| !e.is_empty())
                        .collect();
                    l.retain(|x| !to_remove.contains(x));
                    write_list(&l);
                    drop(l);
                    reload_sinkhole();
                    format!("file-remove done: {}\n", path)
                }
                Err(_) => format!("error: cannot read {}\n", path),
            },
            _ => "unknown command\n".to_string(),
        };

        writer.write_all(response.as_bytes()).ok();
    }
}

fn send_command(args: &[String]) {
    let mut stream =
        UnixStream::connect(SOCKET_PATH).expect("failed to connect — is ctl running?");
    writeln!(stream, "{}", args.join(" ")).unwrap();
    let mut resp = String::new();
    BufReader::new(&stream).read_line(&mut resp).unwrap();
    print!("{}", resp);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()) {
        Some("add") | Some("remove") | Some("file-add") | Some("file-remove") => {
            send_command(&args);
        }
        _ => {
            run_supervisor(args);
        }
    }
}