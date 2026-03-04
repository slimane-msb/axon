use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use clap::Parser;
use log::{info, warn};
use std::sync::Arc;
use tokio::signal;

#[derive(Parser)]
struct Opts {
    #[clap(short, long, default_value = "wlp8s0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opts = Opts::parse();
    env_logger::init();

    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/axon-runtime"
    ))?;

    let program: &mut Xdp = bpf.program_mut("xdp_firewall").unwrap().try_into()?;
    program.load()?;
    
    info!("Attaching XDP to {} in SKB mode...", opts.iface);
    program.attach(&opts.iface, XdpFlags::SKB_MODE)?;

    info!("Firewall active. Press Ctrl-C to stop.");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}