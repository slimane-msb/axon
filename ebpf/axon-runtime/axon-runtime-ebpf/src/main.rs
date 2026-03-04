#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, RingBuf},
    programs::XdpContext,
};
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use axon_runtime_common::{IpKey, DropEvent};

#[map]
static BLOCKED_IP_MAP: HashMap<IpKey, u8> = HashMap::with_max_entries(65536, 0);

#[map]
static MODE_MAP: HashMap<u32, u8> = HashMap::with_max_entries(64, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(16777216, 0);

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    if unsafe { (*ethhdr).ether_type } != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let src_ip = unsafe { (*ipv4hdr).src_addr };
    let dst_ip = unsafe { (*ipv4hdr).dst_addr };
    let protocol = unsafe { (*ipv4hdr).proto };
    let ifindex = unsafe { (*ctx.ctx).ingress_ifindex };

    let mode = MODE_MAP.get(&ifindex).copied().unwrap_or(0); 
    let key = IpKey { ifindex, ip: dst_ip };

    if let Some(_hit) = BLOCKED_IP_MAP.get(&key) {
        if mode == 0 { 
            return Ok(xdp_action::XDP_DROP);
        }
        return Ok(xdp_action::XDP_PASS); 
    }

    if mode == 1 {
        return Ok(xdp_action::XDP_DROP);
    }

    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end { return Err(()); }
    Ok((start + offset) as *const T)
}