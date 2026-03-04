#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IpKey {
    pub ifindex: u32,
    pub ip: u32, // Network byte order
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DropEvent {
    pub ifindex: u32,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub rule_type: u8, // 0=explicit, 1=tentative, 2=shared, 3=mode
    pub action: u8,    // 1=Drop, 0=Pass
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for IpKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for DropEvent {}