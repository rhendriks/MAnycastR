use socket2::Socket;

// cBPF opcode bits (linux/filter.h, linux/bpf_common.h)
#[cfg(target_os = "linux")]
mod op {
    pub const LD: u16 = 0x00;
    pub const LDX: u16 = 0x01;
    pub const B: u16 = 0x10;
    pub const H: u16 = 0x08;
    pub const ABS: u16 = 0x20;
    pub const IND: u16 = 0x40;
    pub const MSH: u16 = 0xa0;
    pub const ALU: u16 = 0x04;
    pub const AND: u16 = 0x50;
    pub const RSH: u16 = 0x70;
    pub const JMP: u16 = 0x05;
    pub const JEQ: u16 = 0x10;
    pub const K: u16 = 0x00;
    pub const RET: u16 = 0x06;
}

#[cfg(target_os = "linux")]
const ACCEPT: u32 = 0xffff_ffff; // return value: keep the whole packet
#[cfg(target_os = "linux")]
const DROP: u32 = 0; // return value: drop the packet

#[cfg(target_os = "linux")]
#[inline]
fn sf(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// Attach a cBPF program to a socket via `SO_ATTACH_FILTER`.
/// The kernel copies the program during the call, so `prog` need only remain
/// valid for the duration of this function.
#[cfg(target_os = "linux")]
fn attach(socket: &Socket, prog: &mut [libc::sock_filter]) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;

    let fprog = libc::sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_mut_ptr(),
    };

    let ret = unsafe { // TODO unsafe
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &fprog as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
        )
    };

    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Attach a filter to a raw ICMP socket so the kernel only delivers ICMP echo
/// replies whose identifier matches `icmp_id`, dropping all other ICMP traffic.
///
/// # Arguments
/// * `socket` - the raw ICMP socket to attach the filter to
/// * `icmp_id` - the ICMP identifier used for this measurement
/// * `is_ipv6` - whether this is an IPv6 (ICMPv6) socket
#[cfg(target_os = "linux")]
pub(crate) fn attach_icmp_filter(
    socket: &Socket,
    icmp_id: u16,
    is_ipv6: bool,
) -> std::io::Result<()> {
    use op::*;

    const ICMP_ECHO_REPLY_V4: u32 = 0;
    const ICMP_ECHO_REPLY_V6: u32 = 129;
    let id = icmp_id as u32;

    let mut prog: Vec<libc::sock_filter> = if !is_ipv6 {
        vec![
            sf(LDX | B | MSH, 0, 0, 0), // X = IP header length
            sf(LD | B | IND, 0, 0, 0),  // A = ICMP type
            sf(JMP | JEQ | K, 0, 3, ICMP_ECHO_REPLY_V4), // type == 0 ? else -> drop
            sf(LD | H | IND, 0, 0, 4),  // A = ICMP identifier
            sf(JMP | JEQ | K, 0, 1, id), // id == icmp_id ? else -> drop
            sf(RET | K, 0, 0, ACCEPT),
            sf(RET | K, 0, 0, DROP),
        ]
    } else {
        vec![
            sf(LD | B | ABS, 0, 0, 0), // A = ICMPv6 type
            sf(JMP | JEQ | K, 0, 3, ICMP_ECHO_REPLY_V6), // type == 129 ? else -> drop
            sf(LD | H | ABS, 0, 0, 4), // A = identifier
            sf(JMP | JEQ | K, 0, 1, id), // id == icmp_id ? else -> drop
            sf(RET | K, 0, 0, ACCEPT),
            sf(RET | K, 0, 0, DROP),
        ]
    };

    attach(socket, &mut prog)
}

/// Attach a filter to a raw ICMP socket for traceroute measurements: deliver
/// only ICMP Time Exceeded (intermediate hops) and Echo Reply (final target)
/// packets, dropping all other ICMP (echo requests to the host, redirects, etc.).
///
/// # Arguments
/// * `socket` - the raw ICMP socket to attach the filter to
/// * `is_ipv6` - whether this is an IPv6 (ICMPv6) socket
#[cfg(target_os = "linux")]
pub(crate) fn attach_traceroute_filter(socket: &Socket, is_ipv6: bool) -> std::io::Result<()> {
    use op::*;

    const ICMP_ECHO_REPLY_V4: u32 = 0;
    const ICMP_TIME_EXCEEDED_V4: u32 = 11;
    const ICMP_ECHO_REPLY_V6: u32 = 129;
    const ICMP_TIME_EXCEEDED_V6: u32 = 3;

    let mut prog: Vec<libc::sock_filter> = if !is_ipv6 {
        vec![
            sf(LDX | B | MSH, 0, 0, 0), // X = IP header length
            sf(LD | B | IND, 0, 0, 0),  // A = ICMP type
            sf(JMP | JEQ | K, 1, 0, ICMP_TIME_EXCEEDED_V4), // type == 11 -> accept
            sf(JMP | JEQ | K, 0, 1, ICMP_ECHO_REPLY_V4), // type == 0 -> accept, else drop
            sf(RET | K, 0, 0, ACCEPT),
            sf(RET | K, 0, 0, DROP),
        ]
    } else {
        vec![
            sf(LD | B | ABS, 0, 0, 0), // A = ICMPv6 type
            sf(JMP | JEQ | K, 1, 0, ICMP_TIME_EXCEEDED_V6), // type == 3 -> accept
            sf(JMP | JEQ | K, 0, 1, ICMP_ECHO_REPLY_V6), // type == 129 -> accept, else drop
            sf(RET | K, 0, 0, ACCEPT),
            sf(RET | K, 0, 0, DROP),
        ]
    };

    attach(socket, &mut prog)
}

/// Attach a filter to a raw TCP socket so the kernel only delivers TCP segments
/// with the RST flag set whose destination port matches `sport` (the worker's
/// source port), dropping all other TCP traffic — which on a raw TCP socket
/// includes a copy of every TCP segment on the host (SSH, the gRPC control
/// connection to the orchestrator, etc.).
///
/// # Arguments
/// * `socket` - the raw TCP socket to attach the filter to
/// * `sport` - the worker's source port (TCP replies carry it as their dport)
/// * `is_ipv6` - whether this is an IPv6 socket
#[cfg(target_os = "linux")]
pub(crate) fn attach_tcp_filter(
    socket: &Socket,
    sport: u16,
    is_ipv6: bool,
) -> std::io::Result<()> {
    use op::*;

    const TCP_RST: u32 = 0x04; // RST flag in the TCP flags byte (offset 13)
    let dport = sport as u32;

    let mut prog: Vec<libc::sock_filter> = if !is_ipv6 {
        vec![
            sf(LDX | B | MSH, 0, 0, 0),   // X = IP header length
            sf(LD | H | IND, 0, 0, 2),    // A = TCP destination port
            sf(JMP | JEQ | K, 0, 4, dport), // dport == sport ? else -> drop
            sf(LD | B | IND, 0, 0, 13),   // A = TCP flags byte
            sf(ALU | AND | K, 0, 0, TCP_RST), // A = flags & RST
            sf(JMP | JEQ | K, 0, 1, TCP_RST), // RST set ? else -> drop
            sf(RET | K, 0, 0, ACCEPT),
            sf(RET | K, 0, 0, DROP),
        ]
    } else {
        vec![
            sf(LD | H | ABS, 0, 0, 2),    // A = TCP destination port
            sf(JMP | JEQ | K, 0, 4, dport), // dport == sport ? else -> drop
            sf(LD | B | ABS, 0, 0, 13),   // A = TCP flags byte
            sf(ALU | AND | K, 0, 0, TCP_RST), // A = flags & RST
            sf(JMP | JEQ | K, 0, 1, TCP_RST), // RST set ? else -> drop
            sf(RET | K, 0, 0, ACCEPT),
            sf(RET | K, 0, 0, DROP),
        ]
    };

    attach(socket, &mut prog)
}

/// Attach a filter to a raw UDP socket so the kernel only delivers DNS replies
/// destined to `sport` whose DNS transaction ID carries our 6-bit identifier,
/// dropping all other UDP traffic (e.g. the host's own DNS resolution).
///
/// # Arguments
/// * `socket` - the raw UDP socket to attach the filter to
/// * `sport` - the worker's source port (DNS replies carry it as their dport)
/// * `dns_identifier` - the 6-bit DNS identifier encoded in outgoing queries
/// * `is_ipv6` - whether this is an IPv6 socket
#[cfg(target_os = "linux")]
pub(crate) fn attach_dns_filter(
    socket: &Socket,
    sport: u16,
    dns_identifier: u8,
    is_ipv6: bool,
) -> std::io::Result<()> {
    use op::*;

    let dport = sport as u32;
    let id = dns_identifier as u32;

    let mut prog: Vec<libc::sock_filter> = if !is_ipv6 {
        vec![
            sf(LDX | B | MSH, 0, 0, 0),   // X = IP header length
            sf(LD | H | IND, 0, 0, 2),    // A = UDP destination port
            sf(JMP | JEQ | K, 0, 4, dport), // dport == sport ? else -> drop
            sf(LD | B | IND, 0, 0, 8),    // A = first byte of DNS transaction ID
            sf(ALU | RSH | K, 0, 0, 2),   // A = first_byte >> 2  (top 6 bits)
            sf(JMP | JEQ | K, 0, 1, id),  // identifier matches ? else -> drop
            sf(RET | K, 0, 0, ACCEPT),
            sf(RET | K, 0, 0, DROP),
        ]
    } else {
        vec![
            sf(LD | H | ABS, 0, 0, 2),    // A = UDP destination port
            sf(JMP | JEQ | K, 0, 4, dport), // dport == sport ? else -> drop
            sf(LD | B | ABS, 0, 0, 8),    // A = first byte of DNS transaction ID
            sf(ALU | RSH | K, 0, 0, 2),   // A = first_byte >> 2  (top 6 bits)
            sf(JMP | JEQ | K, 0, 1, id),  // identifier matches ? else -> drop
            sf(RET | K, 0, 0, ACCEPT),
            sf(RET | K, 0, 0, DROP),
        ]
    };

    attach(socket, &mut prog)
}

// --- Non-Linux stubs (cBPF socket filters are Linux-specific) -----------------

#[cfg(not(target_os = "linux"))]
pub(crate) fn attach_icmp_filter(
    _socket: &Socket,
    _icmp_id: u16,
    _is_ipv6: bool,
) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn attach_traceroute_filter(_socket: &Socket, _is_ipv6: bool) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn attach_tcp_filter(
    _socket: &Socket,
    _sport: u16,
    _is_ipv6: bool,
) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn attach_dns_filter(
    _socket: &Socket,
    _sport: u16,
    _dns_identifier: u8,
    _is_ipv6: bool,
) -> std::io::Result<()> {
    Ok(())
}
