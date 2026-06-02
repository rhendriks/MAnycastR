//! Classic BPF (cBPF) socket filters for raw sockets.
//!
//! Attaching a cBPF program via `SO_ATTACH_FILTER` lets the kernel drop
//! irrelevant packets before they reach the socket receive buffer, replicating
//! the kernel-side identifier filtering that unprivileged ICMP datagram sockets
//! get for free.
//!
//! Classic BPF requires no privilege beyond owning the socket (unlike eBPF,
//! which needs CAP_BPF / CAP_SYS_ADMIN to load programs). Since raw sockets
//! already require CAP_NET_RAW, attaching the filter adds no extra privilege.

use socket2::Socket;

/// Attach a cBPF filter to a raw ICMP socket so the kernel only delivers ICMP
/// echo replies whose identifier matches `icmp_id`, dropping all other ICMP
/// traffic before it reaches the socket receive buffer.
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
    use std::os::fd::AsRawFd;

    // cBPF opcode bits (linux/filter.h, linux/bpf_common.h)
    const LD: u16 = 0x00;
    const LDX: u16 = 0x01;
    const B: u16 = 0x10;
    const H: u16 = 0x08;
    const ABS: u16 = 0x20;
    const IND: u16 = 0x40;
    const MSH: u16 = 0xa0;
    const JMP: u16 = 0x05;
    const JEQ: u16 = 0x10;
    const K: u16 = 0x00;
    const RET: u16 = 0x06;

    const ICMP_ECHO_REPLY_V4: u32 = 0;
    const ICMP_ECHO_REPLY_V6: u32 = 129;
    const ACCEPT: u32 = 0xffff_ffff; // return value: keep the whole packet
    const DROP: u32 = 0; // return value: drop the packet

    let sf = |code: u16, jt: u8, jf: u8, k: u32| libc::sock_filter { code, jt, jf, k };
    let id = icmp_id as u32;

    // Jump offsets (jt/jf) are relative to the NEXT instruction; on any
    // mismatch we jump straight to the final `RET DROP`.
    let mut prog: Vec<libc::sock_filter> = if !is_ipv6 {
        // IPv4 raw socket: received data INCLUDES the IP header (variable length),
        // so use BPF_MSH to compute the header length into X and index from there.
        vec![
            sf(LDX | B | MSH, 0, 0, 0), // X = 4 * (P[0] & 0x0f)  (IP header length)
            sf(LD | B | IND, 0, 0, 0),  // A = P[X+0]  ICMP type
            sf(JMP | JEQ | K, 0, 3, ICMP_ECHO_REPLY_V4), // type == 0 ? else -> drop
            sf(LD | H | IND, 0, 0, 4),  // A = P[X+4]  ICMP identifier (big-endian u16)
            sf(JMP | JEQ | K, 0, 1, id), // id == icmp_id ? else -> drop
            sf(RET | K, 0, 0, ACCEPT),  // accept
            sf(RET | K, 0, 0, DROP),    // drop
        ]
    } else {
        // IPv6 raw socket: the kernel STRIPS the IPv6 header, so the received
        // data starts at the ICMPv6 header — fixed offsets, no BPF_MSH needed.
        vec![
            sf(LD | B | ABS, 0, 0, 0), // A = P[0]   ICMPv6 type
            sf(JMP | JEQ | K, 0, 3, ICMP_ECHO_REPLY_V6), // type == 129 ? else -> drop
            sf(LD | H | ABS, 0, 0, 4), // A = P[4]   identifier
            sf(JMP | JEQ | K, 0, 1, id), // id == icmp_id ? else -> drop
            sf(RET | K, 0, 0, ACCEPT), // accept
            sf(RET | K, 0, 0, DROP),   // drop
        ]
    };

    let fprog = libc::sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_mut_ptr(),
    };

    // The kernel copies the program during setsockopt, so `prog` only needs to
    // remain valid for the duration of this call.
    let ret = unsafe {
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

/// No-op on non-Linux platforms (cBPF socket filters are Linux-specific).
#[cfg(not(target_os = "linux"))]
pub(crate) fn attach_icmp_filter(
    _socket: &Socket,
    _icmp_id: u16,
    _is_ipv6: bool,
) -> std::io::Result<()> {
    Ok(())
}
