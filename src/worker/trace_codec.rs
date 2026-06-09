pub(crate) struct TraceTag {
    /// Sending worker id (≤10 bits, up to 1024 workers).
    pub worker_id: u32,
    /// Probe TTL — the hop count that triggers the reply.
    pub ttl: u8,
    /// Low 14 bits of the send time in milliseconds.
    pub ts14: u16,
}

impl TraceTag {
    /// ICMP encoded in the ICMP identifier (16 bit) and sequence number (16 bit) fields
    /// UDP encoded in the IPv4 identifier or IPv6 flow label (16 bit) and UDP checksum (16 bit)
    pub fn encode_split(&self) -> (u16, u16) {
        let worker_hi = ((self.worker_id >> 8) & 0x03) as u16;
        let worker_lo = (self.worker_id & 0xFF) as u16;
        let id_field = (worker_hi << 14) | (self.ts14 & 0x3FFF);
        let seq_field = ((self.ttl as u16) << 8) | worker_lo;
        (id_field, seq_field)
    }

    /// Inverse of [`TraceTag::encode_split`].
    pub fn decode_split(id_field: u16, seq_field: u16) -> Self {
        let worker_hi = ((id_field >> 14) & 0x03) as u32;
        let worker_lo = (seq_field & 0xFF) as u32;
        TraceTag {
            worker_id: (worker_hi << 8) | worker_lo,
            ttl: (seq_field >> 8) as u8,
            ts14: id_field & 0x3FFF,
        }
    }

    /// Encoded in the 32 bit seq value for TCP
    pub fn encode_tcp_seq(&self) -> u32 {
        let worker10 = self.worker_id & 0x3FF;
        (worker10 << 22) | (((self.ttl as u32) & 0xFF) << 14) | (self.ts14 as u32 & 0x3FFF)
    }

    /// Inverse of [`TraceTag::encode_tcp_seq`].
    pub fn decode_tcp_seq(seq: u32) -> Self {
        TraceTag {
            worker_id: (seq >> 22) & 0x3FF,
            ttl: ((seq >> 14) & 0xFF) as u8,
            ts14: (seq & 0x3FFF) as u16,
        }
    }
}
