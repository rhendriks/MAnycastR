use crate::custom_module::manycastr::{MeasurementType, ProtocolType};
use manycastr::{address::Value::Unicast, address::Value::V4, address::Value::V6, Address, IPv6};
use std::fmt;
use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use socket2::SockAddr;

pub mod manycastr {
    tonic::include_proto!("manycastr");
}

/// Write Address to string (e.g., 1.1.1.1)
impl Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.value {
            Some(V4(v4)) => {
                write!(f, "{}", Ipv4Addr::from(*v4))
            }
            Some(V6(_)) => {
                let val: u128 = self.into();
                write!(f, "{}", Ipv6Addr::from(val))
            }
            Some(Unicast(_)) => write!(f, "UNICAST"),
            None => write!(f, "None"),
        }
    }
}

impl Address {
    /// Returns the integer representation of the IP address as u128.
    pub fn as_numeric(&self) -> u128 {
        match &self.value {
            Some(V4(v4)) => *v4 as u128,
            Some(V6(_)) => self.into(),
            _ => 0,
        }
    }

    pub fn is_v6(&self) -> bool {
        matches!(self.value, Some(V6(_)))
    }

    pub fn is_unicast(&self) -> bool {
        matches!(self.value, Some(Unicast(_)))
    }

    /// Get the prefix of the address (/24 for IPv4 and /48 for IPv6)
    pub fn get_prefix(&self) -> u64 {
        match &self.value {
            // /24: Shift right by 8 bits
            Some(V4(v4)) => (v4 >> 8) as u64,
            // /48: high is 64 bits, we want top 48. Shift right by (64 - 48) = 16
            Some(V6(v6)) => v6.high >> 16,
            _ => 0,
        }
    }

    /// Convert Address to bytes (big-endian)
    pub fn to_be_bytes(self) -> Vec<u8> {
        match &self.value {
            Some(V4(v4)) => v4.to_be_bytes().to_vec(),
            Some(V6(_)) => {
                let val: u128 = self.into();
                val.to_be_bytes().to_vec()
            }
            _ => vec![],
        }
    }
}

/// Address -> u32 (panic if not V4)
impl From<Address> for u32 {
    fn from(addr: Address) -> Self {
        match addr.value {
            Some(V4(v4)) => v4,
            _ => panic!("Attempted to convert non-IPv4 Address to u32"),
        }
    }
}

/// Address -> u128 (Panic if not V6)
impl From<Address> for u128 {
    fn from(addr: Address) -> Self {
        match addr.value {
            Some(V6(v6)) => (v6.high as u128) << 64 | v6.low as u128,
            _ => panic!("Attempted to convert non-IPv6 Address to u128"),
        }
    }
}

/// convert bytes into Address
impl From<&[u8]> for Address {
    fn from(bytes: &[u8]) -> Self {
        match bytes.len() {
            4 => {
                let array: [u8; 4] = bytes.try_into().unwrap();
                Address::from(array)
            }
            16 => {
                let array: [u8; 16] = bytes.try_into().unwrap();
                Address::from(array)
            }
            _ => panic!("Invalid IP address length: {}", bytes.len()),
        }
    }
}

impl From<[u8; 4]> for Address {
    fn from(bytes: [u8; 4]) -> Self {
        Address {
            value: Some(V4(u32::from_be_bytes(bytes))),
        }
    }
}

impl From<[u8; 16]> for Address {
    fn from(bytes: [u8; 16]) -> Self {
        Address {
            value: Some(V6(IPv6 {
                high: u64::from_be_bytes(bytes[0..8].try_into().unwrap()),
                low: u64::from_be_bytes(bytes[8..16].try_into().unwrap()),
            })),
        }
    }
}

impl From<u32> for Address {
    fn from(bytes: u32) -> Self {
        Address {
            value: Some(V4(bytes)),
        }
    }
}

impl From<u128> for Address {
    fn from(bytes: u128) -> Self {
        Address {
            value: Some(V6(IPv6 {
                high: (bytes >> 64) as u64,
                low: (bytes & 0xFFFFFFFFFFFFFFFF) as u64,
            })),
        }
    }
}

impl From<&Address> for u32 {
    fn from(addr: &Address) -> Self {
        match &addr.value {
            Some(V4(v4)) => *v4,
            _ => panic!("Attempted to convert non-IPv4 &Address to u32"),
        }
    }
}

impl From<&Address> for u128 {
    fn from(addr: &Address) -> Self {
        match &addr.value {
            Some(V6(v6)) => (v6.high as u128) << 64 | v6.low as u128,
            _ => panic!("Attempted to convert non-IPv6 &Address to u128"),
        }
    }
}

/// Convert String into an Address (can be an IP number or a standard IP string)
impl FromStr for Address {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Standard IP string format (e.g., "1.1.1.1" or "2001::1")
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok(Address::from(ip));
        }

        // IP number
        if let Ok(ip_number) = s.parse::<u128>() {
            return Ok(Address::from(ip_number));
        }

        Err(format!("Invalid IP address or IP number: {s}"))
    }
}

impl From<&str> for Address {
    fn from(s: &str) -> Self {
        s.parse().unwrap_or_else(|e| panic!("{}", e))
    }
}

impl From<String> for Address {
    fn from(s: String) -> Self {
        Address::from(s.as_str())
    }
}

impl From<&String> for Address {
    fn from(s: &String) -> Self {
        Address::from(s.as_str())
    }
}

/// Convert IpAddr to Address (used for converting local unicast addresses)
impl From<IpAddr> for Address {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => Address::from(u32::from(v4)),
            IpAddr::V6(v6) => Address::from(v6.octets()),
        }
    }
}

impl From<&Address> for IpAddr {
    fn from(addr: &Address) -> Self {
        match addr.value {
            Some(V4(v4_u32)) => IpAddr::V4(Ipv4Addr::from(v4_u32)),
            Some(V6(v6_msg)) => {
                let combined = ((v6_msg.high as u128) << 64) | (v6_msg.low as u128);
                IpAddr::V6(Ipv6Addr::from(combined))
            }
            _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED), // None and Unicast
        }
    }
}

pub trait Separated {
    fn with_separator(&self) -> String;
}

fn format_number(number: usize) -> String {
    let number_str = number.to_string();
    let chunks: Vec<&str> = number_str
        .as_bytes()
        .rchunks(3)
        .rev()
        .map(std::str::from_utf8)
        .collect::<Result<Vec<&str>, _>>()
        .expect("Unable to format number");

    chunks.join(",")
}

/// Print integer types with a thousand separator (e.g., 1000 -> 1,000)
macro_rules! impl_separated {
    ($($t:ty),*) => {
        $(
            impl Separated for $t {
                fn with_separator(&self) -> String {
                    format_number(*self as usize)
                }
            }
        )*
    };
}

impl_separated!(u32, usize, u64, i32);

/// Pretty print measurement types
impl Display for MeasurementType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Laces => "LACeS",
            Self::Verfploeter => "Verfploeter",
            Self::AnycastLatency => "Anycast Latency",
            Self::UnicastLatency => "Unicast Latency",
            Self::AnycastTraceroute => "Anycast Traceroute",
        };
        write!(f, "{}", s)
    }
}

impl MeasurementType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Laces => "laces",
            Self::Verfploeter => "verfploeter",
            Self::AnycastLatency => "latency",
            Self::UnicastLatency => "unicast",
            Self::AnycastTraceroute => "anycast-traceroute",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "laces" => Some(Self::Laces),
            "verfploeter" => Some(Self::Verfploeter),
            "latency" => Some(Self::AnycastLatency),
            "unicast" => Some(Self::UnicastLatency),
            "anycast-traceroute" => Some(Self::AnycastTraceroute),
            _ => None,
        }
    }
}

impl Display for ProtocolType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ProtocolType::Icmp => "ICMP",
            ProtocolType::ADns => "DNS (A)",
            ProtocolType::Tcp => "TCP",
            ProtocolType::ChaosDns => "DNS (CHAOS)",
        };
        write!(f, "{}", s)
    }
}

impl ProtocolType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProtocolType::Icmp => "icmp",
            ProtocolType::ADns => "dns",
            ProtocolType::Tcp => "tcp",
            ProtocolType::ChaosDns => "chaos",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "icmp" => Some(Self::Icmp),
            "dns" => Some(Self::ADns),
            "tcp" => Some(Self::Tcp),
            "chaos" => Some(Self::ChaosDns),
            _ => None,
        }
    }
}
