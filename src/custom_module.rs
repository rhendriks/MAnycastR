use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use manycastr::{address::Value::Unicast, address::Value::V4, address::Value::V6, Address, IPv6};

pub mod manycastr {
    tonic::include_proto!("manycastr");
}

impl Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match &self.value {
            Some(V4(v4)) => Ipv4Addr::from(*v4).to_string(),
            Some(V6(v6)) => Ipv6Addr::new(
                (v6.high >> 48) as u16,
                (v6.high >> 32) as u16,
                (v6.high >> 16) as u16,
                v6.high as u16,
                (v6.low >> 48) as u16,
                (v6.low >> 32) as u16,
                (v6.low >> 16) as u16,
                v6.low as u16,
            )
            .to_string(),
            None => String::from("None"),
            Some(Unicast(_)) => "UNICAST".to_string(),
        };
        write!(f, "{str}")
    }
}

impl Address {
    pub fn is_v6(&self) -> bool {
        matches!(&self.value, Some(V6(_)))
    }

    pub fn is_unicast(&self) -> bool {
        matches!(&self.value, Some(Unicast(_)))
    }

    /// Get the prefix of the address
    ///
    /// /24 for IPv4 and /48 for IPv6
    ///
    #[allow(dead_code)]
    pub fn get_prefix(&self) -> u64 {
        match &self.value {
            Some(V4(v4)) => {
                // Return the sum of first 24 bits
                ((v4 >> 8) & 0x00FFFFFF).into()
            }
            Some(V6(v6)) => {
                // Return the sum of first 48 bits
                (v6.high >> 16) & 0x0000FFFFFFFF
            }
            _ => 0,
        }
    }

    /// Get the IPv4 address as u32
    ///
    /// Panic if the address is not IPv4
    pub fn get_v4(&self) -> u32 {
        match &self.value {
            Some(V4(v4)) => *v4,
            _ => panic!("Not a v4 address"),
        }
    }

    /// Get the IPv6 address as u128
    ///
    /// Panic if the address is not IPv6
    pub fn get_v6(&self) -> u128 {
        match &self.value {
            Some(V6(v6)) => (v6.high as u128) << 64 | v6.low as u128,
            _ => panic!("Not a v6 address"),
        }
    }

    /// Convert Address to bytes (big-endian)
    pub fn to_be_bytes(self) -> Vec<u8> {
        match self.value {
            Some(V4(_)) => self.get_v4().to_be_bytes().to_vec(),
            Some(V6(_)) => self.get_v6().to_be_bytes().to_vec(),
            _ => vec![],
        }
    }
}

// convert bytes into Address
impl From<&[u8]> for Address {
    fn from(bytes: &[u8]) -> Self {
        match bytes.len() {
            4 => {
                let mut ip = [0; 4];
                ip.copy_from_slice(bytes);
                Address {
                    value: Some(V4(u32::from_be_bytes(ip))),
                }
            }
            16 => {
                let mut ip = [0; 16];
                ip.copy_from_slice(bytes);
                Address {
                    value: Some(V6(IPv6 {
                        high: u64::from_be_bytes(ip[0..8].try_into().unwrap()),
                        low: u64::from_be_bytes(ip[8..16].try_into().unwrap()),
                    })),
                }
            }
            _ => panic!("Invalid IP address length"),
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

// Convert String into an Address
impl From<String> for Address {
    fn from(s: String) -> Self {
        if let Ok(ip) = s.parse::<IpAddr>() {
            // handle standard IP string format (e.g., 2001::1, 1.1.1.1)
            match ip {
                IpAddr::V4(v4_addr) => Address {
                    value: Some(V4(u32::from_be_bytes(v4_addr.octets()))),
                },
                IpAddr::V6(v6_addr) => Address {
                    value: Some(V6(IPv6 {
                        high: u64::from_be_bytes(v6_addr.octets()[0..8].try_into().unwrap()),
                        low: u64::from_be_bytes(v6_addr.octets()[8..16].try_into().unwrap()),
                    })),
                },
            }
        } else if let Ok(ip_number) = s.parse::<u128>() {
            // attempt to interpret as a raw IP number
            if ip_number <= u32::MAX as u128 {
                // IPv4
                Address {
                    value: Some(V4(ip_number as u32)),
                }
            } else {
                // IPv6
                Address {
                    value: Some(V6(IPv6 {
                        high: (ip_number >> 64) as u64, // Most significant 64 bits
                        low: (ip_number & 0xFFFFFFFFFFFFFFFF) as u64, // Least significant 64 bits
                    })),
                }
            }
        } else {
            panic!("Invalid IP address or IP number {s}");
        }
    }
}

impl From<&String> for Address {
    fn from(s: &String) -> Self {
        Address::from(s.to_string())
    }
}

impl From<&str> for Address {
    fn from(s: &str) -> Self {
        Address::from(s.to_string())
    }
}

impl From<IpAddr> for Address {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4_addr) => Address {
                value: Some(V4(u32::from_be_bytes(v4_addr.octets()))),
            },
            IpAddr::V6(v6_addr) => Address {
                value: Some(V6(IPv6 {
                    high: u64::from_be_bytes(v6_addr.octets()[0..8].try_into().unwrap()),
                    low: u64::from_be_bytes(v6_addr.octets()[8..16].try_into().unwrap()),
                })),
            },
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

impl Separated for u32 {
    fn with_separator(&self) -> String {
        format_number(*self as usize)
    }
}

impl Separated for usize {
    fn with_separator(&self) -> String {
        format_number(*self)
    }
}
