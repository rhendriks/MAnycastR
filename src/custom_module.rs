use std::fmt::Display;
use std::net::{Ipv4Addr, Ipv6Addr};

use verfploeter::{Address, address::Value::V4, address::Value::V6, IpResult, IPv6};

pub mod verfploeter { tonic::include_proto!("verfploeter"); }

impl Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match &self.value {
            Some(V4(v4)) => v4.to_string(),
            Some(V6(v6)) => v6.to_string(),
            None => String::from("None"),
        };
        write!(f, "{}", str)
    }
}

impl Address {
    pub fn is_v6(&self) -> bool {
        match &self.value {
            Some(V6(_)) => true,
            _ => false,
        }
    }

    /// Get the prefix of the address
    ///
    /// /24 for IPv4 and /48 for IPv6
    ///
    pub fn get_prefix(&self) -> u64 {
        match &self.value {
            Some(V4(v4)) => {
                // Return the sum of first 24 bits
                ((v4 >> 8) & 0x00FFFFFF).into()
            },
            Some(V6(v6)) => {
                // Return the sum of first 48 bits
                (v6.p1 >> 16) & 0x0000FFFFFFFF
            },
            None => 0,
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[derive(Eq, Hash, PartialEq)]
pub enum IP {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    None,
}

impl From<Address> for IP {
    fn from(address: Address) -> Self {
        match address.value {
            Some(V4(v4)) => IP::V4(v4.into()),
            Some(V6(v6)) => IP::V6(Ipv6Addr::new(
                (v6.p1 >> 48) as u16,
                (v6.p1 >> 32) as u16,
                (v6.p1 >> 16) as u16,
                v6.p1 as u16,
                (v6.p2 >> 48) as u16,
                (v6.p2 >> 32) as u16,
                (v6.p2 >> 16) as u16,
                v6.p2 as u16,
            )),
            None => IP::None,
        }
    }
}

impl IP {
    pub fn _is_v4(&self) -> bool {
        match self {
            IP::V4(_) => true,
            _ => false,
        }
    }

    pub fn is_v6(&self) -> bool {
        match self {
            IP::V6(_) => true,
            _ => false,
        }
    }

    pub fn get_v4(&self) -> Ipv4Addr {
        match self {
            IP::V4(v4) => *v4,
            _ => panic!("Not a v4 address"),
        }
    }

    pub fn get_v6(&self) -> Ipv6Addr {
        match self {
            IP::V6(v6) => *v6,
            _ => panic!("Not a v6 address"),
        }
    }
}

impl From<IP> for Address {
    fn from(ip: IP) -> Self {
        match ip {
            IP::V4(v4) => Address {
                value: Some(V4(u32::from(v4))),
            },
            IP::V6(v6) => Address {
                value: Some(V6(IPv6 {
                    p1: (v6.segments()[0] as u64) << 48
                        | (v6.segments()[1] as u64) << 32
                        | (v6.segments()[2] as u64) << 16
                        | (v6.segments()[3] as u64),
                    p2: (v6.segments()[4] as u64) << 48
                        | (v6.segments()[5] as u64) << 32
                        | (v6.segments()[6] as u64) << 16
                        | (v6.segments()[7] as u64),
                })),
            },
            IP::None => Address {
                value: None,
            },
        }
    }
}

// convert bytes into Address
impl From<&[u8]> for Address {
    fn from(bytes: &[u8]) -> Self {
        match bytes.len() {
            4 => {
                let mut ip = [0; 4];
                ip.copy_from_slice(&bytes);
                Address {
                    value: Some(V4(u32::from_be_bytes(ip))),
                }
            },
            16 => {
                let mut ip = [0; 16];
                ip.copy_from_slice(&bytes);
                Address {
                    value: Some(V6(IPv6 {
                        p1: u64::from_be_bytes(ip[0..8].try_into().unwrap()),
                        p2: u64::from_be_bytes(ip[8..16].try_into().unwrap()),
                    })),
                }
            },
            _ => panic!("Invalid IP address length"),
        }
    }
}

impl Display for IP {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            IP::V4(v4) => v4.to_string(),
            IP::V6(v6) => v6.to_string(),
            IP::None => String::from("None"),
        };
        write!(f, "{}", str)
    }
}

impl From<String> for IP {
    fn from(s: String) -> Self {
        match s.parse::<Ipv4Addr>() {
            Ok(v4) => IP::V4(v4),
            Err(_) => match s.parse::<Ipv6Addr>() {
                Ok(v6) => IP::V6(v6),
                Err(_) => panic!("Invalid IP address: {}", s),
            },
        }
    }
}

impl Display for IPv6 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = ((self.p1 as u128) << 64 | self.p2 as u128).to_string();
        write!(f, "{}", str)
    }
}

impl IpResult {
    pub fn get_src_str(&self) -> String {
        match &self.value {
            Some(verfploeter::ip_result::Value::Ipv4(v4)) => v4.src.to_string(),
            Some(verfploeter::ip_result::Value::Ipv6(v6)) => {
                let src = v6.src.clone().expect("None IPv6 data type");
                ((src.p1 as u128) << 64 | src.p2 as u128).to_string()
            }
            None => String::from("None"),
        }
    }

    pub fn get_dst_str(&self) -> String {
        match &self.value {
            Some(verfploeter::ip_result::Value::Ipv4(v4)) => v4.dst.to_string(),
            Some(verfploeter::ip_result::Value::Ipv6(v6)) => {
                let dst = v6.dst.clone().expect("None IPv6 data type");
                ((dst.p1 as u128) << 64 | dst.p2 as u128).to_string()
            }
            None => String::from("None"),
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
