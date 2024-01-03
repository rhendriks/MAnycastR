use std::fmt::Display;
use std::net::{Ipv4Addr, Ipv6Addr};
pub mod verfploeter { tonic::include_proto!("verfploeter"); }
use verfploeter::{Address, address::Value::V4, address::Value::V6, IpResult, IPv6};

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

#[derive(Clone, Copy)]
#[derive(PartialEq)]
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
    pub fn is_v4(&self) -> bool {
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
    pub fn get_source_address_str(&self) -> String {
        match &self.value {
            Some(verfploeter::ip_result::Value::Ipv4(v4)) => v4.source_address.to_string(),
            Some(verfploeter::ip_result::Value::Ipv6(v6)) => {
                let source_address = v6.source_address.clone().expect("None IPv6 data type");
                ((source_address.p1 as u128) << 64 | source_address.p2 as u128).to_string()
            },
            None => String::from("None"),
        }
    }

    pub fn get_dest_address_str(&self) -> String {
        match &self.value {
            Some(verfploeter::ip_result::Value::Ipv4(v4)) => v4.destination_address.to_string(),
            Some(verfploeter::ip_result::Value::Ipv6(v6)) => {
                let destination_address = v6.destination_address.clone().expect("None IPv6 data type");
                ((destination_address.p1 as u128) << 64 | destination_address.p2 as u128).to_string()
            },
            None => String::from("None"),
        }
    }
}