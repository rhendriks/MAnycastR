use std::net::{Ipv4Addr, Ipv6Addr};
pub mod verfploeter { tonic::include_proto!("verfploeter"); }
use verfploeter::{Address, address::Value::V4, address::Value::V6, IpResult, IPv4Result, IPv6Result, IPv6};

#[derive(Clone)]
#[derive(PartialEq)]
pub(crate) enum IP {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    None,
}

impl From<Address> for IP {
    // TODO untested
    fn from(address: Address) -> Self {
        match address.value.unwrap() {
            V4(v4) => IP::V4(v4.into()),
            V6(v6) => IP::V6(Ipv6Addr::new(
                (v6.p1 >> 48) as u16,
                (v6.p1 >> 32) as u16,
                (v6.p1 >> 16) as u16,
                v6.p1 as u16,
                (v6.p2 >> 48) as u16,
                (v6.p2 >> 32) as u16,
                (v6.p2 >> 16) as u16,
                v6.p2 as u16,
            )),
        }
    }
}

impl From<IP> for Address {
    fn from(ip: IP) -> Self {
        match ip {
            IP::V4(v4) => Address {
                value: Some(V4(v4.to_string())),
            },
            IP::V6(v6) => Address {
                value: Some(V6(IPv6Result {
                    source_address: IPv6 {
                        p1: (v6.segments()[0] as u64) << 48
                            | (v6.segments()[1] as u64) << 32
                            | (v6.segments()[2] as u64) << 16
                            | (v6.segments()[3] as u64),
                        p2: (v6.segments()[4] as u64) << 48
                            | (v6.segments()[5] as u64) << 32
                            | (v6.segments()[6] as u64) << 16
                            | (v6.segments()[7] as u64),
                    },
                    destination_address: IPv6 {
                        p1: (v6.segments()[0] as u64) << 48
                            | (v6.segments()[1] as u64) << 32
                            | (v6.segments()[2] as u64) << 16
                            | (v6.segments()[3] as u64),
                        p2: (v6.segments()[4] as u64) << 48
                            | (v6.segments()[5] as u64) << 32
                            | (v6.segments()[6] as u64) << 16
                            | (v6.segments()[7] as u64),
                    },
                })),
            },
            IP::None => Address {
                value: None,
            },
        }
    }
}

impl ToString for IP {
    fn to_string(&self) -> String {
        match self {
            IP::V4(v4) => v4.to_string(),
            IP::V6(v6) => v6.to_string(),
            IP::None => String::from("None"),
        }
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

impl ToString for IPv6 {
    fn to_string(&self) -> String {
        format!(
            "{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}",
            self.p1 >> 48,
            self.p1 >> 32,
            self.p1 >> 16,
            self.p1,
            self.p2 >> 48,
            self.p2 >> 32,
            self.p2 >> 16,
            self.p2
        )
    }
}

impl IpResult {
    pub fn get_source_address_str(&self) -> String {
        match self.value.unwrap() {
            verfploeter::ip_result::Value::IPv4Result(v4) => v4.source_address.to_string(),
            verfploeter::ip_result::Value::IPv6Result(v6) => v6.source_address.to_string(),
        }
    }

    pub fn get_dest_address_str(&self) -> String {
        match self.value.unwrap() {
            verfploeter::ip_result::Value::IPv4Result(v4) => v4.destination_address.to_string(),
            verfploeter::ip_result::Value::IPv6Result(v6) => v6.destination_address.to_string(),
        }
    }
}