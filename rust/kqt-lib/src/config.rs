use std::net::{IpAddr, SocketAddr};

use cidr::IpInet;
use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    /// Local keypair
    pub keypair: String,
    /// CA for authenticating certificates
    pub anchor: Vec<String>,
    /// Suffix used in certificate verification
    pub suffix: String,

    /// Operating mode
    #[serde(default)]
    pub mode: Mode,

    /// System MTU
    pub mtu: Option<u16>,

    /// IP Addresses
    #[serde(default)]
    pub address: Vec<cidr::IpInet>,

    /// Enable server mode
    pub listen: Option<SocketAddr>,

    /// Connect to remote endpoint
    #[serde(default)]
    pub connect_to: Vec<ConnectTo>,

    /// DNS servers
    #[serde(default)]
    pub dns: Vec<IpAddr>,

    /// Whether to add routes to the system routing table
    #[serde(default)]
    pub table: bool,

    /// Automatically add routes
    #[serde(default)]
    pub route: Vec<Route>,

    /// Advanced settings
    #[serde(default)]
    pub advanced: Advanced,
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    L2,
    L3,
}

impl Default for Mode {
    fn default() -> Self {
        Mode::L2
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct ConnectTo {
    pub endpoint: SocketAddr,
    #[serde(default)]
    pub designated_range: Vec<IpInet>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Route {
    pub to: cidr::IpInet,
    pub via: IpAddr,
    pub metric: Option<u32>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Advanced {
    /// Initial outer connection MTU
    pub initial_outer_mtu: u16,

    /// Keepalive interval in seconds
    pub keepalive: u16,

    /// Idle timeout in seconds
    pub max_idle_timeout: u16,

    /// Override send buffer size
    pub send_buffer: Option<usize>,

    /// Overrride recv buffer size
    pub recv_buffer: Option<usize>,
}

impl Default for Advanced {
    fn default() -> Self {
        Advanced {
            initial_outer_mtu: 1452,
            keepalive: 25,
            max_idle_timeout: 60,
            send_buffer: None,
            recv_buffer: None,
        }
    }
}
