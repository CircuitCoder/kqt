use std::net::{IpAddr, SocketAddr};

use serde::Deserialize;

#[derive(Deserialize, Debug)]
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

    /// Automatically add routes
    #[serde(default)]
    pub routes: Vec<Route>,

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

#[derive(Deserialize, Debug)]
pub struct ConnectTo {
    pub endpoint: SocketAddr,
    pub san: Option<String>,
    #[serde(default)]
    pub designated_ip: Vec<IpAddr>,
}

#[derive(Deserialize, Debug)]
pub struct Route {
    pub to: cidr::IpInet,
    pub via: IpAddr,
    pub metric: Option<u32>,
}

#[derive(Deserialize, Debug)]
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