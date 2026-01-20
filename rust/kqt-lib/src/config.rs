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
    pub advanced: Advanced,
}

#[derive(Deserialize, Debug)]
pub struct ConnectTo {
    pub endpoint: SocketAddr,
    pub san: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct Route {
    pub to: cidr::IpInet,
    pub via: IpAddr,
    pub metric: Option<u32>,
}

const fn default_u16<const V: u16>() -> u16 {
    V
}

#[derive(Deserialize, Debug)]
pub struct Advanced {
    /// Initial outer connection MTU
    #[serde(default = "default_u16::<1452>")]
    pub initial_outer_mtu: u16,

    /// Keepalive interval in seconds
    #[serde(default = "default_u16::<25>")]
    pub keepalive: u16,

    /// Idle timeout in seconds
    #[serde(default = "default_u16::<60>")]
    pub max_idle_timeout: u16,

    /// Override send buffer size
    pub send_buffer: Option<usize>,

    /// Overrride recv buffer size
    pub recv_buffer: Option<usize>,
}
