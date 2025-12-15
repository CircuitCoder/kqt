use std::net::SocketAddr;

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
}

#[derive(Deserialize, Debug)]
pub struct ConnectTo {
    pub endpoint: SocketAddr,
    pub san: Option<String>,
}
