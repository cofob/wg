use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub addr: IpAddr,
    pub peer: SocketAddr,
    pub listen: SocketAddr,
}
