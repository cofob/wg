//! WireGuard format configuration types and parser.

use std::net::IpAddr;

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use cidr::IpCidr;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowedIps(pub Vec<IpCidr>);

#[derive(Debug, Clone)]
pub struct Key(pub [u8; 32]);

impl Serialize for Key {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let encoded = BASE64_STANDARD.encode(&self.0);
        serializer.serialize_str(&encoded)
    }
}

impl<'de> Deserialize<'de> for Key {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        let decoded = BASE64_STANDARD
            .decode(&encoded)
            .map_err(serde::de::Error::custom)?;
        if decoded.len() != 32 {
            return Err(serde::de::Error::custom("Invalid key length"));
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&decoded);
        Ok(Key(key_bytes))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceConfig {
    pub private_key: String,
    pub listen_port: Option<u16>,
    pub mtu: Option<u16>,
    pub dns: Option<Vec<IpAddr>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    pub public_key: String,
    pub allowed_ips: AllowedIps,
    #[serde(default)]
    pub endpoint: Option<String>,
    pub persistent_keepalive: Option<u16>,
    pub preshared_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardConfig {
    pub interface: InterfaceConfig,
    pub peers: Vec<PeerConfig>,
}
