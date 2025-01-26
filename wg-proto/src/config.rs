//! WireGuard format configuration types and parser.

use std::net::IpAddr;

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use cidr::{IpCidr, IpInet};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cidrs(pub Vec<IpCidr>);

impl IntoIterator for Cidrs {
    type Item = IpCidr;
    type IntoIter = std::vec::IntoIter<IpCidr>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a Cidrs {
    type Item = &'a IpCidr;
    type IntoIter = std::slice::Iter<'a, IpCidr>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl From<Vec<IpCidr>> for Cidrs {
    fn from(vec: Vec<IpCidr>) -> Self {
        Self(vec)
    }
}

impl From<Cidrs> for Vec<IpCidr> {
    fn from(allowed_ips: Cidrs) -> Self {
        allowed_ips.0
    }
}

impl AsRef<[IpCidr]> for Cidrs {
    fn as_ref(&self) -> &[IpCidr] {
        &self.0
    }
}

// impl Serialize for Cidrs {
//     fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
//         let encoded = self
//             .0
//             .iter()
//             .map(|cidr| cidr.to_string())
//             .collect::<Vec<String>>();
//         serializer.serialize_str(&encoded.join(","))
//     }
// }

// impl<'de> Deserialize<'de> for Cidrs {
//     fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
//         let encoded = String::deserialize(deserializer)?;
//         let decoded = encoded
//             .split(',')
//             .map(|cidr| cidr.parse().map_err(serde::de::Error::custom))
//             .collect::<Result<Vec<IpCidr>, _>>()?;
//         Ok(Cidrs(decoded))
//     }
// }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inets(pub Vec<IpInet>);

impl IntoIterator for Inets {
    type Item = IpInet;
    type IntoIter = std::vec::IntoIter<IpInet>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a Inets {
    type Item = &'a IpInet;
    type IntoIter = std::slice::Iter<'a, IpInet>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl From<Vec<IpInet>> for Inets {
    fn from(vec: Vec<IpInet>) -> Self {
        Self(vec)
    }
}

impl From<Inets> for Vec<IpInet> {
    fn from(allowed_ips: Inets) -> Self {
        allowed_ips.0
    }
}

impl AsRef<[IpInet]> for Inets {
    fn as_ref(&self) -> &[IpInet] {
        &self.0
    }
}

// impl Serialize for Inets {
//     fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
//         let encoded = self
//             .0
//             .iter()
//             .map(|cidr| cidr.to_string())
//             .collect::<Vec<String>>();
//         serializer.serialize_str(&encoded.join(","))
//     }
// }

// impl<'de> Deserialize<'de> for Inets {
//     fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
//         let encoded = String::deserialize(deserializer)?;
//         let decoded = encoded
//             .split(',')
//             .map(|cidr| cidr.parse().map_err(serde::de::Error::custom))
//             .collect::<Result<Vec<IpInet>, _>>()?;
//         Ok(Inets(decoded))
//     }
// }

#[derive(Clone)]
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

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Key")
            .field(&BASE64_STANDARD.encode(&self.0))
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DNS(pub Vec<IpAddr>);

// impl Serialize for DNS {
//     fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
//         let encoded = self
//             .0
//             .iter()
//             .map(|ip| ip.to_string())
//             .collect::<Vec<String>>();
//         serializer.serialize_str(&encoded.join(","))
//     }
// }

// impl<'de> Deserialize<'de> for DNS {
//     fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
//         let encoded = String::deserialize(deserializer)?;
//         let decoded = encoded
//             .split(',')
//             .map(|ip| ip.parse().map_err(serde::de::Error::custom))
//             .collect::<Result<Vec<IpAddr>, _>>()?;
//         Ok(DNS(decoded))
//     }
// }

impl AsRef<[IpAddr]> for DNS {
    fn as_ref(&self) -> &[IpAddr] {
        &self.0
    }
}

impl From<Vec<IpAddr>> for DNS {
    fn from(vec: Vec<IpAddr>) -> Self {
        Self(vec)
    }
}

impl From<DNS> for Vec<IpAddr> {
    fn from(dns: DNS) -> Self {
        dns.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceConfig {
    #[serde(rename = "PrivateKey")]
    pub private_key: Key,
    #[serde(rename = "Address")]
    pub address: Inets,
    #[serde(default, rename = "PostUp")]
    pub post_up: Option<String>,
    #[serde(default, rename = "PostDown")]
    pub post_down: Option<String>,
    #[serde(default, rename = "ListenPort")]
    pub listen_port: Option<u16>,
    #[serde(default, rename = "MTU")]
    pub mtu: Option<u16>,
    #[serde(default, rename = "DNS")]
    pub dns: Option<DNS>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    #[serde(rename = "PublicKey")]
    pub public_key: Key,
    #[serde(rename = "AllowedIPs")]
    pub allowed_ips: Cidrs,
    #[serde(default, rename = "Endpoint")]
    pub endpoint: Option<String>,
    #[serde(default, rename = "PersistentKeepalive")]
    pub persistent_keepalive: Option<u16>,
    #[serde(default, rename = "PresharedKey")]
    pub preshared_key: Option<Key>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardConfig {
    #[serde(rename = "Interface")]
    pub interface: InterfaceConfig,
    #[serde(default, rename = "Peers")]
    pub peers: Vec<PeerConfig>,
}
