mod ipv4;
mod ipv6;
mod protocols;

pub use ipv4::IPv4Packet;
pub use ipv6::IPv6Packet;
pub use protocols::Protocol;

pub enum IPPacket<'a> {
    V4(IPv4Packet<'a>),
    V6(IPv6Packet<'a>),
}

impl<'a> IPPacket<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        match data[0] >> 4 {
            4 => Some(IPPacket::V4(IPv4Packet::new(data))),
            6 => Some(IPPacket::V6(IPv6Packet::new(data))),
            _ => None,
        }
    }

    pub fn version(&self) -> u8 {
        match self {
            IPPacket::V4(packet) => packet.version(),
            IPPacket::V6(packet) => packet.version(),
        }
    }

    pub fn protocol(&self) -> Option<Protocol> {
        match self {
            IPPacket::V4(packet) => packet.protocol(),
            IPPacket::V6(packet) => packet.protocol(),
        }
    }

    pub fn src(&self) -> std::net::IpAddr {
        match self {
            IPPacket::V4(packet) => std::net::IpAddr::V4(packet.src()),
            IPPacket::V6(packet) => std::net::IpAddr::V6(packet.src()),
        }
    }

    pub fn dst(&self) -> std::net::IpAddr {
        match self {
            IPPacket::V4(packet) => std::net::IpAddr::V4(packet.dst()),
            IPPacket::V6(packet) => std::net::IpAddr::V6(packet.dst()),
        }
    }
}

impl core::fmt::Debug for IPPacket<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IPPacket")
            .field("version", &self.version())
            .field("protocol", &self.protocol())
            .field("src", &self.src())
            .field("dst", &self.dst())
            .finish()
    }
}
