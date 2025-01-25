use core::net::Ipv4Addr;

pub struct IPv4Packet<'a> {
    data: &'a [u8],
}

impl<'a> IPv4Packet<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn version(&self) -> u8 {
        self.data[0] >> 4
    }

    pub fn protocol(&self) -> u8 {
        self.data[9]
    }

    pub fn src(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.data[12], self.data[13], self.data[14], self.data[15])
    }

    pub fn dst(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.data[16], self.data[17], self.data[18], self.data[19])
    }
}

impl core::fmt::Debug for IPv4Packet<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IPv4Packet")
            .field("version", &self.version())
            .field("protocol", &self.protocol())
            .field("src", &self.src())
            .field("dst", &self.dst())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // This is a test packet with the following data:
    // - Version: 4
    // - Protocol: 1 (ICMP)
    // - Source: 10.0.0.3
    // - Destination: 10.0.0.1
    const TEST_PACKET: [u8; 84] = [
        69, 0, 0, 84, 245, 121, 64, 0, 64, 1, 49, 44, 10, 0, 0, 3, 10, 0, 0, 1, 8, 0, 234, 185, 0,
        28, 0, 2, 239, 71, 149, 103, 0, 0, 0, 0, 194, 165, 7, 0, 0, 0, 0, 0, 16, 17, 18, 19, 20,
        21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43,
        44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55,
    ];

    #[test]
    fn test_ipv4_packet() {
        let packet = IPv4Packet::new(&TEST_PACKET);

        assert_eq!(packet.version(), 4);
        assert_eq!(packet.protocol(), 1);
        assert_eq!(packet.src(), Ipv4Addr::new(10, 0, 0, 3));
        assert_eq!(packet.dst(), Ipv4Addr::new(10, 0, 0, 1));
    }
}
