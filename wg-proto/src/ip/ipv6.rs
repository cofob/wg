use core::net::Ipv6Addr;

pub struct IPv6Packet<'a> {
    data: &'a [u8],
}

impl<'a> IPv6Packet<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn version(&self) -> u8 {
        self.data[0] >> 4
    }

    pub fn protocol(&self) -> u8 {
        self.data[6]
    }

    pub fn src(&self) -> Ipv6Addr {
        Ipv6Addr::new(
            u16::from_be_bytes([self.data[8], self.data[9]]),
            u16::from_be_bytes([self.data[10], self.data[11]]),
            u16::from_be_bytes([self.data[12], self.data[13]]),
            u16::from_be_bytes([self.data[14], self.data[15]]),
            u16::from_be_bytes([self.data[16], self.data[17]]),
            u16::from_be_bytes([self.data[18], self.data[19]]),
            u16::from_be_bytes([self.data[20], self.data[21]]),
            u16::from_be_bytes([self.data[22], self.data[23]]),
        )
    }

    pub fn dst(&self) -> Ipv6Addr {
        Ipv6Addr::new(
            u16::from_be_bytes([self.data[24], self.data[25]]),
            u16::from_be_bytes([self.data[26], self.data[27]]),
            u16::from_be_bytes([self.data[28], self.data[29]]),
            u16::from_be_bytes([self.data[30], self.data[31]]),
            u16::from_be_bytes([self.data[32], self.data[33]]),
            u16::from_be_bytes([self.data[34], self.data[35]]),
            u16::from_be_bytes([self.data[36], self.data[37]]),
            u16::from_be_bytes([self.data[38], self.data[39]]),
        )
    }
}

impl core::fmt::Debug for IPv6Packet<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IPv6Packet")
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
    // - Version: 6
    // - Protocol: 58 (ICMP)
    // - Source: 2::
    // - Destination: 2::1
    const TEST_PACKET: [u8; 104] = [
        96, 1, 99, 100, 0, 64, 58, 64, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 128, 0, 45, 206, 0, 29, 0, 2, 56, 73, 149, 103, 0, 0,
        0, 0, 191, 15, 6, 0, 0, 0, 0, 0, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
        30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52,
        53, 54, 55,
    ];

    #[test]
    fn test_ipv6_packet() {
        let packet = IPv6Packet::new(&TEST_PACKET);

        assert_eq!(packet.version(), 6);
        assert_eq!(packet.protocol(), 58);
        assert_eq!(packet.src(), Ipv6Addr::new(2, 0, 0, 0, 0, 0, 0, 0));
        assert_eq!(packet.dst(), Ipv6Addr::new(2, 0, 0, 0, 0, 0, 0, 1));
    }
}
