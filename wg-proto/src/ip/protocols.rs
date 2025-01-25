/// A comprehensive enumeration of IP protocol numbers as assigned by IANA, with references
/// to relevant RFCs and usage contexts. It includes widely used protocols (e.g., UDP, TCP,
/// ICMP) and various specialized or deprecated variants for broader interoperability.
///
/// This enum offers:
///
/// - Seamless conversion to and from `u8` via the [`From`] and [`TryFrom`] traits.
/// - String-based parsing with [`FromStr`], which tolerates hyphens, spaces, and varying
///   casing for protocol names.
/// - Inclusion of legacy and deprecated protocols (e.g., ARGUS, MICP, SM, SWIPE) to
///   maintain compatibility with older implementations.
///
/// Source: <https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml>
///
/// # Examples
///
/// ```
/// use std::convert::TryFrom;
/// use wg_proto::ip::Protocol;
///
/// // Convert from enum to numeric protocol identifier:
/// let udp_num: u8 = Protocol::UDP.into();
/// assert_eq!(udp_num, 17);
///
/// // Convert numeric protocol identifier back to enum:
/// let tcp_protocol = Protocol::try_from(6).unwrap();
/// assert_eq!(tcp_protocol, Protocol::TCP);
///
/// // Parse a protocol name from a string:
/// let icmp_protocol: Protocol = "icmp".parse().unwrap();
/// assert_eq!(icmp_protocol, Protocol::ICMP);
/// ```
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Protocol {
    /// IPv6 Hop-by-Hop Option (RFC8200)
    HOPOPT = 0,
    /// Internet Control Message Protocol (RFC792)
    ICMP = 1,
    /// Internet Group Management Protocol (RFC1112)
    IGMP = 2,
    /// Gateway-to-Gateway Protocol (RFC823)
    GGP = 3,
    /// IPv4 Encapsulation (RFC2003)
    IPv4 = 4,
    /// Stream Protocol (RFC1190, RFC1819)
    ST = 5,
    /// Transmission Control Protocol (RFC9293)
    TCP = 6,
    /// CBT protocol (Tony Ballardie)
    CBT = 7,
    /// Exterior Gateway Protocol (RFC888)
    EGP = 8,
    /// Private interior gateway (Cisco IGRP)
    IGP = 9,
    /// BBN RCC Monitoring (Steve Chipman)
    BBNRCCMON = 10,
    /// Network Voice Protocol (RFC741)
    NVPII = 11,
    /// PUP internetworking architecture
    PUP = 12,
    /// ARGUS protocol (deprecated)
    #[deprecated]
    ARGUS = 13,
    /// EMCON system for network emergencies
    EMCON = 14,
    /// Cross Net Debugger (IEN 158)
    XNET = 15,
    /// Chaos network protocol
    CHAOS = 16,
    /// User Datagram Protocol (RFC768)
    UDP = 17,
    /// Multiplexing Protocol (IEN 90)
    MUX = 18,
    /// DCN Measurement Subsystems
    DCNMEAS = 19,
    /// Host Monitoring Protocol (RFC869)
    HMP = 20,
    /// Packet Radio Measurement protocol
    PRM = 21,
    /// Xerox NS IDP protocol
    XNSIDP = 22,
    /// Trunk-1 network protocol
    TRUNK1 = 23,
    /// Trunk-2 network protocol
    TRUNK2 = 24,
    /// Leaf-1 network protocol
    LEAF1 = 25,
    /// Leaf-2 network protocol
    LEAF2 = 26,
    /// Reliable Data Protocol (RFC908)
    RDP = 27,
    /// Internet Reliable Transaction (RFC938)
    IRTP = 28,
    /// ISO Transport Protocol Class 4 (RFC905)
    ISOTP4 = 29,
    /// Bulk Data Transfer Protocol (RFC969)
    NETBLT = 30,
    /// MFE Network Services Protocol
    MFENSP = 31,
    /// MERIT Internodal Protocol
    MERITINP = 32,
    /// Datagram Congestion Control Protocol (RFC4340)
    DCCP = 33,
    /// Third Party Connect Protocol
    ThirdPC = 34,
    /// Inter-Domain Policy Routing Protocol
    IDPR = 35,
    /// Xpress Transport Protocol
    XTP = 36,
    /// Datagram Delivery Protocol
    DDP = 37,
    /// IDPR Control Message Transport
    IDPRCMTP = 38,
    /// TP++ Transport Protocol
    TPPlusPlus = 39,
    /// IL Transport Protocol
    IL = 40,
    /// IPv6 Encapsulation (RFC2473)
    IPv6 = 41,
    /// Source Demand Routing Protocol
    SDRP = 42,
    /// IPv6 Routing Header (RFC8200)
    IPv6Route = 43,
    /// IPv6 Fragment Header (RFC8200)
    IPv6Frag = 44,
    /// Inter-Domain Routing Protocol
    IDRP = 45,
    /// Reservation Protocol (RFC2205)
    RSVP = 46,
    /// Generic Routing Encapsulation (RFC2784)
    GRE = 47,
    /// Dynamic Source Routing (RFC4728)
    DSR = 48,
    /// BNA protocol (Gary Salamon)
    BNA = 49,
    /// Encapsulating Security Payload (RFC4303), IPv6 Extension Header
    ESP = 50,
    /// Authentication Header (RFC4302), IPv6 Extension Header
    AH = 51,
    /// Integrated Net Layer Security TUBA
    INLSP = 52,
    /// IP with Encryption (deprecated)
    #[deprecated]
    SWIPE = 53,
    /// NBMA Address Resolution (RFC1735)
    NARP = 54,
    /// Minimal IPv4 Encapsulation (RFC2004)
    MinIPv4 = 55,
    /// Transport Layer Security with Kryptonet
    TLSP = 56,
    /// SKIP protocol (Tom Markson)
    SKIP = 57,
    /// ICMPv6 (RFC8200)
    IPv6ICMP = 58,
    /// IPv6 No Next Header (RFC8200)
    IPv6NoNxt = 59,
    /// IPv6 Destination Options (RFC8200)
    IPv6Opts = 60,
    /// Any host internal protocol
    HostInternal = 61,
    /// CFTP protocol (Harry Forsdick)
    CFTP = 62,
    /// Any local network
    LocalNetwork = 63,
    /// SATNET/Backroom EXPAK
    SATEXPAK = 64,
    /// Kryptolan protocol
    KRYPTOLAN = 65,
    /// MIT Remote Virtual Disk
    RVD = 66,
    /// Internet Pluribus Packet Core
    IPPC = 67,
    /// Any distributed filesystem
    DistributedFS = 68,
    /// SATNET Monitoring
    SATMON = 69,
    /// VISA Protocol (Gene Tsudik)
    VISA = 70,
    /// Internet Packet Core Utility
    IPCV = 71,
    /// Computer Protocol Network Executive
    CPNX = 72,
    /// Computer Protocol Heart Beat
    CPHB = 73,
    /// Wang Span Network protocol
    WSN = 74,
    /// Packet Video Protocol
    PVP = 75,
    /// Backroom SATNET Monitoring
    BRSATMON = 76,
    /// SUN ND Protocol (Temporary)
    SUNND = 77,
    /// WIDEBAND Monitoring
    WBMON = 78,
    /// WIDEBAND EXPAK
    WBEXPAK = 79,
    /// ISO Internet Protocol
    ISOIP = 80,
    /// Versatile Message Transport
    VMTP = 81,
    /// Secure VMTP protocol
    SECUREVMTP = 82,
    /// VINES protocol
    VINES = 83,
    /// IP Traffic Manager
    IPTM = 84,
    /// NSFNET-IGP protocol
    NSFNETIGP = 85,
    /// Dissimilar Gateway Protocol
    DGP = 86,
    /// TCF protocol
    TCF = 87,
    /// Enhanced Interior Gateway Routing Protocol (RFC7868)
    EIGRP = 88,
    /// OSPF Gateway Protocol (RFC1583)
    OSPFIGP = 89,
    /// Sprite RPC Protocol
    SpriteRPC = 90,
    /// Locus Address Resolution
    LARP = 91,
    /// Multicast Transport Protocol
    MTP = 92,
    /// AX.25 Frames protocol
    AX25 = 93,
    /// IP-within-IP Encapsulation
    IPIP = 94,
    /// Mobile Internetworking Control (deprecated)
    #[deprecated]
    MICP = 95,
    /// Semaphore Communications Security
    SCCSP = 96,
    /// Ethernet-over-IP (RFC3378)
    ETHERIP = 97,
    /// Encapsulation Header (RFC1241)
    ENCAP = 98,
    /// Private encryption scheme
    PrivateEncryption = 99,
    /// GMTP protocol
    GMTP = 100,
    /// Ipsilon Flow Management
    IFMP = 101,
    /// PNNI over IP protocol
    PNNI = 102,
    /// Protocol Independent Multicast (RFC7761)
    PIM = 103,
    /// ARIS protocol
    ARIS = 104,
    /// SCPS protocol
    SCPS = 105,
    /// QNX protocol
    QNX = 106,
    /// Active Networks protocol
    AN = 107,
    /// IP Payload Compression (RFC2393)
    IPComp = 108,
    /// Sitara Networks Protocol
    SNP = 109,
    /// Compaq Peer Protocol
    CompaqPeer = 110,
    /// IPX in IP encapsulation
    IPXinIP = 111,
    /// Virtual Router Redundancy (RFC9568)
    VRRP = 112,
    /// PGM Reliable Transport
    PGM = 113,
    /// Any 0-hop protocol
    ZeroHop = 114,
    /// Layer 2 Tunneling (RFC3931)
    L2TP = 115,
    /// D-II Data Exchange
    DDX = 116,
    /// Interactive Agent Transfer
    IATP = 117,
    /// Schedule Transfer Protocol
    STP = 118,
    /// SpectraLink Radio Protocol
    SRP = 119,
    /// UTI protocol
    UTI = 120,
    /// Simple Message Protocol
    SMP = 121,
    /// Simple Multicast (deprecated)
    #[deprecated]
    SM = 122,
    /// Performance Transparency Protocol
    PTP = 123,
    /// ISIS over IPv4 routing
    ISISoverIPv4 = 124,
    /// FIRE protocol
    FIRE = 125,
    /// Combat Radio Transport
    CRTP = 126,
    /// Combat Radio User Datagram
    CRUDP = 127,
    /// SSCOPMCE protocol
    SSCOPMCE = 128,
    /// IPLT protocol
    IPLT = 129,
    /// Secure Packet Shield
    SPS = 130,
    /// Private IP Encapsulation
    PIPE = 131,
    /// Stream Control Transmission (RFC4960)
    SCTP = 132,
    /// Fibre Channel (RFC6172)
    FC = 133,
    /// RSVP End-to-End Ignore
    RSVPE2EIGNORE = 134,
    /// IPv6 Mobility Header (RFC6275)
    MobilityHeader = 135,
    /// UDP-Lite protocol (RFC3828)
    UDPLite = 136,
    /// MPLS in IP (RFC4023)
    MPLSinIP = 137,
    /// MANET Protocols (RFC5498)
    MANET = 138,
    /// Host Identity Protocol (RFC7401), IPv6 EH
    HIP = 139,
    /// Shim6 Protocol (RFC5533), IPv6 EH
    Shim6 = 140,
    /// Wrapped ESP (RFC5840)
    WESP = 141,
    /// Robust Header Compression (RFC5858)
    ROHC = 142,
    /// Ethernet Service (RFC8986)
    Ethernet = 143,
    /// AGGFRAG for ESP (RFC9347)
    AGGFRAG = 144,
    /// Network Service Header (RFC9491)
    NSH = 145,
    /// Homa Transport Protocol
    Homa = 146,
    /// Bit-stream Emulation (RFC-ietf-pals-ple-14)
    BITEMU = 147,
    /// Experimental use (253) (RFC3692)
    ExperimentalAndTesting253 = 253,
    /// Experimental use (254) (RFC3692)
    ExperimentalAndTesting254 = 254,
    /// Reserved protocol number
    Reserved = 255,
}

impl From<Protocol> for u8 {
    fn from(value: Protocol) -> Self {
        value as u8
    }
}

impl TryFrom<u8> for Protocol {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Protocol::HOPOPT),
            1 => Ok(Protocol::ICMP),
            2 => Ok(Protocol::IGMP),
            3 => Ok(Protocol::GGP),
            4 => Ok(Protocol::IPv4),
            5 => Ok(Protocol::ST),
            6 => Ok(Protocol::TCP),
            7 => Ok(Protocol::CBT),
            8 => Ok(Protocol::EGP),
            9 => Ok(Protocol::IGP),
            10 => Ok(Protocol::BBNRCCMON),
            11 => Ok(Protocol::NVPII),
            12 => Ok(Protocol::PUP),
            #[allow(deprecated)]
            13 => Ok(Protocol::ARGUS),
            14 => Ok(Protocol::EMCON),
            15 => Ok(Protocol::XNET),
            16 => Ok(Protocol::CHAOS),
            17 => Ok(Protocol::UDP),
            18 => Ok(Protocol::MUX),
            19 => Ok(Protocol::DCNMEAS),
            20 => Ok(Protocol::HMP),
            21 => Ok(Protocol::PRM),
            22 => Ok(Protocol::XNSIDP),
            23 => Ok(Protocol::TRUNK1),
            24 => Ok(Protocol::TRUNK2),
            25 => Ok(Protocol::LEAF1),
            26 => Ok(Protocol::LEAF2),
            27 => Ok(Protocol::RDP),
            28 => Ok(Protocol::IRTP),
            29 => Ok(Protocol::ISOTP4),
            30 => Ok(Protocol::NETBLT),
            31 => Ok(Protocol::MFENSP),
            32 => Ok(Protocol::MERITINP),
            33 => Ok(Protocol::DCCP),
            34 => Ok(Protocol::ThirdPC),
            35 => Ok(Protocol::IDPR),
            36 => Ok(Protocol::XTP),
            37 => Ok(Protocol::DDP),
            38 => Ok(Protocol::IDPRCMTP),
            39 => Ok(Protocol::TPPlusPlus),
            40 => Ok(Protocol::IL),
            41 => Ok(Protocol::IPv6),
            42 => Ok(Protocol::SDRP),
            43 => Ok(Protocol::IPv6Route),
            44 => Ok(Protocol::IPv6Frag),
            45 => Ok(Protocol::IDRP),
            46 => Ok(Protocol::RSVP),
            47 => Ok(Protocol::GRE),
            48 => Ok(Protocol::DSR),
            49 => Ok(Protocol::BNA),
            50 => Ok(Protocol::ESP),
            51 => Ok(Protocol::AH),
            52 => Ok(Protocol::INLSP),
            #[allow(deprecated)]
            53 => Ok(Protocol::SWIPE),
            54 => Ok(Protocol::NARP),
            55 => Ok(Protocol::MinIPv4),
            56 => Ok(Protocol::TLSP),
            57 => Ok(Protocol::SKIP),
            58 => Ok(Protocol::IPv6ICMP),
            59 => Ok(Protocol::IPv6NoNxt),
            60 => Ok(Protocol::IPv6Opts),
            61 => Ok(Protocol::HostInternal),
            62 => Ok(Protocol::CFTP),
            63 => Ok(Protocol::LocalNetwork),
            64 => Ok(Protocol::SATEXPAK),
            65 => Ok(Protocol::KRYPTOLAN),
            66 => Ok(Protocol::RVD),
            67 => Ok(Protocol::IPPC),
            68 => Ok(Protocol::DistributedFS),
            69 => Ok(Protocol::SATMON),
            70 => Ok(Protocol::VISA),
            71 => Ok(Protocol::IPCV),
            72 => Ok(Protocol::CPNX),
            73 => Ok(Protocol::CPHB),
            74 => Ok(Protocol::WSN),
            75 => Ok(Protocol::PVP),
            76 => Ok(Protocol::BRSATMON),
            77 => Ok(Protocol::SUNND),
            78 => Ok(Protocol::WBMON),
            79 => Ok(Protocol::WBEXPAK),
            80 => Ok(Protocol::ISOIP),
            81 => Ok(Protocol::VMTP),
            82 => Ok(Protocol::SECUREVMTP),
            83 => Ok(Protocol::VINES),
            84 => Ok(Protocol::IPTM),
            85 => Ok(Protocol::NSFNETIGP),
            86 => Ok(Protocol::DGP),
            87 => Ok(Protocol::TCF),
            88 => Ok(Protocol::EIGRP),
            89 => Ok(Protocol::OSPFIGP),
            90 => Ok(Protocol::SpriteRPC),
            91 => Ok(Protocol::LARP),
            92 => Ok(Protocol::MTP),
            93 => Ok(Protocol::AX25),
            94 => Ok(Protocol::IPIP),
            #[allow(deprecated)]
            95 => Ok(Protocol::MICP),
            96 => Ok(Protocol::SCCSP),
            97 => Ok(Protocol::ETHERIP),
            98 => Ok(Protocol::ENCAP),
            99 => Ok(Protocol::PrivateEncryption),
            100 => Ok(Protocol::GMTP),
            101 => Ok(Protocol::IFMP),
            102 => Ok(Protocol::PNNI),
            103 => Ok(Protocol::PIM),
            104 => Ok(Protocol::ARIS),
            105 => Ok(Protocol::SCPS),
            106 => Ok(Protocol::QNX),
            107 => Ok(Protocol::AN),
            108 => Ok(Protocol::IPComp),
            109 => Ok(Protocol::SNP),
            110 => Ok(Protocol::CompaqPeer),
            111 => Ok(Protocol::IPXinIP),
            112 => Ok(Protocol::VRRP),
            113 => Ok(Protocol::PGM),
            114 => Ok(Protocol::ZeroHop),
            115 => Ok(Protocol::L2TP),
            116 => Ok(Protocol::DDX),
            117 => Ok(Protocol::IATP),
            118 => Ok(Protocol::STP),
            119 => Ok(Protocol::SRP),
            120 => Ok(Protocol::UTI),
            121 => Ok(Protocol::SMP),
            #[allow(deprecated)]
            122 => Ok(Protocol::SM),
            123 => Ok(Protocol::PTP),
            124 => Ok(Protocol::ISISoverIPv4),
            125 => Ok(Protocol::FIRE),
            126 => Ok(Protocol::CRTP),
            127 => Ok(Protocol::CRUDP),
            128 => Ok(Protocol::SSCOPMCE),
            129 => Ok(Protocol::IPLT),
            130 => Ok(Protocol::SPS),
            131 => Ok(Protocol::PIPE),
            132 => Ok(Protocol::SCTP),
            133 => Ok(Protocol::FC),
            134 => Ok(Protocol::RSVPE2EIGNORE),
            135 => Ok(Protocol::MobilityHeader),
            136 => Ok(Protocol::UDPLite),
            137 => Ok(Protocol::MPLSinIP),
            138 => Ok(Protocol::MANET),
            139 => Ok(Protocol::HIP),
            140 => Ok(Protocol::Shim6),
            141 => Ok(Protocol::WESP),
            142 => Ok(Protocol::ROHC),
            143 => Ok(Protocol::Ethernet),
            144 => Ok(Protocol::AGGFRAG),
            145 => Ok(Protocol::NSH),
            146 => Ok(Protocol::Homa),
            147 => Ok(Protocol::BITEMU),
            253 => Ok(Protocol::ExperimentalAndTesting253),
            254 => Ok(Protocol::ExperimentalAndTesting254),
            255 => Ok(Protocol::Reserved),
            _ => Err(()),
        }
    }
}

impl std::str::FromStr for Protocol {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().replace(['-', ' '], "").as_str() {
            "HOPOPT" => Ok(Protocol::HOPOPT),
            "ICMP" => Ok(Protocol::ICMP),
            "IGMP" => Ok(Protocol::IGMP),
            "GGP" => Ok(Protocol::GGP),
            "IPV4" => Ok(Protocol::IPv4),
            "ST" => Ok(Protocol::ST),
            "TCP" => Ok(Protocol::TCP),
            "CBT" => Ok(Protocol::CBT),
            "EGP" => Ok(Protocol::EGP),
            "IGP" => Ok(Protocol::IGP),
            "BBNRCCMON" => Ok(Protocol::BBNRCCMON),
            "NVPII" => Ok(Protocol::NVPII),
            "PUP" => Ok(Protocol::PUP),
            #[allow(deprecated)]
            "ARGUS" => Ok(Protocol::ARGUS),
            "EMCON" => Ok(Protocol::EMCON),
            "XNET" => Ok(Protocol::XNET),
            "CHAOS" => Ok(Protocol::CHAOS),
            "UDP" => Ok(Protocol::UDP),
            "MUX" => Ok(Protocol::MUX),
            "DCNMEAS" => Ok(Protocol::DCNMEAS),
            "HMP" => Ok(Protocol::HMP),
            "PRM" => Ok(Protocol::PRM),
            "XNSIDP" => Ok(Protocol::XNSIDP),
            "TRUNK1" => Ok(Protocol::TRUNK1),
            "TRUNK2" => Ok(Protocol::TRUNK2),
            "LEAF1" => Ok(Protocol::LEAF1),
            "LEAF2" => Ok(Protocol::LEAF2),
            "RDP" => Ok(Protocol::RDP),
            "IRTP" => Ok(Protocol::IRTP),
            "ISOTP4" => Ok(Protocol::ISOTP4),
            "NETBLT" => Ok(Protocol::NETBLT),
            "MFENSP" => Ok(Protocol::MFENSP),
            "MERITINP" => Ok(Protocol::MERITINP),
            "DCCP" => Ok(Protocol::DCCP),
            "3PC" => Ok(Protocol::ThirdPC),
            "IDPR" => Ok(Protocol::IDPR),
            "XTP" => Ok(Protocol::XTP),
            "DDP" => Ok(Protocol::DDP),
            "IDPRCMTP" => Ok(Protocol::IDPRCMTP),
            "TP++" => Ok(Protocol::TPPlusPlus),
            "IL" => Ok(Protocol::IL),
            "IPV6" => Ok(Protocol::IPv6),
            "SDRP" => Ok(Protocol::SDRP),
            "IPV6ROUTE" => Ok(Protocol::IPv6Route),
            "IPV6FRAG" => Ok(Protocol::IPv6Frag),
            "IDRP" => Ok(Protocol::IDRP),
            "RSVP" => Ok(Protocol::RSVP),
            "GRE" => Ok(Protocol::GRE),
            "DSR" => Ok(Protocol::DSR),
            "BNA" => Ok(Protocol::BNA),
            "ESP" => Ok(Protocol::ESP),
            "AH" => Ok(Protocol::AH),
            "INLSP" => Ok(Protocol::INLSP),
            #[allow(deprecated)]
            "SWIPE" => Ok(Protocol::SWIPE),
            "NARP" => Ok(Protocol::NARP),
            "MINIPV4" => Ok(Protocol::MinIPv4),
            "TLSP" => Ok(Protocol::TLSP),
            "SKIP" => Ok(Protocol::SKIP),
            "IPV6ICMP" => Ok(Protocol::IPv6ICMP),
            "IPV6NONXT" => Ok(Protocol::IPv6NoNxt),
            "IPV6OPTS" => Ok(Protocol::IPv6Opts),
            "HOSTINTERNAL" => Ok(Protocol::HostInternal),
            "CFTP" => Ok(Protocol::CFTP),
            "LOCALNETWORK" => Ok(Protocol::LocalNetwork),
            "SATEXPAK" => Ok(Protocol::SATEXPAK),
            "KRYPTOLAN" => Ok(Protocol::KRYPTOLAN),
            "RVD" => Ok(Protocol::RVD),
            "IPPC" => Ok(Protocol::IPPC),
            "DISTRIBUTEDFS" => Ok(Protocol::DistributedFS),
            "SATMON" => Ok(Protocol::SATMON),
            "VISA" => Ok(Protocol::VISA),
            "IPCV" => Ok(Protocol::IPCV),
            "CPNX" => Ok(Protocol::CPNX),
            "CPHB" => Ok(Protocol::CPHB),
            "WSN" => Ok(Protocol::WSN),
            "PVP" => Ok(Protocol::PVP),
            "BRSATMON" => Ok(Protocol::BRSATMON),
            "SUNND" => Ok(Protocol::SUNND),
            "WBMON" => Ok(Protocol::WBMON),
            "WBEXPAK" => Ok(Protocol::WBEXPAK),
            "ISOIP" => Ok(Protocol::ISOIP),
            "VMTP" => Ok(Protocol::VMTP),
            "SECUREVMTP" => Ok(Protocol::SECUREVMTP),
            "VINES" => Ok(Protocol::VINES),
            "IPTM" => Ok(Protocol::IPTM),
            "NSFNETIGP" => Ok(Protocol::NSFNETIGP),
            "DGP" => Ok(Protocol::DGP),
            "TCF" => Ok(Protocol::TCF),
            "EIGRP" => Ok(Protocol::EIGRP),
            "OSPFIGP" => Ok(Protocol::OSPFIGP),
            "SPRITERPC" => Ok(Protocol::SpriteRPC),
            "LARP" => Ok(Protocol::LARP),
            "MTP" => Ok(Protocol::MTP),
            "AX25" => Ok(Protocol::AX25),
            "IPIP" => Ok(Protocol::IPIP),
            #[allow(deprecated)]
            "MICP" => Ok(Protocol::MICP),
            "SCCSP" => Ok(Protocol::SCCSP),
            "ETHERIP" => Ok(Protocol::ETHERIP),
            "ENCAP" => Ok(Protocol::ENCAP),
            "PRIVATEENCRYPTION" => Ok(Protocol::PrivateEncryption),
            "GMTP" => Ok(Protocol::GMTP),
            "IFMP" => Ok(Protocol::IFMP),
            "PNNI" => Ok(Protocol::PNNI),
            "PIM" => Ok(Protocol::PIM),
            "ARIS" => Ok(Protocol::ARIS),
            "SCPS" => Ok(Protocol::SCPS),
            "QNX" => Ok(Protocol::QNX),
            "AN" => Ok(Protocol::AN),
            "IPCOMP" => Ok(Protocol::IPComp),
            "SNP" => Ok(Protocol::SNP),
            "COMPAQPEER" => Ok(Protocol::CompaqPeer),
            "IPXINIP" => Ok(Protocol::IPXinIP),
            "VRRP" => Ok(Protocol::VRRP),
            "PGM" => Ok(Protocol::PGM),
            "ZEROHOP" => Ok(Protocol::ZeroHop),
            "L2TP" => Ok(Protocol::L2TP),
            "DDX" => Ok(Protocol::DDX),
            "IATP" => Ok(Protocol::IATP),
            "STP" => Ok(Protocol::STP),
            "SRP" => Ok(Protocol::SRP),
            "UTI" => Ok(Protocol::UTI),
            "SMP" => Ok(Protocol::SMP),
            #[allow(deprecated)]
            "SM" => Ok(Protocol::SM),
            "PTP" => Ok(Protocol::PTP),
            "ISISOVERIPV4" => Ok(Protocol::ISISoverIPv4),
            "FIRE" => Ok(Protocol::FIRE),
            "CRTP" => Ok(Protocol::CRTP),
            "CRUDP" => Ok(Protocol::CRUDP),
            "SSCOPMCE" => Ok(Protocol::SSCOPMCE),
            "IPLT" => Ok(Protocol::IPLT),
            "SPS" => Ok(Protocol::SPS),
            "PIPE" => Ok(Protocol::PIPE),
            "SCTP" => Ok(Protocol::SCTP),
            "FC" => Ok(Protocol::FC),
            "RSVPE2EIGNORE" => Ok(Protocol::RSVPE2EIGNORE),
            "MOBILITYHEADER" => Ok(Protocol::MobilityHeader),
            "UDPLITE" => Ok(Protocol::UDPLite),
            "MPLSINIP" => Ok(Protocol::MPLSinIP),
            "MANET" => Ok(Protocol::MANET),
            "HIP" => Ok(Protocol::HIP),
            "SHIM6" => Ok(Protocol::Shim6),
            "WESP" => Ok(Protocol::WESP),
            "ROHC" => Ok(Protocol::ROHC),
            "ETHERNET" => Ok(Protocol::Ethernet),
            "AGGFRAG" => Ok(Protocol::AGGFRAG),
            "NSH" => Ok(Protocol::NSH),
            "HOMA" => Ok(Protocol::Homa),
            "BITEMU" => Ok(Protocol::BITEMU),
            "EXPERIMENTALANDTESTING253" => Ok(Protocol::ExperimentalAndTesting253),
            "EXPERIMENTALANDTESTING254" => Ok(Protocol::ExperimentalAndTesting254),
            "RESERVED" => Ok(Protocol::Reserved),
            _ => Err(()),
        }
    }
}
