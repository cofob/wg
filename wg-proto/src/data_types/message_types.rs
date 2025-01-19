/// Enum representing the different types of messages that can be sent between peers.
#[derive(Clone, Copy, Debug)]
pub enum MessageType {
    /// A handshake initiation message.
    HandshakeInitiation,
    /// A handshake response message.
    HandshakeResponse,
    /// A handshake cookie reply message.
    HandshakeCookieReply,
    /// Data packet message.
    PacketData,
}

impl MessageType {
    /// Convert a `u8` value to a `MessageType`.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::HandshakeInitiation),
            2 => Some(Self::HandshakeResponse),
            3 => Some(Self::HandshakeCookieReply),
            4 => Some(Self::PacketData),
            _ => None,
        }
    }

    /// Convert a `MessageType` to a `u8` value.
    pub fn to_u8(&self) -> u8 {
        match self {
            Self::HandshakeInitiation => 1,
            Self::HandshakeResponse => 2,
            Self::HandshakeCookieReply => 3,
            Self::PacketData => 4,
        }
    }
}

impl From<u8> for MessageType {
    fn from(value: u8) -> Self {
        Self::from_u8(value).unwrap()
    }
}

impl From<MessageType> for u8 {
    fn from(value: MessageType) -> Self {
        value.to_u8()
    }
}

/// Trait for getting the message type of a message.
pub trait GetMessageType {
    /// Get the message type of the message.
    fn message_type(&self) -> MessageType;
}
