use crate::errors::MessageDecodeError;

use super::{
    traits::{FromLEArray, ToLEArray},
    GetMessageType, MessageType,
};

/// A handshake initiation message.
///
/// This message is sent by a peer to initiate a new handshake with another peer.
/// ([`MessageType::HandshakeInitiation`])
///
/// Internally, the message is represented as a mutable byte slice. This allows for efficient
/// serialization and deserialization of the message.
///
/// The message is exactly 148 bytes long and has the following format:
/// ```plaintext
/// handshake_initiation {
///     u8 message_type
///     u8 reserved_zero[3]
///     u32 sender_index
///     u8 unencrypted_ephemeral[32]
///     u8 encrypted_static[AEAD_LEN(32)]
///     u8 encrypted_timestamp[AEAD_LEN(12)]
///     u8 mac1[16]
///     u8 mac2[16]
/// }
/// ```
pub struct HandshakeInitiationMessage<'a> {
    data: &'a mut [u8],
}

impl<'a> HandshakeInitiationMessage<'a> {
    /// Create a new byte sequence for a HandshakeInitiationMessage.
    ///
    /// # Example
    ///
    /// ```
    /// use wg_proto::data_types::HandshakeInitiationMessage;
    ///
    /// let mut message_data = HandshakeInitiationMessage::init();
    /// let mut message = HandshakeInitiationMessage::from_bytes_unchecked(&mut message_data);
    /// ```
    pub fn init() -> [u8; 148] {
        let mut data = [0; 148];
        data[0] = MessageType::HandshakeInitiation.to_u8();
        data
    }

    /// Create a HandshakeInitiationMessage from a mutable byte slice.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the byte slice is exactly 148 bytes long,
    /// and that the contents of the byte slice are a valid HandshakeInitiationMessage.
    ///
    /// Use the `from_bytes` method for a safe alternative.
    pub fn from_bytes_unchecked(data: &'a mut (impl AsMut<[u8]> + ?Sized)) -> Self {
        Self {
            data: data.as_mut(),
        }
    }

    /// Create a HandshakeInitiationMessage from a mutable byte slice.
    ///
    /// # Safety
    ///
    /// This function checks that the byte slice is exactly 148 bytes long
    /// and that the first byte is the correct message type.
    pub fn from_bytes(data: &'a mut impl AsMut<[u8]>) -> Result<Self, MessageDecodeError> {
        let data = data.as_mut();
        if data.len() != 148 {
            return Err(MessageDecodeError::InvalidLength);
        }
        if data[0] != MessageType::HandshakeInitiation.to_u8() {
            return Err(MessageDecodeError::InvalidMessageType);
        }
        Ok(Self { data })
    }

    /// Set the message type.
    pub fn set_message_type(&mut self, message_type: MessageType) -> &mut Self {
        self.data[0] = message_type.to_u8();
        self
    }

    /// Get the sender index.
    pub fn sender_index<T: FromLEArray<4>>(&self) -> T {
        T::from_le_array(&self.data[4..8].try_into().unwrap())
    }

    /// Get the sender index as a byte slice.
    pub fn sender_index_bytes(&self) -> &[u8] {
        &self.data[4..8]
    }

    /// Set the sender index.
    pub fn set_sender_index<T>(&mut self, sender_index: impl ToLEArray<T, 4>) -> &mut Self {
        self.data[4..8].copy_from_slice(&sender_index.to_le_array());
        self
    }

    /// Get the unencrypted ephemeral public key.
    pub fn unencrypted_ephemeral(&self) -> &[u8] {
        &self.data[8..40]
    }

    /// Set the unencrypted ephemeral public key.
    pub fn set_unencrypted_ephemeral(&mut self, ephemeral: impl AsRef<[u8]>) -> &mut Self {
        self.data[8..40].copy_from_slice(ephemeral.as_ref());
        self
    }

    /// Get the encrypted static public key.
    pub fn encrypted_static(&self) -> &[u8] {
        &self.data[40..88]
    }

    /// Set the encrypted static public key.
    pub fn set_encrypted_static(&mut self, static_key: impl AsRef<[u8]>) -> &mut Self {
        self.data[40..88].copy_from_slice(static_key.as_ref());
        self
    }

    /// Get the encrypted timestamp.
    pub fn encrypted_timestamp(&self) -> &[u8] {
        &self.data[88..116]
    }

    /// Set the encrypted timestamp.
    pub fn set_encrypted_timestamp(&mut self, timestamp: impl AsRef<[u8]>) -> &mut Self {
        self.data[88..116].copy_from_slice(timestamp.as_ref());
        self
    }

    /// Get the MAC1 field.
    pub fn mac1(&self) -> &[u8] {
        &self.data[116..132]
    }

    /// Set the MAC1 field.
    pub fn set_mac1(&mut self, mac1: impl AsRef<[u8]>) -> &mut Self {
        self.data[116..132].copy_from_slice(mac1.as_ref());
        self
    }

    /// Get message content for MAC1.
    pub fn mac1_content(&self) -> &[u8] {
        &self.data[..116]
    }

    /// Get the MAC2 field.
    pub fn mac2(&self) -> &[u8] {
        &self.data[132..148]
    }

    /// Set the MAC2 field.
    pub fn set_mac2(&mut self, mac2: impl AsRef<[u8]>) -> &mut Self {
        self.data[132..148].copy_from_slice(mac2.as_ref());
        self
    }

    /// Get message content for MAC2.
    pub fn mac2_content(&self) -> &[u8] {
        &self.data[..132]
    }
}

impl GetMessageType for HandshakeInitiationMessage<'_> {
    fn message_type(&self) -> MessageType {
        MessageType::HandshakeInitiation
    }
}

impl From<&HandshakeInitiationMessage<'_>> for Vec<u8> {
    fn from(value: &HandshakeInitiationMessage) -> Vec<u8> {
        value.data.to_vec()
    }
}

impl<'a> From<&'a mut [u8]> for HandshakeInitiationMessage<'a> {
    fn from(value: &'a mut [u8]) -> Self {
        HandshakeInitiationMessage::from_bytes_unchecked(value)
    }
}

impl AsRef<[u8]> for HandshakeInitiationMessage<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl AsMut<[u8]> for HandshakeInitiationMessage<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl std::fmt::Debug for HandshakeInitiationMessage<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeInitiationMessage")
            .field("message_type", &self.message_type())
            .field("sender_index", &self.sender_index::<u32>())
            .field("unencrypted_ephemeral", &self.unencrypted_ephemeral())
            .field("encrypted_static", &self.encrypted_static())
            .field("encrypted_timestamp", &self.encrypted_timestamp())
            .field("mac1", &self.mac1())
            .field("mac2", &self.mac2())
            .finish()
    }
}
