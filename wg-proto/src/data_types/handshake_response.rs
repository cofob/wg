use crate::errors::MessageDecodeError;

use super::{
    traits::{FromLEArray, ToLEArray},
    GetMessageType, MessageType,
};

/// A handshake response message.
///
/// This message is sent by a peer in response to a handshake initiation message.
/// ([`MessageType::HandshakeResponse`])
///
/// Internally, the message is represented as a mutable byte slice. This allows for efficient
/// serialization and deserialization of the message.
///
/// The message is exactly 92 bytes long and has the following format:
/// ```plaintext
/// handshake_response {
///     u8 message_type
///     u8 reserved_zero[3]
///     u32 sender_index
///     u32 receiver_index
///     u8 unencrypted_ephemeral[32]
///     u8 encrypted_nothing[AEAD_LEN(0)]
///     u8 mac1[16]
///     u8 mac2[16]
/// }
/// ```
pub struct HandshakeResponseMessage<'a> {
    data: &'a mut [u8],
}

impl<'a> HandshakeResponseMessage<'a> {
    /// Create a new byte sequence for a HandshakeResponseMessage.
    ///
    /// # Example
    ///
    /// ```
    /// use wg_proto::data_types::HandshakeResponseMessage;
    ///
    /// let mut message_data = HandshakeResponseMessage::init();
    /// let mut message = HandshakeResponseMessage::from_bytes_unchecked(&mut message_data);
    /// ```
    pub fn init() -> [u8; 92] {
        let mut data = [0; 92];
        data[0] = MessageType::HandshakeResponse.to_u8();
        data
    }

    /// Create a HandshakeResponseMessage from a mutable byte slice.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the byte slice is exactly 92 bytes long,
    /// and that the contents of the byte slice are a valid HandshakeInitiationMessage.
    ///
    /// Use the `from_bytes` method for a safe alternative.
    pub fn from_bytes_unchecked(data: &'a mut (impl AsMut<[u8]> + ?Sized)) -> Self {
        Self {
            data: data.as_mut(),
        }
    }

    /// Create a HandshakeResponseMessage from a mutable byte slice.
    ///
    /// # Safety
    ///
    /// This function checks that the byte slice is exactly 92 bytes long
    /// and that the first byte is the correct message type.
    pub fn from_bytes(
        data: &'a mut (impl AsMut<[u8]> + ?Sized),
    ) -> Result<Self, MessageDecodeError> {
        let data = data.as_mut();
        if data.len() != 92 {
            return Err(MessageDecodeError::InvalidLength);
        }
        if data[0] != MessageType::HandshakeResponse.to_u8() {
            return Err(MessageDecodeError::InvalidMessageType);
        }
        Ok(Self { data })
    }

    /// To byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        self.data
    }

    /// To mutable byte slice.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        self.data
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

    /// Get the receiver index.
    pub fn receiver_index<T: FromLEArray<4>>(&self) -> T {
        T::from_le_array(&self.data[8..12].try_into().unwrap())
    }

    /// Get the receiver index as a byte slice.
    pub fn receiver_index_bytes(&self) -> &[u8] {
        &self.data[8..12]
    }

    /// Set the receiver index.
    pub fn set_receiver_index<T>(&mut self, receiver_index: impl ToLEArray<T, 4>) -> &mut Self {
        self.data[8..12].copy_from_slice(&receiver_index.to_le_array());
        self
    }

    /// Get the unencrypted ephemeral public key.
    pub fn unencrypted_ephemeral(&self) -> &[u8] {
        &self.data[12..44]
    }

    /// Set the unencrypted ephemeral public key.
    pub fn set_unencrypted_ephemeral(&mut self, ephemeral: impl AsRef<[u8]>) -> &mut Self {
        self.data[12..44].copy_from_slice(ephemeral.as_ref());
        self
    }

    /// Get the encrypted nothing.
    pub fn encrypted_nothing(&self) -> &[u8] {
        &self.data[44..60]
    }

    /// Set the encrypted nothing.
    pub fn set_encrypted_nothing(&mut self, nothing: impl AsRef<[u8]>) -> &mut Self {
        self.data[44..60].copy_from_slice(nothing.as_ref());
        self
    }

    /// Get the MAC1 field.
    pub fn mac1(&self) -> &[u8] {
        &self.data[60..76]
    }

    /// Set the MAC1 field.
    pub fn set_mac1(&mut self, mac1: impl AsRef<[u8]>) -> &mut Self {
        self.data[60..76].copy_from_slice(mac1.as_ref());
        self
    }

    /// Get message content for MAC1.
    pub fn mac1_content(&self) -> &[u8] {
        &self.data[..60]
    }

    /// Get the MAC2 field.
    pub fn mac2(&self) -> &[u8] {
        &self.data[76..92]
    }

    /// Set the MAC2 field.
    pub fn set_mac2(&mut self, mac2: impl AsRef<[u8]>) -> &mut Self {
        self.data[76..92].copy_from_slice(mac2.as_ref());
        self
    }

    /// Get message content for MAC2.
    pub fn mac2_content(&self) -> &[u8] {
        &self.data[..76]
    }
}

impl GetMessageType for HandshakeResponseMessage<'_> {
    fn message_type(&self) -> MessageType {
        MessageType::HandshakeResponse
    }
}

impl From<&HandshakeResponseMessage<'_>> for Vec<u8> {
    fn from(value: &HandshakeResponseMessage) -> Vec<u8> {
        value.data.to_vec()
    }
}

impl<'a> From<&'a mut [u8]> for HandshakeResponseMessage<'a> {
    fn from(value: &'a mut [u8]) -> HandshakeResponseMessage<'a> {
        HandshakeResponseMessage::from_bytes_unchecked(value)
    }
}

impl AsRef<[u8]> for HandshakeResponseMessage<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl AsMut<[u8]> for HandshakeResponseMessage<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl std::fmt::Debug for HandshakeResponseMessage<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeResponseMessage")
            .field("message_type", &self.message_type())
            .field("sender_index", &self.sender_index::<u32>())
            .field("receiver_index", &self.receiver_index::<u32>())
            .field("unencrypted_ephemeral", &self.unencrypted_ephemeral())
            .field("encrypted_nothing", &self.encrypted_nothing())
            .field("mac1", &self.mac1())
            .field("mac2", &self.mac2())
            .finish()
    }
}
