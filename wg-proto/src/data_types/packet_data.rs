use crate::errors::MessageDecodeError;

use super::{
    traits::{FromLEArray, ToLEArray},
    GetMessageType, MessageType,
};

/// A data packet message.
///
/// This message is used to encapsulate encrypted packets.
/// ([`MessageType::DataPacket`])
///
/// Internally, the message is represented as a mutable byte slice. This allows for efficient
/// serialization and deserialization of the message.
///
/// The message is at least 32 bytes long (16 bytes header + 16 bytes AEAD overhead) and has
/// the following format:
/// ```plaintext
/// packet_data {
///     u8 message_type
///     u8 reserved_zero[3]
///     u32 receiver_index
///     u64 counter
///     u8 encrypted_encapsulated_packet[]
/// }
/// ```
pub struct PacketData<'a> {
    pub data: &'a mut [u8],
}

impl<'a> PacketData<'a> {
    pub fn prepare_data(&mut self) {
        // Set the message type to DataPacket
        self.data[0] = MessageType::PacketData.to_u8();
        // Fill 3 bytes with 0
        self.data[1..4].copy_from_slice(&[0, 0, 0]);
        // Fill 8 bytes with 0
    }

    /// Create a new PacketData from a byte slice.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the byte slice is at least 32 bytes long,
    /// and that the contents of the byte slice are a valid PacketData.
    ///
    /// Use the `from_bytes` method for a safe alternative.
    pub fn from_bytes_unchecked(data: &'a mut (impl AsMut<[u8]> + ?Sized)) -> Self {
        PacketData {
            data: data.as_mut(),
        }
    }

    /// Create a PacketData from a mutable byte slice.
    ///
    /// # Safety
    ///
    /// This function checks that the byte slice is at least 32 bytes long and that the message type
    /// is correct. It does not check the contents of the byte slice.
    pub fn from_bytes(
        data: &'a mut (impl AsMut<[u8]> + ?Sized),
    ) -> Result<Self, MessageDecodeError> {
        let data = data.as_mut();
        if data.len() < 32 {
            return Err(MessageDecodeError::InvalidLength);
        }
        if data[0] != MessageType::PacketData.to_u8() {
            return Err(MessageDecodeError::InvalidMessageType);
        }
        Ok(PacketData { data })
    }

    /// To byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        self.data
    }

    /// To mutable byte slice.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        self.data
    }

    /// Get the receiver index.
    pub fn receiver_index<T: FromLEArray<4>>(&self) -> T {
        T::from_le_array(&self.data[4..8].try_into().unwrap())
    }

    /// Get the receiver index as a byte slice.
    pub fn receiver_index_bytes(&self) -> &[u8] {
        &self.data[4..8]
    }

    /// Set the receiver index.
    pub fn set_receiver_index<T>(&mut self, receiver_index: impl ToLEArray<T, 4>) -> &mut Self {
        self.data[4..8].copy_from_slice(&receiver_index.to_le_array());
        self
    }

    /// Get the counter.
    pub fn counter<T: FromLEArray<8>>(&self) -> T {
        T::from_le_array(&self.data[8..16].try_into().unwrap())
    }

    /// Get the counter as a byte slice.
    pub fn counter_bytes(&self) -> &[u8] {
        &self.data[8..16]
    }

    /// Set the counter.
    pub fn set_counter<T>(&mut self, counter: impl ToLEArray<T, 8>) -> &mut Self {
        self.data[8..16].copy_from_slice(&counter.to_le_array());
        self
    }

    /// Get the encrypted encapsulated packet.
    pub fn encrypted_encapsulated_packet(&self) -> &[u8] {
        &self.data[16..]
    }

    /// Get mutable reference to the encrypted encapsulated packet.
    pub fn encrypted_encapsulated_packet_mut(&mut self) -> &mut [u8] {
        &mut self.data[16..]
    }

    /// Get slice of the unencrypted encapsulated packet.
    pub fn encapsulated_packet(&self) -> &[u8] {
        &self.data[16..&self.data.len() - 16]
    }

    /// Set the encrypted encapsulated packet.
    ///
    /// This function will copy the contents of the given slice into the message, and hence
    /// is not recommended for use. Instead, use the `prepare_data` method to prepare the message
    /// in buffer and use in-place encryption to encrypt the packet.
    pub fn set_encrypted_encapsulated_packet(&mut self, packet: &[u8]) -> &mut Self {
        self.data[16..].copy_from_slice(packet);
        self
    }
}

impl GetMessageType for PacketData<'_> {
    fn message_type(&self) -> MessageType {
        MessageType::PacketData
    }
}

impl From<&PacketData<'_>> for Vec<u8> {
    fn from(value: &PacketData) -> Vec<u8> {
        value.data.to_vec()
    }
}

impl<'a> From<&'a mut [u8]> for PacketData<'a> {
    fn from(value: &'a mut [u8]) -> PacketData<'a> {
        PacketData::from_bytes_unchecked(value)
    }
}

impl AsRef<[u8]> for PacketData<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl AsMut<[u8]> for PacketData<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl std::fmt::Debug for PacketData<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketData")
            .field("message_type", &self.message_type())
            .field("receiver_index", &self.receiver_index::<u32>())
            .field("counter", &self.counter::<u64>())
            .field(
                "encrypted_encapsulated_packet_len",
                &self.encrypted_encapsulated_packet().len(),
            )
            .finish()
    }
}
