use crate::crypto::blake2::Blake2s;
use crate::crypto::chacha20poly1305::{ChaCha20Poly1305, EncryptionBuffer};
use crate::crypto::tai64::Tai64N;
use crate::data_types::traits::Counter;
use crate::data_types::{
    HandshakeResponseMessage, InitialHandshakeData, PacketData, PeerState, ReadyData,
};
use crate::errors::WgError;
use crate::{consts, data_types};
use crate::{
    crypto::x25519::{X25519EphemeralSecret, X25519PublicKey, X25519StaticSecret},
    data_types::HandshakeInitiationMessage,
};

pub fn initiate_handshake<'a, BLAKE2s: Blake2s, CHACHA: ChaCha20Poly1305, TAI64N: Tai64N>(
    buf: &'a mut [u8],
    rng: &mut impl rand::Rng,
    initiator_static_secret: &'a impl X25519StaticSecret,
    initiator_static_public: &'a impl X25519PublicKey,
    initiator_ephemeral_secret: &'a impl X25519EphemeralSecret,
    initiator_ephemeral_public: &'a impl X25519PublicKey,
    responder_static_public: &'a impl X25519PublicKey,
) -> Result<(HandshakeInitiationMessage<'a>, PeerState), WgError> {
    let mut msg = HandshakeInitiationMessage::from_bytes_unchecked(&mut buf[..148]);

    // Set the message type
    msg.set_message_type(data_types::MessageType::HandshakeInitiation);

    // Compute hashes
    // initiator.chaining_key = HASH(CONSTRUCTION)
    let chaining_key = BLAKE2s::hash(consts::CONSTRUCTION.as_bytes());
    // initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)
    let hash = BLAKE2s::hash(
        &vec![
            chaining_key.to_vec(),
            consts::IDENTIFIER.as_bytes().to_vec(),
        ]
        .concat(),
    );
    let hash =
        BLAKE2s::hash(&vec![hash.to_vec(), responder_static_public.to_bytes().to_vec()].concat());

    // Generate a random 4-byte sender index
    // msg.sender_index = little_endian(initiator.sender_index)
    let sender_index = rng.next_u32();
    msg.set_sender_index(sender_index);

    // Next - 32 bytes of public ephemeral Curve25519 key
    // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
    msg.set_unencrypted_ephemeral(initiator_ephemeral_public.to_bytes());

    // Extend hash with the message
    // initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
    let hash = BLAKE2s::hash(
        &vec![
            hash.to_vec(),
            initiator_ephemeral_public.to_bytes().to_vec(),
        ]
        .concat(),
    );

    // temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
    let temp = BLAKE2s::hmac(&chaining_key, initiator_ephemeral_public.to_bytes());

    // initiator.chaining_key = HMAC(temp, 0x1)
    let message: [u8; 1] = [0x1];
    let chaining_key = BLAKE2s::hmac(&temp, &message);

    // temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
    let dh_result = initiator_ephemeral_secret.diffie_hellman(responder_static_public)?;
    let temp = BLAKE2s::hmac(&chaining_key, &dh_result);

    // initiator.chaining_key = HMAC(temp, 0x1)
    let chaining_key = BLAKE2s::hmac(&temp, &message);

    // key = HMAC(temp, initiator.chaining_key || 0x2)
    let key = BLAKE2s::hmac(&temp, &vec![chaining_key.to_vec(), [0x2].to_vec()].concat());

    // msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
    let encrypted_static =
        CHACHA::aead_encrypt(&key, 0, initiator_static_public.to_bytes(), &hash)?;
    // initiator.hash = HASH(initiator.hash || msg.encrypted_static)
    let hash = BLAKE2s::hash(&vec![hash.to_vec(), encrypted_static.to_vec()].concat());

    msg.set_encrypted_static(&encrypted_static);

    // temp = HMAC(initiator.chaining_key, DH(initiator.static_private, responder.static_public))
    let dh_result = initiator_static_secret.diffie_hellman(responder_static_public)?;
    let temp = BLAKE2s::hmac(&chaining_key, &dh_result);
    // initiator.chaining_key = HMAC(temp, 0x1)
    let chaining_key = BLAKE2s::hmac(&temp, &message);
    // key = HMAC(temp, initiator.chaining_key || 0x2)
    let key = BLAKE2s::hmac(&temp, &vec![chaining_key.to_vec(), [0x2].to_vec()].concat());

    // msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
    let encrypted_timestamp = CHACHA::aead_encrypt(&key, 0, &TAI64N::now().to_bytes(), &hash)?;
    // initiator.hash = HASH(initiator.hash || msg.encrypted_timestamp)
    let hash = BLAKE2s::hash(&vec![hash.to_vec(), encrypted_timestamp.clone()].concat());

    msg.set_encrypted_timestamp(&encrypted_timestamp);

    // msg.mac1 = MAC(HASH(LABEL_MAC1 || responder.static_public), msg[0:offsetof(msg.mac1)])
    let mac1 = BLAKE2s::mac(
        &BLAKE2s::hash(
            &vec![
                consts::LABEL_MAC1.as_bytes(),
                responder_static_public.to_bytes(),
            ]
            .concat(),
        ),
        &msg.mac1_content(),
    );
    msg.set_mac1(&mac1);

    // mac2
    // if (initiator.last_received_cookie is empty or expired)
    //     msg.mac2 = [zeros]
    // else
    //     msg.mac2 = MAC(initiator.last_received_cookie, msg[0:offsetof(msg.mac2)])
    // buf.extend_from_slice(&[0u8; 16]);

    Ok((
        msg,
        PeerState::InitialHandshake(InitialHandshakeData {
            sender_index,
            hash,
            chaining_key,
        }),
    ))
}

pub fn process_handshake_response<
    'a,
    BLAKE2s: Blake2s,
    CHACHA: ChaCha20Poly1305,
    X25519PUBKEY: X25519PublicKey,
>(
    buf: &'a mut [u8],
    state: InitialHandshakeData,
    initiator_static_secret: &'a impl X25519StaticSecret,
    initiator_ephemeral_secret: &'a impl X25519EphemeralSecret,
) -> Result<PeerState, WgError> {
    let msg = HandshakeResponseMessage::from_bytes(&mut buf[..92])?;

    // responser.hash = HASH(responder.hash || msg.unencrypted_ephemeral)
    let hash =
        BLAKE2s::hash(&vec![state.hash.to_vec(), msg.unencrypted_ephemeral().to_vec()].concat());

    // temp = HMAC(responder.chaining_key, msg.unencrypted_ephemeral)
    let temp = BLAKE2s::hmac(&state.chaining_key, msg.unencrypted_ephemeral());

    // responder.chaining_key = HMAC(temp, 0x1)
    let chaining_key = BLAKE2s::hmac(&temp, &[0x1]);

    // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.ephemeral_public))
    let unencrypted_ephemeral = X25519PUBKEY::from_bytes(msg.unencrypted_ephemeral())?;
    let dh_result = initiator_ephemeral_secret.diffie_hellman(&unencrypted_ephemeral)?;
    let temp = BLAKE2s::hmac(&chaining_key, &dh_result);

    // responder.chaining_key = HMAC(temp, 0x1)
    let chaining_key = BLAKE2s::hmac(&temp, &[0x1]);

    // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.static_public))
    let dh_result = initiator_static_secret.diffie_hellman(&unencrypted_ephemeral)?;
    let temp = BLAKE2s::hmac(&chaining_key, &dh_result);

    // responder.chaining_key = HMAC(temp, 0x1)
    let chaining_key = BLAKE2s::hmac(&temp, &[0x1]);

    // temp = HMAC(responder.chaining_key, preshared_key)
    let temp = BLAKE2s::hmac(&chaining_key, &[0u8; 32]);

    // responder.chaining_key = HMAC(temp, 0x1)
    let chaining_key = BLAKE2s::hmac(&temp, &[0x1]);

    // temp2 = HMAC(temp, responder.chaining_key || 0x2)
    let temp2 = BLAKE2s::hmac(&temp, &vec![chaining_key.to_vec(), [0x2].to_vec()].concat());

    // key = HMAC(temp, temp2 || 0x3)
    let key = BLAKE2s::hmac(&temp, &vec![temp2.to_vec(), [0x3].to_vec()].concat());

    // responder.hash = HASH(responder.hash || temp2)
    let hash = BLAKE2s::hash(&vec![hash.to_vec(), temp2.to_vec()].concat());

    // decrypt msg.encrypted_nothing
    let nothing_plain = CHACHA::aead_decrypt(&key, 0, msg.encrypted_nothing(), &hash)?;

    if !nothing_plain.is_empty() {
        return Err(WgError::EncryptedEmptyNonEmpty);
    }

    // temp1 = HMAC(initiator.chaining_key, [empty])
    let temp1 = BLAKE2s::hmac(&chaining_key, &[]);
    // temp2 = HMAC(temp1, 0x1)
    let temp2 = BLAKE2s::hmac(&temp1, &[0x1]);
    // temp3 = HMAC(temp1, temp2 || 0x2)
    let temp3 = BLAKE2s::hmac(&temp1, &vec![temp2.to_vec(), [0x2].to_vec()].concat());
    // initiator.sending_key = temp2
    let sending_key = temp2;
    // initiator.receiving_key = temp3
    let receiving_key = temp3;

    Ok(PeerState::Ready(data_types::ReadyData::new(
        sending_key,
        receiving_key,
        msg.sender_index(),
    )))
}

pub struct EncryptData {
    pub padded_len: usize,
    pub slice: (usize, usize),
    pub counter: u64,
}

pub fn prepare_packet<'a>(
    buf: &'a mut [u8],
    start_offset: usize,
    len: usize,
    state: &mut ReadyData,
) -> Result<(PacketData<'a>, EncryptData), WgError> {
    // Calculate padding so that len is a multiple of 16
    let padding = 16 - (len % 16);
    let padded_len = len + padding;
    if len % 16 != 0 {
        // Pad the data to a multiple of 16 bytes
        buf[start_offset + len..start_offset + padded_len].copy_from_slice(&vec![0u8; padding]);
    }

    // Determine header location and total length
    let header_start = start_offset - 16;
    let full_len = padded_len + 32;

    // Create our packet wrapper over the slice
    let mut packet =
        PacketData::from_bytes_unchecked(&mut buf[header_start..header_start + full_len]);
    packet.prepare_data();

    let counter = state.sending_key_counter.next_counter();

    // Populate the necessary fields
    packet.set_receiver_index(state.receiver_index);
    packet.set_counter(counter);

    Ok((
        packet,
        EncryptData {
            padded_len,
            slice: (start_offset, padded_len + 16),
            counter,
        },
    ))
}

pub fn encrypt_data_in_place<'a, CHACHA, CHACHABUFFER>(
    data: &'a mut [u8],
    padded_len: usize,
    key: &[u8; 32],
    counter: u64,
) -> Result<(), WgError>
where
    CHACHA: ChaCha20Poly1305,
    CHACHABUFFER: EncryptionBuffer<'a> + 'a,
{
    let buffer = CHACHABUFFER::new(data, padded_len);
    CHACHA::aead_encrypt_in_place(buffer, key, counter, &[])?;
    Ok(())
}
