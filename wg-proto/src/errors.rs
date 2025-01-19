use thiserror::Error;

#[derive(Debug, Error)]
pub enum MessageDecodeError {
    #[error("Invalid message length")]
    InvalidLength,
    #[error("Invalid message type")]
    InvalidMessageType,
}

#[derive(Debug, Error)]
pub enum WgError {
    #[error("Message decode error: {0}")]
    Decode(#[from] MessageDecodeError),
}
