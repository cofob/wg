//! Abstract WireGuard protocol structures and types.
//!
//! This crate provides the abstract structures and types that are used to represent the WireGuard

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "config")]
pub mod config;
pub mod consts;
pub mod crypto;
pub mod data_types;
pub mod errors;
pub mod operations;
pub mod utils;
