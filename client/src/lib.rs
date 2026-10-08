//! The parts of letmeknow that the session process and the browser client share.
pub mod entity;
pub mod proto;
#[cfg(target_arch = "wasm32")]
mod web;
