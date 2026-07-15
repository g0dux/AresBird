//! Built-in AresBird modules.

pub mod active;
pub mod asn;
pub mod discover;
pub mod fingerprint;
pub mod path;
pub mod paths;
pub mod recon;
pub mod registry;
pub mod scan;
pub mod service;
pub mod talk;

pub use registry::builtin_registry;
