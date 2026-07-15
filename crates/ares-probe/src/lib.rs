//! Service probes and banner grabbing.

pub mod banner;
pub mod fingerprint;
pub mod service;

pub use banner::grab_banner;
pub use fingerprint::{
    guess_os_correlated, guess_os_from_banner, guess_os_from_observed_ttl, guess_os_from_smb,
    guess_os_from_ttl_rtt,
};
pub use service::{detect_service, detect_service_ex};
