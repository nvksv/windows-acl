//! `windows-acl` is a Rust library to simplify Windows ACL operations.
#![cfg(windows)]

mod types;
mod sid;
mod sd;
mod acl_entry;
mod acl;
mod utils;

pub use acl::ACL;
pub use acl_entry::ACLEntry;
pub use sid::SID;

pub mod helper {
    pub use crate::utils::{current_user};
}

// #[cfg(test)]
mod tests;
