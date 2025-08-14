//! `windows-acl` is a Rust library to simplify Windows ACL operations.
#![cfg(windows)]

// mod fallible_iterator;
mod types;
mod sid;
mod sd;
mod acl_entry;
mod raw_acl;
mod acl;
mod utils;

pub use acl::{ACL, ACLKind, DACL, SACL};
pub use acl_entry::ACLEntry;
pub use sid::{SID, SIDRef, VSID};
pub use types::{AceType, ACCESS_MASK};

pub mod helper {
    pub use crate::utils::{current_user_account_name};
}

// #[cfg(test)]
mod tests;
