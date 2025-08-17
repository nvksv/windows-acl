//! `windows-acl` is a Rust library to simplify Windows ACL operations.
#![cfg(windows)]

mod types;
mod sid;
mod privilege;
mod sd;
mod acl_entry;
mod acl_list;
mod acl;
mod utils;

pub use acl::{ACL, ACLKind, DACL, SACL};
pub use acl_entry::{ACLEntry, ACLEntryMask};
pub use acl_list::{ACLList, ACLEntryIterator, ACLVecList};
pub use sid::{SID, SIDRef, VSID};
pub use types::{AceType, ACCESS_MASK};

pub mod helper {
    pub use crate::utils::{current_user_account_name};
}

// #[cfg(test)]
mod tests;
