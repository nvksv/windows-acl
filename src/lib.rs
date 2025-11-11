//! `windows-acl` is a Rust library to simplify Windows ACL operations.
#![cfg(windows)]

mod types;
mod winapi;
mod acl_kind;
mod ace;
mod acl;
mod security_descriptor;
mod utils;

pub use acl_kind::{ACLKind, DACL, SACL};
pub use security_descriptor::{SecurityDescriptor};
pub use ace::{ACE, ACEFilter, ACEMask, IntoOptionalACEFilter, IntoOptionalACEMask};
pub use acl::{ACL, ACLEntryIterator, ACLVecList};
pub use winapi::sid::{SID, SIDRef, VSID};
pub use types::{AceType, ACCESS_MASK, IntoAccessMask};

pub mod helper {
    pub use crate::{
        utils::{current_user_account_name, DebugIdent, DebugUnpretty},
        types::{FileAccessRightsRepresenter, FileAccessRightsFullIdents, FileAccessRightsShortIdents, AccessMaskIdents, AceFlagsFullIdents, AceFlagsShortIdents, AceFlagsRepresenter},
    };
}

pub mod lowlevel {
    pub use crate::winapi::security_descriptor::WindowsSecurityDescriptor as SecurityDescriptor;
    pub use crate::winapi::privilege::Privilege;
}

/// Reexport
pub use ::windows;
pub use ::windows::core::{Result, Error};
pub use ::fallible_iterator;

// #[cfg(test)]
mod tests;
