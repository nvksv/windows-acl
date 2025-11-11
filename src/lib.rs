//! `windows-acl` is a Rust library to simplify Windows ACL operations.
#![cfg(windows)]

mod types;
mod sid;
mod privilege;
mod windows_security_descriptor;
mod acl_kind;
mod ace;
mod acl;
mod security_descriptor;
mod utils;

pub use acl_kind::{ACLKind, DACL, SACL};
pub use security_descriptor::{SecurityDescriptor};
pub use ace::{ACE, ACEFilter, ACEMask, IntoOptionalACEFilter, IntoOptionalACEMask};
pub use acl::{ACL, ACLEntryIterator, ACLVecList};
pub use sid::{SID, SIDRef, VSID};

pub use types::{AceType, ACCESS_MASK, IntoAccessMask};

pub mod helper {
    pub use crate::utils::{current_user_account_name, DebugIdent, DebugUnpretty};
    pub use crate::types::{
        AccessMaskIdents, AceFlagsIdents, AceFlagsFullIdents, AceFlagsShortIdents, FileAccessRightsFullIdents, FileAccessRightsShortIdents,
        AceFlagsRepresenter, 
    };
}

pub mod lowlevel {
    pub use crate::windows_security_descriptor::WindowsSecurityDescriptor as SecurityDescriptor;
    pub use crate::privilege::Privilege;
}

/// Reexport
pub use ::windows;
pub use ::windows::core::{Result, Error};
pub use ::fallible_iterator;

// #[cfg(test)]
mod tests;
