//! `windows-acl` is a Rust library to simplify Windows ACL operations.
#![cfg(windows)]

mod ace;
mod acl;
mod acl_kind;
mod security_descriptor;
mod types;
mod utils;
mod winapi;

pub use ace::{ACEFilter, ACEMask, IntoOptionalACEFilter, IntoOptionalACEMask, ACE};
pub use acl::{ACLEntryIterator, ACLVecList, ACL};
pub use acl_kind::{ACLKind, DACL, SACL};
pub use security_descriptor::SecurityDescriptor;
pub use types::{AceType, IntoAccessMask, ACCESS_MASK};
pub use winapi::api::ErrorExt;
pub use winapi::sid::{IntoVSID, SIDRef, SID, VSID};

pub mod helper {
    pub use crate::{
        types::{
            AccessMaskIdents, AceFlagsFullIdents, AceFlagsRepresenter, AceFlagsShortIdents,
            FileAccessRightsFullIdents, FileAccessRightsRepresenter, FileAccessRightsShortIdents,
        },
        utils::{current_user_account_name, DebugIdent, DebugUnpretty},
    };
}

pub mod lowlevel {
    pub use crate::winapi::privilege::Privilege;
    pub use crate::winapi::security_descriptor::WindowsSecurityDescriptor as SecurityDescriptor;
}

pub use ::fallible_iterator;
pub use ::widestring;
/// Reexport
pub use ::windows;
pub use ::windows::core::{Error, Result};

#[cfg(test)]
mod tests;
