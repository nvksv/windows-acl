//! Contains the ACL introspection and manipulation functionality

#![allow(non_snake_case)]

use core::{
    mem,
};
use windows::{
    core::{
        Error, Result,
    },
    Win32::{
        Security::{
            PSID, ACE_FLAGS,
        },
        Storage::FileSystem::{
            FILE_ACCESS_RIGHTS,
        }
    },
};

use crate::{
    acl::acl_entry_size,
    types::*,
    sid::SID,
};

/// `ACLEntry` represents a single access control entry in an access control list
#[derive(Clone, Debug, PartialEq)]
pub struct ACLEntry {
    /// The entry's type
    pub entry_type: AceType,

    /// See `AceSize` in [ACE_HEADER](https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_ace_header)
    pub size: u16,

    /// See `AceFlags` in [ACE_HEADER](https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_ace_header)
    pub flags: ACE_FLAGS,

    /// See [ACCESS_MASK](https://docs.microsoft.com/en-us/windows/desktop/secauthz/access-mask)
    pub mask: FILE_ACCESS_RIGHTS,

    /// The target entity's raw SID
    pub sid: SID,
}

#[allow(dead_code)]
impl ACLEntry {
    /// Returns an `ACLEntry` object with default values.
    #[inline]
    pub fn new() -> ACLEntry {
        ACLEntry {
            entry_type: AceType::Unknown,
            size: 0,
            flags: ACE_FLAGS(0),
            mask: FILE_ACCESS_RIGHTS(0),
            sid: SID::empty(),
        }
    }

    /// The target entity's SID in string representation
    pub fn string_sid(&self) -> Result<Option<String>> {
        self.sid.to_string()
    }

    pub(crate) fn psid(&self) -> Option<PSID> {
        self.sid.psid()
    }

    pub fn size(&self) -> Result<u32> {
        Self::calculate_entry_size( self.entry_type, &self.sid )
    }

    pub fn calculate_entry_size(entry_type: AceType, sid: &SID) -> Result<u32> {
        if sid.is_empty() {
            return Err(Error::empty());
        }
        
        let size = acl_entry_size(entry_type)? + sid.len() - (mem::size_of::<u32>() as u32);
        Ok(size)
    }
}

