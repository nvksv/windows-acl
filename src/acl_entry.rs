//! Contains the ACL introspection and manipulation functionality

#![allow(non_snake_case)]

use core::{
    mem,
    hash,
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
    sid::{SID, SIDRef, VSID},
    utils::MaybePtr,
};

/// `ACLEntry` represents a single access control entry in an access control list
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ACLEntry<'r> {
    /// The entry's type
    pub entry_type: AceType,

    /// See `AceSize` in [ACE_HEADER](https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_ace_header)
    pub size: u16,

    /// See `AceFlags` in [ACE_HEADER](https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_ace_header)
    pub flags: ACE_FLAGS,

    /// See [ACCESS_MASK](https://docs.microsoft.com/en-us/windows/desktop/secauthz/access-mask)
    pub mask: FILE_ACCESS_RIGHTS,

    /// The target entity's raw SID
    pub sid: VSID<'r>,
}

#[allow(dead_code)]
impl<'r> ACLEntry<'r> {
    /// Returns an `ACLEntry` object with default values.
    #[inline]
    pub fn new() -> Self {
        Self {
            entry_type: AceType::Unknown,
            size: 0,
            flags: ACE_FLAGS(0),
            mask: FILE_ACCESS_RIGHTS(0),
            sid: VSID::empty(),
        }
    }

    /// The target entity's SID in string representation
    pub fn sid_to_string(&self) -> Result<String> {
        self.sid.to_string()
    }

    pub(crate) fn psid(&self) -> Option<PSID> {
        self.sid.psid()
    }

    pub fn size(&self) -> Result<u32> {
        let sid = self.sid.as_ref().ok_or_else(|| Error::empty())?;
        Self::calculate_entry_size( self.entry_type, sid )
    }

    pub fn calculate_entry_size<'s>(entry_type: AceType, sid: SIDRef<'s>) -> Result<u32> {
        let size = acl_entry_size(entry_type)? + sid.len() - (mem::size_of::<u32>() as u32);
        Ok(size)
    }
}

impl<'r> hash::Hash for ACLEntry<'r> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        hash::Hash::hash(&self.entry_type, state);
        hash::Hash::hash(&self.flags.0, state);
        hash::Hash::hash(&self.mask.0, state);
        hash::Hash::hash(&self.sid, state);
    }
}