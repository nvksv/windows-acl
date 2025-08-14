//! Contains the ACL introspection and manipulation functionality

#![allow(non_snake_case)]

use core::{
    mem,
    hash,
    marker::PhantomData,
};
use windows::{
    core::{
        Error, Result,
    },
    Win32::{
        Security::{
            PSID, ACE_FLAGS, CONTAINER_INHERIT_ACE, FAILED_ACCESS_ACE_FLAG, INHERIT_ONLY_ACE, INHERITED_ACE, 
            NO_PROPAGATE_INHERIT_ACE, OBJECT_INHERIT_ACE, SUCCESSFUL_ACCESS_ACE_FLAG,
        },
        Storage::FileSystem::{
            FILE_ACCESS_RIGHTS,
        }
    },
};

use crate::{
    utils::acl_entry_size,
    types::*,
    sid::{SID, SIDRef, VSID},
    acl::{ACLKind, DACL, SACL},
};

/// `ACLEntry` represents a single access control entry in an access control list
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ACLEntry<'r, K> where K: ACLKind + ?Sized {
    /// The entry's type
    pub entry_type: AceType,

    /// See `AceFlags` in [ACE_HEADER](https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_ace_header)
    pub flags: ACE_FLAGS,

    /// See [ACCESS_MASK](https://docs.microsoft.com/en-us/windows/desktop/secauthz/access-mask)
    pub access_mask: ACCESS_MASK,

    /// The target entity's raw SID
    pub sid: VSID<'r>,

    pub _ph: PhantomData<K>,
}

#[allow(dead_code)]
impl<'r, K> ACLEntry<'r, K> where K: ACLKind + ?Sized {
    /// Returns an `ACLEntry` object with default values.
    #[inline]
    pub fn new() -> Self {
        Self {
            entry_type: AceType::Unknown,
            flags: ACE_FLAGS(0),
            access_mask: ACCESS_MASK::default(),
            sid: VSID::empty(),
            _ph: PhantomData,
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

    pub fn inherited_flag( &self ) -> bool {
        self.flags.contains(INHERITED_ACE)
    }

    pub fn inherit_only_flag( &self ) -> bool {
        self.flags.contains(INHERIT_ONLY_ACE)
    }

    pub fn no_propagate_inherit_flag( &self ) -> bool {
        self.flags.contains(NO_PROPAGATE_INHERIT_ACE)
    }

    pub fn container_inherit_flag( &self ) -> bool {
        self.flags.contains(CONTAINER_INHERIT_ACE)
    }

    pub fn object_inherit_flag( &self ) -> bool {
        self.flags.contains(OBJECT_INHERIT_ACE)
    }

    pub fn successful_access_flag( &self ) -> bool {
        self.flags.contains(SUCCESSFUL_ACCESS_ACE_FLAG)
    }

    pub fn failed_access_flag( &self ) -> bool {
        self.flags.contains(FAILED_ACCESS_ACE_FLAG)
    }
}

impl<'r, K> hash::Hash for ACLEntry<'r, K> where K: ACLKind + ?Sized {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        hash::Hash::hash(&self.entry_type, state);
        hash::Hash::hash(&self.flags.0, state);
        hash::Hash::hash(&self.access_mask.0, state);
        hash::Hash::hash(&self.sid, state);
    }
}

