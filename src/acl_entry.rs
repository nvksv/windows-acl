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
    },
};

use crate::{
    utils::acl_entry_size,
    types::*,
    sid::{SID, SIDRef, VSID},
    acl::{ACLKind, DACL, SACL},
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub const AVERAGE_ACE_SIZE: u16 = 36;
pub const MAX_ACL_SIZE: u16 = 65535;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

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

    #[inline]
    pub fn new_allow<'s: 'r>( flags: ACE_FLAGS, access_mask: ACCESS_MASK, sid: VSID<'s> ) -> Self {
        Self {
            entry_type: AceType::AccessAllow,
            flags,
            access_mask,
            sid,
            _ph: PhantomData,
        }
    }

    #[inline]
    pub fn new_deny<'s: 'r>( flags: ACE_FLAGS, access_mask: ACCESS_MASK, sid: VSID<'s> ) -> Self {
        Self {
            entry_type: AceType::AccessDeny,
            flags,
            access_mask,
            sid,
            _ph: PhantomData,
        }
    }

    pub fn is_match_any_sid<'s>( &self, mask: &ACLEntryMask ) -> bool {
        if let Some(entry_type) = mask.entry_type {
            if self.entry_type != entry_type {
                return false;
            }
        }

        if mask.flags_mask != ACE_FLAGS(0) {
            if self.flags & mask.flags_mask != mask.flags {
                return false;
            }
        }

        if mask.access_mask_mask != ACCESS_MASK(0) {
            if self.access_mask & mask.access_mask != mask.access_mask_mask {
                return false;
            }
        }

        true
    }

    pub fn is_match<'s>( &self, sid: SIDRef<'s>, mask: &Option<ACLEntryMask> ) -> bool {
        if !self.sid.eq_to_ref(sid) {
            return false;
        }

        if let Some(mask) = mask {
            if !self.is_match_any_sid(mask) {
                return false;
            }
        }

        true
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

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ACLEntryMask {
    /// The entry's type
    pub entry_type: Option<AceType>,

    /// See `AceFlags` in [ACE_HEADER](https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_ace_header)
    pub flags: ACE_FLAGS,
    pub flags_mask: ACE_FLAGS,

    /// See [ACCESS_MASK](https://docs.microsoft.com/en-us/windows/desktop/secauthz/access-mask)
    pub access_mask: ACCESS_MASK,
    pub access_mask_mask: ACCESS_MASK,
}

impl ACLEntryMask {
    /// Returns an `ACLEntry` object with default values.
    #[inline]
    pub fn new() -> Self {
        Self {
            entry_type: None,
            flags: ACE_FLAGS(0),
            flags_mask: ACE_FLAGS(0),
            access_mask: ACCESS_MASK(0),
            access_mask_mask: ACCESS_MASK(0),
        }
    }

    //

    pub fn set_entry_type( mut self, entry_type: AceType ) -> Self {
        self.entry_type = Some(entry_type);
        self
    }

    pub fn unset_entry_type( mut self ) -> Self {
        self.entry_type = None;
        self
    }

    //

    pub fn set_flags( mut self, flags: ACE_FLAGS ) -> Self {
        self.flags = flags;
        self.flags_mask = flags;
        self
    }

    pub fn set_flags_with_mask( mut self, flags: ACE_FLAGS, mask: ACE_FLAGS ) -> Self {
        self.flags = flags;
        self.flags_mask = mask;
        self
    }

    pub fn unset_flags( mut self ) -> Self {
        self.flags = ACE_FLAGS(0);
        self.flags_mask = ACE_FLAGS(0);
        self
    }

    //

    pub fn set_access_mask( mut self, access_mask: ACCESS_MASK ) -> Self {
        self.access_mask = access_mask;
        self.access_mask_mask = access_mask;
        self
    }

    pub fn set_access_mask_with_mask( mut self, access_mask: ACCESS_MASK, mask: ACCESS_MASK ) -> Self {
        self.access_mask = access_mask;
        self.access_mask_mask = mask;
        self
    }

    pub fn unset_access_mask( mut self ) -> Self {
        self.access_mask = ACCESS_MASK(0);
        self.access_mask_mask = ACCESS_MASK(0);
        self
    }

    //

    pub fn set_inherited_flag( mut self, bit: bool ) -> Self {
        
        self.flags &= !INHERITED_ACE;
        
        if bit {
            self.flags_mask |= INHERITED_ACE;
        }

        self.flags_mask |= INHERITED_ACE;

        self
    }


}
