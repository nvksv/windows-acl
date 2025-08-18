//! Contains the ACL introspection and manipulation functionality

#![allow(non_snake_case)]

use core::{
    mem,
    hash,
    marker::PhantomData,
    fmt,
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
    utils::{acl_entry_size, DebugIdent},
    types::*,
    sid::{SIDRef, VSID},
    acl_kind::{ACLKind, DACL, SACL, IsACLKind},
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub const AVERAGE_ACE_SIZE: u16 = 36;
pub const MAX_ACL_SIZE: u16 = 65535;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/// `ACLEntry` represents a single access control entry in an access control list
#[derive(Clone, PartialEq, Eq)]
pub struct ACLEntry<'r, K: ACLKind> {
    /// The entry's type
    pub entry_type: AceType,

    /// The target entity's raw SID
    pub sid: VSID<'r>,

    /// See `AceFlags` in [ACE_HEADER](https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_ace_header)
    pub flags: ACE_FLAGS,

    /// See [ACCESS_MASK](https://docs.microsoft.com/en-us/windows/desktop/secauthz/access-mask)
    pub access_mask: ACCESS_MASK,

    pub _ph: PhantomData<K>,
}

impl<'r, K: ACLKind> fmt::Debug for ACLEntry<'r, K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ACLEntry")
            .field( "entry_type", &self.entry_type )
            .field( "flags", &DebugAceFlags(self.flags) )
            .field( "access_mask", &DebugFileAccessRights(self.access_mask) )
            .field( "sid", &self.sid )
            .finish()
    }
}

impl<'r, K: ACLKind> ACLEntry<'r, K> {
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
}

impl<'r, K: IsACLKind<DACL>> ACLEntry<'r, K> {
    #[inline]
    pub fn new_allow<'s: 'r>( sid: VSID<'s>, flags: ACE_FLAGS, access_mask: ACCESS_MASK ) -> Self {
        Self {
            entry_type: AceType::AccessAllow,
            sid,
            flags,
            access_mask,
            _ph: PhantomData,
        }
    }

    #[inline]
    pub fn new_deny<'s: 'r>( sid: VSID<'s>, flags: ACE_FLAGS, access_mask: ACCESS_MASK ) -> Self {
        Self {
            entry_type: AceType::SystemAudit,
            sid,
            flags,
            access_mask,
            _ph: PhantomData,
        }
    }
}

impl<'r, K: IsACLKind<SACL>> ACLEntry<'r, K> {
    #[inline]
    pub fn new_audit<'s: 'r>( sid: VSID<'s>, flags: ACE_FLAGS, access_mask: ACCESS_MASK ) -> Self {
        Self {
            entry_type: AceType::SystemAudit,
            sid,
            flags,
            access_mask,
            _ph: PhantomData,
        }
    }

    #[inline]
    pub fn new_mandatory_label<'s: 'r>( label_sid: VSID<'s>, flags: ACE_FLAGS, access_mask: ACCESS_MASK ) -> Self {
        Self {
            entry_type: AceType::SystemMandatoryLabel,
            sid: label_sid,
            flags,
            access_mask,
            _ph: PhantomData,
        }
    }
}

impl<'r, K: ACLKind> ACLEntry<'r, K> {
    pub fn is_match_any_sid<'s>( &self, mask: &ACLEntryMask ) -> bool {
        if mask.never {
            return false;
        }
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

impl<'r, K: ACLKind> hash::Hash for ACLEntry<'r, K> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        hash::Hash::hash(&self.entry_type, state);
        hash::Hash::hash(&self.flags.0, state);
        hash::Hash::hash(&self.access_mask.0, state);
        hash::Hash::hash(&self.sid, state);
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ACLEntryMask {
    pub never: bool, 

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
            never: false,
            entry_type: None,
            flags: ACE_FLAGS(0),
            flags_mask: ACE_FLAGS(0),
            access_mask: ACCESS_MASK(0),
            access_mask_mask: ACCESS_MASK(0),
        }
    }

    #[inline]
    pub fn never() -> Self {
        Self {
            never: true,
            entry_type: None,
            flags: ACE_FLAGS(0),
            flags_mask: ACE_FLAGS(0),
            access_mask: ACCESS_MASK(0),
            access_mask_mask: ACCESS_MASK(0),
        }
    }

    //

    pub fn set_never( mut self ) -> Self {
        self.never = true;
        self
    }

    pub fn unset_never( mut self ) -> Self {
        self.never = false;
        self
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

impl fmt::Debug for ACLEntryMask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ACLEntryMask")
            .field( "never", &self.never )
            .field( "entry_type", &self.entry_type )
            .field( "flags", &DebugAceFlags(self.flags) )
            .field( "flags_mask", &DebugAceFlags(self.flags_mask) )
            .field( "access_mask", &DebugFileAccessRights(self.access_mask) )
            .field( "access_mask_mask", &DebugFileAccessRights(self.access_mask_mask) )
            .finish()
    }
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct DebugAceFlags( ACE_FLAGS );

impl fmt::Debug for DebugAceFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_tuple("AceFlags");

        if self.0.contains(OBJECT_INHERIT_ACE) {
            f.field(&DebugIdent("OBJECT_INHERIT_ACE"));
        }
        if self.0.contains(CONTAINER_INHERIT_ACE) {
            f.field(&DebugIdent("CONTAINER_INHERIT_ACE"));
        }
        if self.0.contains(NO_PROPAGATE_INHERIT_ACE) {
            f.field(&DebugIdent("NO_PROPAGATE_INHERIT_ACE"));
        }
        if self.0.contains(INHERIT_ONLY_ACE) {
            f.field(&DebugIdent("INHERIT_ONLY_ACE"));
        }
        if self.0.contains(INHERITED_ACE) {
            f.field(&DebugIdent("INHERITED_ACE"));
        }
        if self.0.contains(SUCCESSFUL_ACCESS_ACE_FLAG) {
            f.field(&DebugIdent("SUCCESSFUL_ACCESS_ACE_FLAG"));
        }
        if self.0.contains(FAILED_ACCESS_ACE_FLAG) {
            f.field(&DebugIdent("FAILED_ACCESS_ACE_FLAG"));
        }

        f.finish()
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
