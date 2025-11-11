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
    utils::{acl_entry_size, DebugIdent, DebugUnpretty},
    types::*,
    winapi::sid::{SIDRef, VSID, IntoVSID},
    acl_kind::{ACLKind, DACL, SACL, IsACLKind},
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub const AVERAGE_ACE_SIZE: u16 = 36;
pub const MAX_ACL_SIZE: u16 = 65535;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/// `ACLEntry` represents a single access control entry in an access control list
#[derive(Clone, PartialEq, Eq)]
pub struct ACE<'r, K: ACLKind> {
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

impl<'r, K: ACLKind> fmt::Debug for ACE<'r, K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ACE")
            .field( "entry_type", &self.entry_type )
            .field( "sid", &self.sid )
            .field( "flags", &DebugUnpretty(AceFlagsRepresenter::<AceFlagsShortIdents>::new(self.flags, None)) )
            .field( "access_mask", &DebugUnpretty(FileAccessRightsRepresenter::<FileAccessRightsShortIdents>::new(self.access_mask, None)) )
            .finish()
    }
}

impl<'r, K: IsACLKind<DACL>> ACE<'r, K> {
    #[inline]
    pub fn new_allow<'s: 'r>( sid: impl IntoVSID<'s>, flags: impl IntoAceFlags, access_mask: impl IntoAccessMask ) -> Self {
        Self {
            entry_type: AceType::AccessAllow,
            sid: sid.into_vsid(),
            flags: flags.into_ace_flags(),
            access_mask: access_mask.into_access_mask(),
            _ph: PhantomData,
        }
    }

    #[inline]
    pub fn new_deny<'s: 'r>( sid: impl IntoVSID<'s>, flags: impl IntoAceFlags, access_mask: impl IntoAccessMask ) -> Self {
        Self {
            entry_type: AceType::AccessDeny,
            sid: sid.into_vsid(),
            flags: flags.into_ace_flags(),
            access_mask: access_mask.into_access_mask(),
            _ph: PhantomData,
        }
    }
}

impl<'r, K: IsACLKind<SACL>> ACE<'r, K> {
    #[inline]
    pub fn new_audit<'s: 'r>( sid: impl IntoVSID<'s>, flags: impl IntoAceFlags, access_mask: impl IntoAccessMask ) -> Self {
        Self {
            entry_type: AceType::SystemAudit,
            sid: sid.into_vsid(),
            flags: flags.into_ace_flags(),
            access_mask: access_mask.into_access_mask(),
            _ph: PhantomData,
        }
    }

    #[inline]
    pub fn new_mandatory_label<'s: 'r>( label_sid: impl IntoVSID<'s>, flags: impl IntoAceFlags, access_mask: impl IntoAccessMask ) -> Self {
        Self {
            entry_type: AceType::SystemMandatoryLabel,
            sid: label_sid.into_vsid(),
            flags: flags.into_ace_flags(),
            access_mask: access_mask.into_access_mask(),
            _ph: PhantomData,
        }
    }
}

impl<'r, K: ACLKind> ACE<'r, K> {
    pub fn is_match_any_sid<'s>( &self, filter: &ACEFilter ) -> bool {
        if filter.never {
            return false;
        }

        if let Some(entry_type) = filter.entry_type {
            if self.entry_type != entry_type {
                return false;
            }
        }

        if filter.flags_mask != ACE_FLAGS(0) {
            if self.flags & filter.flags_mask != filter.flags {
                return false;
            }
        }

        if filter.access_mask_mask != ACCESS_MASK(0) {
            if self.access_mask & filter.access_mask != filter.access_mask_mask {
                return false;
            }
        }

        true
    }

    pub fn is_match<'s>( &self, sid: SIDRef<'s>, filter: &Option<ACEFilter> ) -> bool {
        if !self.sid.eq_to_ref(sid) {
            return false;
        }

        if let Some(mask) = filter {
            if !self.is_match_any_sid(mask) {
                return false;
            }
        }

        true
    }

    pub fn is_eq<'o>( &self, other: &ACE<'o, K>, mask: &Option<ACEMask> ) -> bool {
        if self.sid != other.sid {
            return false;
        }

        if let Some(mask) = mask {
            if mask.never {
                return false;
            }

            if mask.entry_type {
                if self.entry_type != other.entry_type {
                    return false;
                }
            }

            if mask.flags != ACE_FLAGS(0) {
                if self.flags & other.flags != other.flags & other.flags {
                    return false;
                }
            }

            if mask.access_mask != ACCESS_MASK(0) {
                if self.access_mask & mask.access_mask != other.access_mask & mask.access_mask {
                    return false;
                }
            }
        } else {
            if self.entry_type != other.entry_type {
                return false;
            }
            if self.flags != other.flags {
                return false;
            }
            if self.access_mask != other.access_mask {
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

impl<'r, K: ACLKind> hash::Hash for ACE<'r, K> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        hash::Hash::hash(&self.entry_type, state);
        hash::Hash::hash(&self.flags.0, state);
        hash::Hash::hash(&self.access_mask.0, state);
        hash::Hash::hash(&self.sid, state);
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ACEFilter {
    pub never: bool, 

    /// The entry's type
    pub entry_type: Option<AceType>,

    pub flags: ACE_FLAGS,
    pub flags_mask: ACE_FLAGS,

    pub access_mask: ACCESS_MASK,
    pub access_mask_mask: ACCESS_MASK,
}

impl ACEFilter {
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

    /// Returns an `ACLEntry` object with default values.
    #[inline]
    pub fn all() -> Self {
        Self::new()
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

    #[inline]
    pub fn set_never( mut self ) -> Self {
        self.never = true;
        self
    }

    #[inline]
    pub fn unset_never( mut self ) -> Self {
        self.never = false;
        self
    }

    //

    #[inline]
    pub fn set_entry_type( mut self, entry_type: AceType ) -> Self {
        self.entry_type = Some(entry_type);
        self
    }

    #[inline]
    pub fn unset_entry_type( mut self ) -> Self {
        self.entry_type = None;
        self
    }

    //

    #[inline]
    pub fn set_flags( mut self, flags: impl IntoAceFlags ) -> Self {
        self.flags = flags.into_ace_flags();
        self.flags_mask = self.flags;
        self
    }

    #[inline]
    pub fn set_flags_with_mask( mut self, flags: impl IntoAceFlags, mask: impl IntoAceFlags ) -> Self {
        self.flags = flags.into_ace_flags();
        self.flags_mask = mask.into_ace_flags();
        self
    }

    #[inline]
    pub fn unset_flags( mut self ) -> Self {
        self.flags = ACE_FLAGS(0);
        self.flags_mask = ACE_FLAGS(0);
        self
    }

    //

    #[inline]
    pub fn set_access_mask( mut self, access_mask: impl IntoAccessMask ) -> Self {
        self.access_mask = access_mask.into_access_mask();
        self.access_mask_mask = self.access_mask;
        self
    }

    #[inline]
    pub fn set_access_mask_with_mask( mut self, access_mask: impl IntoAccessMask, mask: impl IntoAccessMask ) -> Self {
        self.access_mask = access_mask.into_access_mask();
        self.access_mask_mask = mask.into_access_mask();
        self
    }

    #[inline]
    pub fn unset_access_mask( mut self ) -> Self {
        self.access_mask = ACCESS_MASK(0);
        self.access_mask_mask = ACCESS_MASK(0);
        self
    }

    //

    #[inline]
    pub fn set_inherited_flag( mut self, bit: bool ) -> Self {
        
        self.flags &= !INHERITED_ACE;
        
        if bit {
            self.flags |= INHERITED_ACE;
        }

        self.flags_mask |= INHERITED_ACE;

        self
    }

}

impl fmt::Debug for ACEFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ACEFilter")
            .field( "never", &self.never )
            .field( "entry_type", &self.entry_type )
            .field( "flags", &DebugUnpretty(AceFlagsRepresenter::<AceFlagsShortIdents>::new(self.flags, None)) )
            .field( "flags_mask", &DebugUnpretty(AceFlagsRepresenter::<AceFlagsShortIdents>::new(self.flags_mask, None)) )
            .field( "access_mask", &DebugUnpretty(FileAccessRightsRepresenter::<FileAccessRightsShortIdents>::new(self.access_mask, None)) )
            .field( "access_mask_mask", &DebugUnpretty(FileAccessRightsRepresenter::<FileAccessRightsShortIdents>::new(self.access_mask_mask, None)) )
            .finish()
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
 
pub trait IntoOptionalACEFilter {
    fn into_optional_mask( self ) -> Option<ACEFilter>;
}

impl IntoOptionalACEFilter for Option<ACEFilter> {
    #[inline]
    fn into_optional_mask( self ) -> Option<ACEFilter> {
        self
    }
}

impl IntoOptionalACEFilter for ACEFilter {
    #[inline]
    fn into_optional_mask( self ) -> Option<ACEFilter> {
        Some(self)
    }
}

impl IntoOptionalACEFilter for bool {
    #[inline]
    fn into_optional_mask( self ) -> Option<ACEFilter> {
        if self {
            Some(ACEFilter::all())
        } else {
            Some(ACEFilter::never())
        }
    }
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ACEMask {
    pub never: bool, 
    pub entry_type: bool,
    pub flags: ACE_FLAGS,
    pub access_mask: ACCESS_MASK,
}

impl ACEMask {
    /// Returns an `ACLEntry` object with default values.
    #[inline]
    pub fn new() -> Self {
        Self {
            never: false,
            entry_type: false,
            flags: ACE_FLAGS(0),
            access_mask: ACCESS_MASK(0),
        }
    }

    #[inline]
    pub fn never() -> Self {
        Self {
            never: true,
            entry_type: false,
            flags: ACE_FLAGS(0),
            access_mask: ACCESS_MASK(0),
        }
    }

    //

    #[inline]
    pub fn set_never( mut self ) -> Self {
        self.never = true;
        self
    }

    #[inline]
    pub fn unset_never( mut self ) -> Self {
        self.never = false;
        self
    }

    //

    #[inline]
    pub fn set_entry_type( mut self ) -> Self {
        self.entry_type = true;
        self
    }

    #[inline]
    pub fn unset_entry_type( mut self ) -> Self {
        self.entry_type = false;
        self
    }

    //

    #[inline]
    pub fn set_flags( mut self, flags: impl IntoAceFlags ) -> Self {
        self.flags = flags.into_ace_flags();
        self
    }

    #[inline]
    pub fn unset_flags( mut self ) -> Self {
        self.flags = ACE_FLAGS(0);
        self
    }

    //

    #[inline]
    pub fn set_access_mask( mut self, access_mask: impl IntoAccessMask ) -> Self {
        self.access_mask = access_mask.into_access_mask();
        self
    }


    #[inline]
    pub fn unset_access_mask( mut self ) -> Self {
        self.access_mask = ACCESS_MASK(0);
        self
    }

    //

    #[inline]
    pub fn set_inherited_flag( mut self ) -> Self {
        self.flags |= INHERITED_ACE;
        self
    }

}

impl fmt::Debug for ACEMask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ACEMask")
            .field( "never", &self.never )
            .field( "entry_type", &self.entry_type )
            .field( "flags", &DebugUnpretty(AceFlagsRepresenter::<AceFlagsShortIdents>::new(self.flags, None)) )
            .field( "access_mask", &DebugUnpretty(FileAccessRightsRepresenter::<FileAccessRightsShortIdents>::new(self.access_mask, None)) )
            .finish()
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
 
pub trait IntoOptionalACEMask {
    fn into_optional_mask( self ) -> Option<ACEMask>;
}

impl IntoOptionalACEMask for Option<ACEMask> {
    #[inline]
    fn into_optional_mask( self ) -> Option<ACEMask> {
        self
    }
}

impl IntoOptionalACEMask for ACEMask {
    #[inline]
    fn into_optional_mask( self ) -> Option<ACEMask> {
        Some(self)
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

