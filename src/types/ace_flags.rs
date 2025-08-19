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
    sid::{SIDRef, VSID, IntoVSID},
    acl_kind::{ACLKind, DACL, SACL, IsACLKind},
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub trait AceFlagsIdents {
    fn object_inherit() -> DebugIdent;
    fn container_inherit() -> DebugIdent;
    fn no_propagate_inherit() -> DebugIdent;
    fn inherit_only() -> DebugIdent;
    fn inherited() -> DebugIdent;
    fn successful_access_flag() -> DebugIdent;
    fn failed_access_flag() -> DebugIdent;
}

pub struct AceFlagsFullIdents {}

impl AceFlagsIdents for AceFlagsFullIdents {
    fn object_inherit() -> DebugIdent {
        DebugIdent("OBJECT_INHERIT")
    }

    fn container_inherit() -> DebugIdent {
        DebugIdent("CONTAINER_INHERIT")
    }

    fn no_propagate_inherit() -> DebugIdent {
        DebugIdent("NO_PROPAGATE_INHERIT")
    }

    fn inherit_only() -> DebugIdent {
        DebugIdent("INHERIT_ONLY")
    }

    fn inherited() -> DebugIdent {
        DebugIdent("INHERITED")
    }

    fn successful_access_flag() -> DebugIdent {
        DebugIdent("SUCCESSFUL_ACCESS_FLAG")
    }

    fn failed_access_flag() -> DebugIdent {
        DebugIdent("FAILED_ACCESS_FLAG")
    }
}

pub struct AceFlagsShortIdents {}

impl AceFlagsIdents for AceFlagsShortIdents {
    fn object_inherit() -> DebugIdent {
        DebugIdent("OI")
    }

    fn container_inherit() -> DebugIdent {
        DebugIdent("CI")
    }

    fn no_propagate_inherit() -> DebugIdent {
        DebugIdent("NPI")
    }

    fn inherit_only() -> DebugIdent {
        DebugIdent("IO")
    }

    fn inherited() -> DebugIdent {
        DebugIdent("I")
    }

    fn successful_access_flag() -> DebugIdent {
        DebugIdent("SAF")
    }

    fn failed_access_flag() -> DebugIdent {
        DebugIdent("FAF")
    }
}


pub struct DebugAceFlags<N: AceFlagsIdents>{
    pub flags: ACE_FLAGS,
    _ph: PhantomData<N>,
}

impl<N: AceFlagsIdents> DebugAceFlags<N> {
    pub fn new( flags: ACE_FLAGS ) -> Self {
        Self { 
            flags,
            _ph: PhantomData
        }
    }
}

impl<N: AceFlagsIdents> fmt::Debug for DebugAceFlags<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_tuple("AceFlags");

        if self.flags.contains(OBJECT_INHERIT_ACE) {
            f.field(&N::object_inherit());
        }
        if self.flags.contains(CONTAINER_INHERIT_ACE) {
            f.field(&N::container_inherit());
        }
        if self.flags.contains(NO_PROPAGATE_INHERIT_ACE) {
            f.field(&N::no_propagate_inherit());
        }
        if self.flags.contains(INHERIT_ONLY_ACE) {
            f.field(&N::inherit_only());
        }
        if self.flags.contains(INHERITED_ACE) {
            f.field(&N::inherited());
        }
        if self.flags.contains(SUCCESSFUL_ACCESS_ACE_FLAG) {
            f.field(&N::successful_access_flag());
        }
        if self.flags.contains(FAILED_ACCESS_ACE_FLAG) {
            f.field(&N::failed_access_flag());
        }

        f.finish()
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub trait IntoAceFlags {
    fn into_ace_flags( self ) -> ACE_FLAGS;
}

impl IntoAceFlags for ACE_FLAGS {
    #[inline]
    fn into_ace_flags( self ) -> ACE_FLAGS {
        self
    }
}

impl IntoAceFlags for u32 {
    #[inline]
    fn into_ace_flags( self ) -> ACE_FLAGS {
        ACE_FLAGS(self)
    }
}