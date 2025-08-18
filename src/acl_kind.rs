#![allow(non_snake_case)]

use core::{
    fmt,
    hash,
};
use windows::{
    core::{
        Result,
    },
    Win32::{
        Security::{
            ACL as _ACL, ACE_HEADER,
        },
    },
};
use crate::{
    acl_entry::ACLEntry, 
    utils::{parse_dacl_ace, parse_sacl_ace, write_dacl_ace, write_sacl_ace}, 
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DACL {}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SACL {}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#[allow(private_bounds)]
pub trait ACLKind: fmt::Debug + PartialEq + Eq + PartialOrd + Ord + hash::Hash + private::Sealed {
    fn parse_ace<'r>( hdr: &'r ACE_HEADER ) -> Result<ACLEntry<'r, Self>> where Self: Sized;
    fn write_ace<'r>( acl: *mut _ACL, entry: &ACLEntry<'r, Self> ) -> Result<()> where Self: Sized;
}

impl ACLKind for DACL {
    #[inline(always)]
    fn parse_ace<'r>( hdr: &'r ACE_HEADER ) -> Result<ACLEntry<'r, Self>> {
        parse_dacl_ace(hdr)
    }

    #[inline(always)]
    fn write_ace<'r>( acl: *mut _ACL, entry: &ACLEntry<'r, Self> ) -> Result<()> {
        write_dacl_ace( acl, entry )
    }
}

impl ACLKind for SACL {
    #[inline(always)]
    fn parse_ace<'r>( hdr: &'r ACE_HEADER ) -> Result<ACLEntry<'r, Self>> {
        parse_sacl_ace(hdr)
    }

    #[inline(always)]
    fn write_ace<'r>( acl: *mut _ACL, entry: &ACLEntry<'r, Self> ) -> Result<()> {
        write_sacl_ace( acl, entry )
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#[allow(private_bounds)]
pub trait IsACLKind<K: ACLKind>: ACLKind {}

impl IsACLKind<DACL> for DACL {}
impl IsACLKind<SACL> for SACL {}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

impl private::Sealed for DACL {}
impl private::Sealed for SACL {}

mod private {
    pub(crate) trait Sealed {}

}
