#![allow(non_snake_case)]

use crate::{
    ace::ACE,
    utils::{parse_dacl_ace, parse_sacl_ace, write_dacl_ace, write_sacl_ace},
};
use core::{fmt, hash};
use windows::{
    core::Result,
    Win32::Security::{
        ACE_HEADER, ACL as _ACL, DACL_SECURITY_INFORMATION, OBJECT_SECURITY_INFORMATION,
        SACL_SECURITY_INFORMATION,
    },
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DACL {}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SACL {}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#[allow(private_bounds)]
pub trait ACLKind:
    fmt::Debug + PartialEq + Eq + PartialOrd + Ord + hash::Hash + private::Sealed
{
    fn parse_ace<'r>(hdr: &'r ACE_HEADER) -> Result<ACE<'r, Self>>
    where
        Self: Sized;
    fn write_ace<'r>(acl: *mut _ACL, entry: &ACE<'r, Self>) -> Result<()>
    where
        Self: Sized;
    fn get_security_information_bit() -> OBJECT_SECURITY_INFORMATION;
}

impl ACLKind for DACL {
    #[inline(always)]
    fn parse_ace<'r>(hdr: &'r ACE_HEADER) -> Result<ACE<'r, Self>> {
        parse_dacl_ace(hdr)
    }

    #[inline(always)]
    fn write_ace<'r>(acl: *mut _ACL, entry: &ACE<'r, Self>) -> Result<()> {
        write_dacl_ace(acl, entry)
    }

    #[inline(always)]
    fn get_security_information_bit() -> OBJECT_SECURITY_INFORMATION {
        DACL_SECURITY_INFORMATION
    }
}

impl ACLKind for SACL {
    #[inline(always)]
    fn parse_ace<'r>(hdr: &'r ACE_HEADER) -> Result<ACE<'r, Self>> {
        parse_sacl_ace(hdr)
    }

    #[inline(always)]
    fn write_ace<'r>(acl: *mut _ACL, entry: &ACE<'r, Self>) -> Result<()> {
        write_sacl_ace(acl, entry)
    }

    #[inline(always)]
    fn get_security_information_bit() -> OBJECT_SECURITY_INFORMATION {
        SACL_SECURITY_INFORMATION
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
