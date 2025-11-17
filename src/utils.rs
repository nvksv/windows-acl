//! Contains helper functions for converting between raw SID and SID string representations.

#![allow(non_snake_case)]

use ::widestring::{U16CStr, U16Str};
use core::fmt;
use std::{
    ffi::{c_void},
    fmt::Debug,
    marker::PhantomData,
    mem,
};
use windows::Win32::{
    
    Security::{
        PSID, 
        AclSizeInformation, AddAccessAllowedAceEx, AddAccessDeniedAceEx, 
        AddAuditAccessAceEx, AddMandatoryAce,
        GetAclInformation, IsValidAcl, ACCESS_ALLOWED_ACE,
        ACCESS_ALLOWED_CALLBACK_ACE, ACCESS_ALLOWED_CALLBACK_OBJECT_ACE, ACCESS_ALLOWED_OBJECT_ACE,
        ACCESS_DENIED_ACE, ACCESS_DENIED_CALLBACK_ACE, ACCESS_DENIED_CALLBACK_OBJECT_ACE,
        ACCESS_DENIED_OBJECT_ACE, ACE_FLAGS, ACE_HEADER, ACL_REVISION_DS, ACL_SIZE_INFORMATION,
        SYSTEM_AUDIT_ACE, SYSTEM_AUDIT_CALLBACK_ACE,
        SYSTEM_AUDIT_CALLBACK_OBJECT_ACE, SYSTEM_AUDIT_OBJECT_ACE, SYSTEM_MANDATORY_LABEL_ACE,
        SYSTEM_RESOURCE_ATTRIBUTE_ACE,
    },
    System::SystemServices::{
        ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, SYSTEM_AUDIT_ACE_TYPE, 
        SYSTEM_MANDATORY_LABEL_ACE_TYPE,
    },
};
use windows::{
    core::{Error, Result, PCWSTR, PWSTR},
    Win32::{
        Security::{
            ACL as _ACL,
        },
        System::{
            WindowsProgramming::GetUserNameW,
        },
    },
};

use crate::{
    ace::ACE,
    acl_kind::{DACL, SACL},
    types::{AceType, ACCESS_MASK},
    winapi::{api::ErrorExt, sid::VSID},
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub enum MaybePtr<P, V> {
    None,
    Ptr(P),
    Value(V),
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub enum MaybeSet<NS, S> {
    NotSet(NS),
    Set(S),
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#[inline(always)]
pub(crate) fn as_pvoid_mut<T>(r: &mut T) -> *mut c_void {
    r as *mut _ as *mut c_void
}

#[inline(always)]
pub(crate) fn as_ppvoid_mut<T>(r: &mut T) -> *mut *mut c_void {
    r as *mut _ as *mut *mut c_void
}

#[inline(always)]
pub(crate) fn vec_as_pacl(sid: &Vec<u8>) -> *const _ACL {
    sid.as_ptr() as *const _ACL
}

#[inline(always)]
pub(crate) fn vec_as_pacl_mut(sid: &mut Vec<u8>) -> *mut _ACL {
    sid.as_mut_ptr() as *mut _ACL
}

// #[inline(always)]
// pub(crate) fn as_ppvoid_mut<T>( r: &mut T ) -> *mut *mut c_void {
//     r as *mut _ as *mut *mut c_void
// }

#[inline(always)]
pub(crate) fn u16cstr_as_pcwstr(s: &U16CStr) -> PCWSTR {
    PCWSTR::from_raw(s.as_ptr())
}

#[inline(always)]
pub(crate) fn u16str_as_pwstr(s: &U16Str) -> PWSTR {
    PWSTR::from_raw(s.as_ptr() as *mut u16)
}

#[inline(always)]
pub(crate) fn pwstr_as_u16str(s: PWSTR) -> *const U16Str {
    let s = unsafe { s.as_wide() };
    U16Str::from_slice(s)
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/// Retrieves the user name of the current user.
pub fn current_user_account_name() -> Result<String> {
    let mut username_size: u32 = 0;

    match unsafe { GetUserNameW(None, &mut username_size) } {
        Ok(()) => {
            return Err(Error::empty());
        }
        Err(e) if e.is_insufficient_buffer() => {}
        Err(e) => {
            return Err(e);
        }
    };

    let mut username: Vec<u16> = Vec::with_capacity(username_size as usize);
    let username = PWSTR(username.as_mut_ptr() as *mut u16);

    unsafe { GetUserNameW(Some(username), &mut username_size) }?;

    unsafe { username.to_string() }.map_err(|_| Error::empty())
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub fn acl_size(pacl: *const _ACL) -> Result<u32> {
    if pacl.is_null() {
        return Ok(mem::size_of::<_ACL>() as u32);
    }

    let mut si: ACL_SIZE_INFORMATION = unsafe { mem::zeroed::<ACL_SIZE_INFORMATION>() };

    if !unsafe { IsValidAcl(pacl) }.as_bool() {
        return Err(Error::empty());
    }

    unsafe {
        GetAclInformation(
            pacl,
            as_pvoid_mut(&mut si),
            mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    }?;

    Ok(si.AclBytesInUse)
}

pub fn acl_entry_size(entry_type: AceType) -> Result<u32> {
    match entry_type {
        AceType::AccessAllow => Ok(mem::size_of::<ACCESS_ALLOWED_ACE>() as u32),
        AceType::AccessAllowCallback => Ok(mem::size_of::<ACCESS_ALLOWED_CALLBACK_ACE>() as u32),
        AceType::AccessAllowObject => Ok(mem::size_of::<ACCESS_ALLOWED_OBJECT_ACE>() as u32),
        AceType::AccessAllowCallbackObject => {
            Ok(mem::size_of::<ACCESS_ALLOWED_CALLBACK_OBJECT_ACE>() as u32)
        }
        AceType::AccessDeny => Ok(mem::size_of::<ACCESS_DENIED_ACE>() as u32),
        AceType::AccessDenyCallback => Ok(mem::size_of::<ACCESS_DENIED_CALLBACK_ACE>() as u32),
        AceType::AccessDenyObject => Ok(mem::size_of::<ACCESS_DENIED_OBJECT_ACE>() as u32),
        AceType::AccessDenyCallbackObject => {
            Ok(mem::size_of::<ACCESS_DENIED_CALLBACK_OBJECT_ACE>() as u32)
        }
        AceType::SystemAudit => Ok(mem::size_of::<SYSTEM_AUDIT_ACE>() as u32),
        AceType::SystemAuditCallback => Ok(mem::size_of::<SYSTEM_AUDIT_CALLBACK_ACE>() as u32),
        AceType::SystemAuditObject => Ok(mem::size_of::<SYSTEM_AUDIT_OBJECT_ACE>() as u32),
        AceType::SystemAuditCallbackObject => {
            Ok(mem::size_of::<SYSTEM_AUDIT_CALLBACK_OBJECT_ACE>() as u32)
        }
        AceType::SystemMandatoryLabel => Ok(mem::size_of::<SYSTEM_MANDATORY_LABEL_ACE>() as u32),
        AceType::SystemResourceAttribute => {
            Ok(mem::size_of::<SYSTEM_RESOURCE_ATTRIBUTE_ACE>() as u32)
        }
        _ => Err(Error::empty()),
    }
}

macro_rules! parse_entry {
    ($entry: ident, $typ: path, $ptr: ident => $cls: path) => {{
        let sid_offset = mem::offset_of!($cls, SidStart);

        let entry_ptr: *const $cls = $ptr as *const ACE_HEADER as *const $cls;
        let pSid: PSID = PSID(entry_ptr.wrapping_byte_add(sid_offset) as *mut _);

        let entry_ptr: &$cls = unsafe { &*entry_ptr };

        ACE {
            entry_type: $typ,
            sid: unsafe { VSID::from_psid(pSid) }?,
            flags: ACE_FLAGS($ptr.AceFlags as u32),
            access_mask: ACCESS_MASK(entry_ptr.Mask),
            _ph: PhantomData,
        }
    }};
}

pub fn parse_dacl_ace<'r>(hdr: &'r ACE_HEADER) -> Result<ACE<'r, DACL>> {
    let entry = match hdr.AceType as u32 {
        ACCESS_ALLOWED_ACE_TYPE => {
            parse_entry!(
                entry,
                AceType::AccessAllow,
                hdr => ACCESS_ALLOWED_ACE
            )
        }
        // ACCESS_ALLOWED_CALLBACK_ACE_TYPE => {
        //     process_entry!(
        //         entry,
        //         AceType::AccessAllowCallback,
        //         hdr => ACCESS_ALLOWED_CALLBACK_ACE
        //     )
        // },
        // ACCESS_ALLOWED_OBJECT_ACE_TYPE => {
        //     process_entry!(
        //         entry,
        //         AceType::AccessAllowObject,
        //         hdr => ACCESS_ALLOWED_OBJECT_ACE
        //     )
        // },
        // ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE => {
        //     process_entry!(
        //         entry,
        //         AceType::AccessAllowCallbackObject,
        //         hdr => ACCESS_ALLOWED_CALLBACK_OBJECT_ACE
        //     )
        // },
        ACCESS_DENIED_ACE_TYPE => {
            parse_entry!(
                entry,
                AceType::AccessDeny,
                hdr => ACCESS_DENIED_ACE
            )
        }
        // ACCESS_DENIED_CALLBACK_ACE_TYPE => {
        //     process_entry!(
        //         entry,
        //         AceType::AccessDenyCallback,
        //         hdr => ACCESS_DENIED_CALLBACK_ACE
        //     )
        // },
        // ACCESS_DENIED_OBJECT_ACE_TYPE => {
        //     process_entry!(
        //         entry,
        //         AceType::AccessDenyObject,
        //         hdr => ACCESS_DENIED_OBJECT_ACE
        //     )
        // },
        // ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE => {
        //     process_entry!(
        //         entry,
        //         AceType::AccessDenyCallbackObject,
        //         hdr => ACCESS_DENIED_CALLBACK_OBJECT_ACE
        //     )
        // },
        _ => {
            return Err(Error::empty());
        }
    };

    Ok(entry)
}

pub fn parse_sacl_ace<'r>(hdr: &'r ACE_HEADER) -> Result<ACE<'r, SACL>> {
    let entry = match hdr.AceType as u32 {
        SYSTEM_AUDIT_ACE_TYPE => {
            parse_entry!(
                entry,
                AceType::SystemAudit,
                hdr => SYSTEM_AUDIT_ACE
            )
        }
        // SYSTEM_AUDIT_CALLBACK_ACE_TYPE => {
        //     process_entry!(
        //         entry,
        //         AceType::SystemAuditCallback,
        //         hdr => SYSTEM_AUDIT_CALLBACK_ACE
        //     )
        // },
        // SYSTEM_AUDIT_OBJECT_ACE_TYPE => {
        //     process_entry!(
        //         entry,
        //         AceType::SystemAuditObject,
        //         hdr => SYSTEM_AUDIT_OBJECT_ACE
        //     )
        // },
        // SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE => {
        //     process_entry!(
        //         entry,
        //         AceType::SystemAuditCallbackObject,
        //         hdr => SYSTEM_AUDIT_CALLBACK_OBJECT_ACE
        //     )
        // },
        SYSTEM_MANDATORY_LABEL_ACE_TYPE => {
            parse_entry!(
                entry,
                AceType::SystemMandatoryLabel,
                hdr => SYSTEM_MANDATORY_LABEL_ACE
            )
        }
        // SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE => {
        //     parse_entry!(
        //         entry,
        //         AceType::SystemResourceAttribute,
        //         hdr => SYSTEM_RESOURCE_ATTRIBUTE_ACE
        //     )
        // },
        _ => {
            return Err(Error::empty());
        }
    };

    Ok(entry)
}

pub fn write_dacl_ace<'r>(pacl: *mut _ACL, entry: &ACE<'r, DACL>) -> Result<()> {
    let psid = entry.psid().ok_or_else(|| Error::empty())?;

    match entry.entry_type {
        AceType::AccessAllow => {
            unsafe {
                AddAccessAllowedAceEx(
                    pacl,
                    ACL_REVISION_DS,
                    entry.flags,
                    entry.access_mask.0,
                    psid,
                )
            }?;
        }
        AceType::AccessDeny => {
            unsafe {
                AddAccessDeniedAceEx(
                    pacl,
                    ACL_REVISION_DS,
                    entry.flags,
                    entry.access_mask.0,
                    psid,
                )
            }?;
        }
        _ => {
            return Err(Error::empty());
        }
    }

    Ok(())
}

pub fn write_sacl_ace<'r>(pacl: *mut _ACL, entry: &ACE<'r, SACL>) -> Result<()> {
    let psid = entry.psid().ok_or_else(|| Error::empty())?;

    match entry.entry_type {
        AceType::SystemAudit => {
            unsafe {
                AddAuditAccessAceEx(
                    pacl,
                    ACL_REVISION_DS,
                    entry.flags,
                    entry.access_mask.0,
                    psid,
                    false,
                    false,
                )
            }?;
        }
        AceType::SystemMandatoryLabel => {
            unsafe {
                AddMandatoryAce(
                    pacl,
                    ACL_REVISION_DS,
                    entry.flags,
                    entry.access_mask.0,
                    psid,
                )
            }?;
        }
        // AceType::SystemMandatoryLabel => {
        //     unsafe {
        //         AddResourceAttributeAce(
        //             pacl,
        //             ACL_REVISION_DS,
        //             entry.flags,
        //             entry.access_mask.0,
        //             psid,
        //         )
        //     }?;
        // },
        _ => {
            return Err(Error::empty());
        }
    }

    Ok(())
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#[repr(transparent)]
pub struct DebugIdent(pub &'static str);

impl fmt::Debug for DebugIdent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#[repr(transparent)]
pub struct DebugUnpretty<T: Debug>(pub T);

impl<T: Debug> fmt::Debug for DebugUnpretty<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{:?}", &self.0))
    }
}
