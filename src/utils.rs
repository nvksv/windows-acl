//! Contains helper functions for converting between raw SID and SID string representations.

#![allow(non_snake_case)]

use core::fmt;
use std::{
    ffi::{c_void, OsStr},
    iter::once,
    mem,
    ops::Drop,
    os::windows::ffi::OsStrExt,
};
use windows::{
    core::{
        Error, Result, HRESULT, PWSTR
    },
    Win32::{
        Foundation::{
            CloseHandle, ERROR_INSUFFICIENT_BUFFER, HANDLE, INVALID_HANDLE_VALUE
        }, Security::{
            AddResourceAttributeAce, AdjustTokenPrivileges, LookupPrivilegeValueW, ACL as _ACL, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_PRIVILEGES_ATTRIBUTES, TOKEN_QUERY 
        }, System::{
            Threading::{
                GetCurrentProcess, OpenProcessToken,
            },
            WindowsProgramming::GetUserNameW,
        }
    },
};
use windows::{
    Win32::{
        Security::{
            Authorization::{
                SE_FILE_OBJECT, SE_KERNEL_OBJECT, SE_OBJECT_TYPE,
                SE_REGISTRY_KEY, SE_REGISTRY_WOW64_32KEY,
            },
            AddAccessAllowedAceEx, AddAccessDeniedAceEx, AddAce, AddAuditAccessAceEx, AddMandatoryAce,
            GetAce, GetAclInformation, InitializeAcl, IsValidAcl,
            AclSizeInformation, ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_CALLBACK_ACE,
            ACCESS_ALLOWED_CALLBACK_OBJECT_ACE, ACCESS_ALLOWED_OBJECT_ACE, ACCESS_DENIED_ACE,
            ACCESS_DENIED_CALLBACK_ACE, ACCESS_DENIED_CALLBACK_OBJECT_ACE, ACCESS_DENIED_OBJECT_ACE,
            ACL_REVISION_DS, ACL_SIZE_INFORMATION, CONTAINER_INHERIT_ACE,
            FAILED_ACCESS_ACE_FLAG, INHERITED_ACE, OBJECT_INHERIT_ACE, PSID, 
            SUCCESSFUL_ACCESS_ACE_FLAG, SYSTEM_AUDIT_ACE, SYSTEM_AUDIT_CALLBACK_ACE,
            SYSTEM_AUDIT_CALLBACK_OBJECT_ACE, SYSTEM_AUDIT_OBJECT_ACE,
            SYSTEM_MANDATORY_LABEL_ACE, SYSTEM_RESOURCE_ATTRIBUTE_ACE, ACE_HEADER, ACE_FLAGS,
        },
        System::SystemServices::{
            ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, 
            ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, ACCESS_DENIED_CALLBACK_ACE_TYPE, 
            ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_DENIED_OBJECT_ACE_TYPE, MAXDWORD, 
            SYSTEM_AUDIT_ACE_TYPE, SYSTEM_AUDIT_CALLBACK_ACE_TYPE, SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE, 
            SYSTEM_AUDIT_OBJECT_ACE_TYPE, SYSTEM_MANDATORY_LABEL_ACE_TYPE, SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE,
        },
        Storage::FileSystem::{
            // FILE_ACCESS_RIGHTS,
        }
    },
};

use crate::{
    acl::{DACL, SACL},
    acl_entry::ACLEntry,
    sid::VSID,
    types::{AceType, ACCESS_MASK}, ACLKind,
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub enum MaybePtr<P, V> {
    None,
    Ptr(P),
    Value(V),
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#[inline(always)]
pub(crate) fn as_pvoid_mut<T>( r: &mut T ) -> *mut c_void {
    r as *mut _ as *mut c_void
}

#[inline(always)]
pub(crate) fn as_ppvoid_mut<T>( r: &mut T ) -> *mut *mut c_void {
    r as *mut _ as *mut *mut c_void
}

#[inline(always)]
pub(crate) fn vec_as_pacl( sid: &Vec<u8> ) -> *const _ACL {
    sid.as_ptr() as *const _ACL
}

#[inline(always)]
pub(crate) fn vec_as_pacl_mut( sid: &mut Vec<u8> ) -> *mut _ACL {
    sid.as_mut_ptr() as *mut _ACL
}

#[inline(always)]
pub(crate) fn str_to_wstr( r: &str ) -> Vec<u16> {
    OsStr::new(r).encode_wide().chain(once(0)).collect()
}

// #[inline(always)]
// pub(crate) fn as_ppvoid_mut<T>( r: &mut T ) -> *mut *mut c_void {
//     r as *mut _ as *mut *mut c_void
// }

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/// Retrieves the user name of the current user.
pub fn current_user_account_name() -> Result<String> {
    let mut username_size: u32 = 0;

    match unsafe { 
        GetUserNameW(
            None, 
            &mut username_size
        ) 
    } {
        Ok(()) => {
            return Err(Error::empty());
        },
        Err(e) if e.code() != HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0) => {
            return Err(e);
        },
        Err(_) => {}
    };

    let mut username: Vec<u16> = Vec::with_capacity(username_size as usize);
    let username = PWSTR(username.as_mut_ptr() as *mut u16);

    unsafe { 
        GetUserNameW(
            Some(username),
            &mut username_size
        )
    }?;

    unsafe { username.to_string() }.map_err(|_| Error::empty())
}

fn set_privilege(name: &str, is_enabled: bool) -> Result<bool> {
    let mut tkp = unsafe { mem::zeroed::<TOKEN_PRIVILEGES>() };
    
    let mut wPrivilegeName: Vec<u16> = str_to_wstr(name);
    let wPrivilegeName = PWSTR(wPrivilegeName.as_mut_ptr() as *mut u16);

    unsafe {
        LookupPrivilegeValueW(
            PWSTR::null(),
            wPrivilegeName,
            &mut tkp.Privileges[0].Luid,
        )
    }?;

    tkp.PrivilegeCount = 1;

    if is_enabled {
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    } else {
        tkp.Privileges[0].Attributes = TOKEN_PRIVILEGES_ATTRIBUTES(0);
    }

    let mut hToken: HANDLE = INVALID_HANDLE_VALUE;
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut hToken,
        )
    }?;

    match unsafe {
        AdjustTokenPrivileges(
            hToken,
            false,
            Some(&mut tkp),
            0,
            None,
            None,
        )
    } {
        Ok(()) => {
            unsafe { CloseHandle(hToken) }?;
        },
        Err(e) => {
            let _ = unsafe { CloseHandle(hToken) };
            return Err(e);
        }
    };

    Ok(is_enabled)
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct SystemPrivilege {
    name: Option<String>,
}

impl SystemPrivilege {
    pub fn acquire(name: &str) -> Result<SystemPrivilege> {
        set_privilege(name, true).map(|_| SystemPrivilege {
            name: Some(name.to_owned()),
        })
    }

    pub fn release(&mut self) -> bool {
        let mut status = true;
        if let Some(ref name) = self.name {
            status = set_privilege(name, false).is_ok();
        }

        self.name = None;
        status
    }
}

impl Drop for SystemPrivilege {
    fn drop(&mut self) {
        self.release();
    }
}

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
        AceType::AccessAllow => {
            Ok(mem::size_of::<ACCESS_ALLOWED_ACE>() as u32)
        },
        AceType::AccessAllowCallback => {
            Ok(mem::size_of::<ACCESS_ALLOWED_CALLBACK_ACE>() as u32)
        }
        AceType::AccessAllowObject => {
            Ok(mem::size_of::<ACCESS_ALLOWED_OBJECT_ACE>() as u32)
        },
        AceType::AccessAllowCallbackObject => {
            Ok(mem::size_of::<ACCESS_ALLOWED_CALLBACK_OBJECT_ACE>() as u32)
        }
        AceType::AccessDeny => {
            Ok(mem::size_of::<ACCESS_DENIED_ACE>() as u32)
        },
        AceType::AccessDenyCallback => {
            Ok(mem::size_of::<ACCESS_DENIED_CALLBACK_ACE>() as u32)
        },
        AceType::AccessDenyObject => {
            Ok(mem::size_of::<ACCESS_DENIED_OBJECT_ACE>() as u32)
        },
        AceType::AccessDenyCallbackObject => {
            Ok(mem::size_of::<ACCESS_DENIED_CALLBACK_OBJECT_ACE>() as u32)
        }
        AceType::SystemAudit => {
            Ok(mem::size_of::<SYSTEM_AUDIT_ACE>() as u32)
        },
        AceType::SystemAuditCallback => {
            Ok(mem::size_of::<SYSTEM_AUDIT_CALLBACK_ACE>() as u32)
        },
        AceType::SystemAuditObject => {
            Ok(mem::size_of::<SYSTEM_AUDIT_OBJECT_ACE>() as u32)
        },
        AceType::SystemAuditCallbackObject => {
            Ok(mem::size_of::<SYSTEM_AUDIT_CALLBACK_OBJECT_ACE>() as u32)
        }
        AceType::SystemMandatoryLabel => {
            Ok(mem::size_of::<SYSTEM_MANDATORY_LABEL_ACE>() as u32)
        }
        AceType::SystemResourceAttribute => {
            Ok(mem::size_of::<SYSTEM_RESOURCE_ATTRIBUTE_ACE>() as u32)
        }
        _ => {
            Err(Error::empty())
        },
    }
}

macro_rules! parse_entry {
    ($entry: ident, $typ: path, $ptr: ident => $cls: path) => {
        {
            let sid_offset = mem::offset_of!($cls, SidStart);

            let entry_ptr: *const $cls = $ptr as *const ACE_HEADER as *const $cls;
            let pSid: PSID = PSID(entry_ptr.wrapping_byte_add(sid_offset) as *mut _);

            let entry_ptr: &$cls = unsafe { &* entry_ptr };

            $entry.entry_type = $typ;
            $entry.access_mask = ACCESS_MASK(entry_ptr.Mask);
            $entry.flags = ACE_FLAGS($ptr.AceFlags as u32);
            $entry.sid = unsafe{ VSID::from_psid(pSid) }?;
        }
    };
}

pub fn parse_dacl_ace<'r>( hdr: &'r ACE_HEADER ) -> Result<ACLEntry<'r, DACL>> {
    let mut entry = ACLEntry::new();

    match hdr.AceType as u32 {
        ACCESS_ALLOWED_ACE_TYPE => {
            parse_entry!(
                entry,
                AceType::AccessAllow,
                hdr => ACCESS_ALLOWED_ACE
            )
        },
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
        },
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
    }

    Ok(entry)
}

pub fn parse_sacl_ace<'r>( hdr: &'r ACE_HEADER ) -> Result<ACLEntry<'r, SACL>> {
    let mut entry = ACLEntry::new();

    match hdr.AceType as u32 {
        SYSTEM_AUDIT_ACE_TYPE => {
            parse_entry!(
                entry,
                AceType::SystemAudit,
                hdr => SYSTEM_AUDIT_ACE
            )
        },
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
        },
        SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE => {
            parse_entry!(
                entry,
                AceType::SystemResourceAttribute,
                hdr => SYSTEM_RESOURCE_ATTRIBUTE_ACE
            )
        },
        _ => {
            return Err(Error::empty());
        }
    }

    Ok(entry)
}

pub fn write_dacl_ace<'r>( pacl: *const _ACL, entry: &ACLEntry<'r, DACL> ) -> Result<()> {
    match entry.entry_type {
        AceType::AccessAllow => {
            unsafe {
                AddAccessAllowedAceEx(
                    pacl,
                    ACL_REVISION_DS,
                    entry.flags,
                    entry.access_mask.0,
                    entry.psid(),
                )
            }?;
        },
        AceType::AccessDeny => {
            unsafe {
                AddAccessDeniedAceEx(
                    pacl,
                    ACL_REVISION_DS,
                    entry.flags,
                    entry.access_mask.0,
                    entry.psid(),
                )
            }?;
        },
        _ => {
            return Err(Error::empty());
        },
    }

    Ok(())
}

pub fn write_sacl_ace<'r>( pacl: *const _ACL, entry: &ACLEntry<'r, SACL> ) -> Result<()> {
    match entry.entry_type {
        AceType::SystemAudit => {
            unsafe {
                AddAuditAccessAceEx(
                    pacl,
                    ACL_REVISION_DS,
                    entry.flags,
                    entry.access_mask.0,
                    entry.psid(),
                    false,
                    false,
                )
            }?;
        },
        AceType::SystemMandatoryLabel => {
            unsafe {
                AddMandatoryAce(
                    pacl,
                    ACL_REVISION_DS,
                    entry.flags,
                    entry.access_mask.0,
                    entry.psid(),
                )
            }?;
        },
        AceType::SystemMandatoryLabel => {
            unsafe {
                AddResourceAttributeAce(
                    pacl,
                    ACL_REVISION_DS,
                    entry.flags,
                    entry.access_mask.0,
                    entry.psid(),
                )
            }?;
        },
        _ => {
            return Err(Error::empty());
        },
    }

    Ok(())
}