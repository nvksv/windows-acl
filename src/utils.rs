//! Contains helper functions for converting between raw SID and SID string representations.

#![allow(non_snake_case)]

use std::{
    ffi::{c_void, OsStr},
    iter::once,
    mem,
    ops::Drop,
    os::windows::ffi::OsStrExt,
    ptr::{null, null_mut},
};
use windows::{
    core::{Result, Error, PWSTR, HRESULT},
    Win32::{
        Foundation::{
            ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS,
            HLOCAL, LocalFree,
            CloseHandle, INVALID_HANDLE_VALUE, HANDLE,
        },
        System::{
            Threading::{
                GetCurrentProcess, OpenProcessToken,
            },
            WindowsProgramming::{
                GetUserNameW,
            },
        },
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSidToSidW,
                SE_OBJECT_TYPE, GetNamedSecurityInfoW, GetSecurityInfo, SetNamedSecurityInfoW, 
                SetSecurityInfo,
            },
            AdjustTokenPrivileges, CopySid, GetLengthSid, LookupAccountNameW, LookupPrivilegeValueW,
            DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION,
            OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
            PSID, SACL_SECURITY_INFORMATION, SE_PRIVILEGE_ENABLED, SID_NAME_USE,
            TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_PRIVILEGES_ATTRIBUTES,
            ACL as _ACL, OBJECT_SECURITY_INFORMATION,
        },
    },
};

#[inline(always)]
pub(crate) fn as_pvoid_mut<T>( r: &mut T ) -> *mut c_void {
    r as *mut _ as *mut c_void
}

#[inline(always)]
pub(crate) fn as_ppvoid_mut<T>( r: &mut T ) -> *mut *mut c_void {
    r as *mut _ as *mut *mut c_void
}

#[inline(always)]
pub(crate) fn vec_as_psid( sid: &Vec<u8> ) -> PSID {
    PSID(sid.as_ptr() as *mut c_void)
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

/// Retrieves the user name of the current user.
pub fn current_user() -> Result<String> {
    let mut username_size: u32 = 0;

    unsafe { GetUserNameW(None, &mut username_size) }?;

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

