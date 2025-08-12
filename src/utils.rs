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
pub(crate) fn str_to_wstr( r: &str ) -> Vec<u16> {
    OsStr::new(r).encode_wide().chain(once(0)).collect()
}

// #[inline(always)]
// pub(crate) fn as_ppvoid_mut<T>( r: &mut T ) -> *mut *mut c_void {
//     r as *mut _ as *mut *mut c_void
// }

/// Converts a raw SID into a SID string representation.
///
/// # Arguments
/// * `sid` - A pointer to a raw SID buffer. In native Windows, this is would be a `PSID` type.
///
/// # Errors
/// On error, a Windows error code is returned with the `Err` type.
pub unsafe fn sid_to_string(sid: PSID) -> Result<String> {
    let mut raw_string_sid: PWSTR = PWSTR::null();
    unsafe { ConvertSidToStringSidW(sid, &mut raw_string_sid) }?;
    if raw_string_sid.is_null() {
        return Err(Error::empty());
    }

    let string_sid = raw_string_sid.to_string().map_err(|_| Error::empty())?;

    unsafe { LocalFree(Some(HLOCAL(raw_string_sid.as_ptr() as *mut _))) };

    Ok(string_sid)
}

/// Resolves a system username (either in the format of "user" or "DOMAIN\user") into a raw SID. The raw SID
/// is represented by a `Vec<u8>` object.
///
/// # Arguments
/// * `name` - The user name to be resolved into a raw SID.
/// * `system` - An optional string denoting the scope of the user name (such as a machine or domain name). If not required, use `None`.
///
/// # Errors
/// On error, a Windows error code is returned with the `Err` type.
///
/// **Note**: If the error code is 0, `GetLastError()` returned `ERROR_INSUFFICIENT_BUFFER` after invoking `LookupAccountNameW` or
///         the `sid_size` is 0.
pub fn name_to_sid(name: &str, system: Option<&str>) -> Result<Vec<u8>> {
    let mut name: Vec<u16> = str_to_wstr(name);
    let name = PWSTR::from_raw(name.as_mut_ptr());

    let mut system: Option<Vec<u16>> = system.map(|name| str_to_wstr(name));
    let system: PWSTR = system.as_mut()
        .map(|system| PWSTR::from_raw(system.as_mut_ptr()))
        .unwrap_or_else(|| PWSTR::null());

    let mut sid_size: u32 = 0;
    let mut sid_type: SID_NAME_USE = SID_NAME_USE(0);

    let mut domain_name_size: u32 = 0;

    match unsafe { 
        LookupAccountNameW(
            system,
            name,
            None,
            &mut sid_size,
            None,
            &mut domain_name_size,
            &mut sid_type,
        )
    } {
        Ok(()) => {
            return Err(Error::empty());
        },
        Err(e) if e.code() != ERROR_INSUFFICIENT_BUFFER.into() => {
            return Err(e);
        },
        Err(_) => {}
    };

    if sid_size == 0 {
        return Err(Error::empty());
    }

    let mut sid: Vec<u8> = Vec::with_capacity(sid_size as usize);
    let mut domain_name: Vec<u8> = Vec::with_capacity((domain_name_size as usize) * mem::size_of::<u16>());

    unsafe {
        LookupAccountNameW(
            system,
            name,
            Some(PSID(sid.as_mut_ptr() as *mut c_void)),
            &mut sid_size,
            Some(PWSTR::from_raw(domain_name.as_mut_ptr() as *mut u16)),
            &mut domain_name_size,
            &mut sid_type,
        )
    }?;

    unsafe { sid.set_len(sid_size as usize) };

    Ok(sid)
}

/// Converts a string representation of a SID into a raw SID. The returned raw SID is contained in a `Vec<u8>` object.
///
/// # Arguments
/// * `string_sid` - The SID to converted into raw form as a string.
///
/// # Errors
/// On error, a Windows error code is wrapped in an `Err` type.
pub fn string_to_sid(string_sid: &str) -> Result<Vec<u8>> {
    let mut raw_string_sid: Vec<u16> = str_to_wstr(string_sid);
    let raw_string_sid = PWSTR::from_raw(raw_string_sid.as_mut_ptr());

    let mut sid: PSID = PSID(null_mut());
    unsafe { ConvertStringSidToSidW(raw_string_sid, &mut sid) }?;

    let size = unsafe { GetLengthSid(sid) };
    let mut sid_buf: Vec<u8> = Vec::with_capacity(size as usize);

    unsafe { 
        CopySid(
            size, 
            PSID(sid_buf.as_mut_ptr() as *mut c_void), 
            sid
        )
    }?;

    unsafe { sid_buf.set_len(size as usize) };

    Ok(sid_buf)
}

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
pub enum SDSource {
    Path(String),
    Handle(HANDLE),
}

#[derive(Debug)]
struct SystemPrivilege {
    name: Option<String>,
}

impl SystemPrivilege {
    fn acquire(name: &str) -> Result<SystemPrivilege> {
        set_privilege(name, true).map(|_| SystemPrivilege {
            name: Some(name.to_owned()),
        })
    }

    fn release(&mut self) -> bool {
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

/// This structure manages a Windows `SECURITY_DESCRIPTOR` object.
#[derive(Debug)]
pub struct SecurityDescriptor {
    pSecurityDescriptor: PSECURITY_DESCRIPTOR,

    /// Pointer to the discretionary access control list in the security descriptor
    pub pDacl: *mut _ACL,

    /// Pointer to the system access control list in the security descriptor
    pub pSacl: *mut _ACL,

    pub psidOwner: PSID,
    pub psidGroup: PSID,
}

impl SecurityDescriptor {
    /// Returns a `SecurityDescriptor` object for the specified object source.
    ///
    /// # Arguments
    /// * `source` - An object handle or a string containing the named object path.
    /// * `obj_type` - The named object path's type. See [SE_OBJECT_TYPE](https://docs.microsoft.com/en-us/windows/desktop/api/accctrl/ne-accctrl-_se_object_type).
    /// * `get_sacl` - A boolean specifying whether the returned `ACL` object will be able to enumerate and set
    ///                System ACL entries.
    ///
    /// # Errors
    /// On error, a Windows error code is wrapped in an `Err` type
    pub fn from_source(
        source: &SDSource,
        obj_type: SE_OBJECT_TYPE,
        get_sacl: bool,
    ) -> Result<SecurityDescriptor> {
        let mut obj = SecurityDescriptor::default();
        let mut flags =
            DACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION;

        if get_sacl {
            let _ = SystemPrivilege::acquire("SeSecurityPrivilege")?;
            flags |= SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
        }

        let ret = match *source {
            SDSource::Handle(handle) => unsafe {
                GetSecurityInfo(
                    handle,
                    obj_type,
                    flags,
                    Some(&mut obj.psidOwner),
                    Some(&mut obj.psidGroup),
                    Some(&mut obj.pDacl),
                    Some(&mut obj.pSacl),
                    Some(&mut obj.pSecurityDescriptor),
                )
            },
            SDSource::Path(ref path) => {
                let mut wPath: Vec<u16> = str_to_wstr(path);
                let wPath = PWSTR(wPath.as_mut_ptr() as *mut u16);

                unsafe {
                    GetNamedSecurityInfoW(
                        wPath,
                        obj_type,
                        flags,
                        Some(&mut obj.psidOwner),
                        Some(&mut obj.psidGroup),
                        Some(&mut obj.pDacl),
                        Some(&mut obj.pSacl),
                        &mut obj.pSecurityDescriptor,
                    )
                }
            }
        };

        if ret != ERROR_SUCCESS {
            let err = Error::from_hresult(HRESULT::from_win32(ret.0));
            return Err(err);
        }

        if !get_sacl {
            obj.pSacl = null_mut();
        }

        Ok(obj)
    }

    fn default() -> SecurityDescriptor {
        SecurityDescriptor {
            pSecurityDescriptor: PSECURITY_DESCRIPTOR(null_mut()),
            pDacl: null_mut(),
            pSacl: null_mut(),
            psidOwner: PSID(null_mut()),
            psidGroup: PSID(null_mut()),
        }
    }

    /// Commits a provided discretionary and/or system access control list to the specified named object path.
    ///
    /// # Arguments
    /// * `path` - A string containing the named object path.
    /// * `obj_type` - The named object path's type. See [SE_OBJECT_TYPE](https://docs.microsoft.com/en-us/windows/desktop/api/accctrl/ne-accctrl-_se_object_type).
    /// * `dacl` - An optional
    /// * `sacl` - An optional
    ///
    /// # Remarks
    /// This function does not update the `pSacl` or `pDacl` field in the `SecurityDescriptor` object. The `ACL` object tends
    /// to completely reload the `SecurityDescriptor` object after a reload to ensure consistency.
    ///
    /// # Errors
    /// On error, `false` is returned.
    pub fn apply(
        &mut self,
        source: &SDSource,
        obj_type: SE_OBJECT_TYPE,
        mut dacl: Option<*const _ACL>,
        mut sacl: Option<*const _ACL>,
    ) -> Result<()> {
        if dacl == Some(null()) {
            dacl = None;
        }
        if sacl == Some(null()) {
            sacl = None;
        }

        let mut flags = OBJECT_SECURITY_INFORMATION(0);

        if dacl.is_some() {
            flags |= DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
        }

        if sacl.is_some() {
            let _ = SystemPrivilege::acquire("SeSecurityPrivilege")?;
            flags |= SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
        }

        let ret = match *source {
            SDSource::Handle(handle) => unsafe {
                SetSecurityInfo(
                    handle,
                    obj_type,
                    flags,
                    None,
                    None,
                    dacl,
                    sacl,
                )
            },
            SDSource::Path(ref path) => {
                let mut wPath: Vec<u16> = str_to_wstr(path);
                let wPath = PWSTR(wPath.as_mut_ptr() as *mut u16);
                unsafe {
                    SetNamedSecurityInfoW(
                        wPath,
                        obj_type,
                        flags,
                        None,
                        None,
                        dacl,
                        sacl,
                    )
                }
            }
        };

        if ret != ERROR_SUCCESS {
            let err = Error::from_hresult(HRESULT::from_win32(ret.0));
            return Err(err);
        }

        Ok(())
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if self.pSecurityDescriptor.0.is_null() {
            unsafe { LocalFree(Some(HLOCAL(self.pSecurityDescriptor.0 as *mut _) )) };
        }
    }
}
