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
            ACL as _ACL, OBJECT_SECURITY_INFORMATION, SetSecurityDescriptorDacl,
            SetSecurityDescriptorSacl, SetSecurityDescriptorOwner, SetSecurityDescriptorGroup,
        },
    },
};

use crate::utils::{SystemPrivilege, str_to_wstr};

#[derive(Debug)]
pub enum SDSource {
    Path(String),
    Handle(HANDLE),
}

/// This structure manages a Windows `SECURITY_DESCRIPTOR` object.
#[derive(Debug)]
pub struct SecurityDescriptor {
    pSecurityDescriptor: PSECURITY_DESCRIPTOR,

    /// Pointer to the discretionary access control list in the security descriptor
    pDacl: Option<*mut _ACL>,

    /// Pointer to the system access control list in the security descriptor
    pSacl: Option<*mut _ACL>,

    pOwner: Option<PSID>,
    pGroup: Option<PSID>,

    dacl_changed: bool,
    sacl_changed: bool,
    owner_changed: bool,
    group_changed: bool,
}

impl Default for SecurityDescriptor {
    fn default() -> Self {
        Self {
            pSecurityDescriptor: PSECURITY_DESCRIPTOR(null_mut()),
            pDacl: None,
            pSacl: None,
            pOwner: None,
            pGroup: None,
            dacl_changed: false,
            sacl_changed: false,
            owner_changed: false,
            group_changed: false,
        }
    }
}

impl SecurityDescriptor {
    /// Returns a `SecurityDescriptor` object for the specified object source.
    ///
    /// # Arguments
    /// * `source` - An object handle or a string containing the named object path.
    /// * `obj_type` - The named object path's type. See [SE_OBJECT_TYPE](https://docs.microsoft.com/en-us/windows/desktop/api/accctrl/ne-accctrl-_se_object_type).
    /// * `include_sacl` - A boolean specifying whether the returned `ACL` object will be able to enumerate and set
    ///                System ACL entries.
    ///
    /// # Errors
    /// On error, a Windows error code is wrapped in an `Err` type
    pub fn from_source(
        source: &SDSource,
        obj_type: SE_OBJECT_TYPE,
        include_sacl: bool,
    ) -> Result<Self> {
        let mut obj = Self::default();

        let mut flags =
            DACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION;

        if include_sacl {
            let _ = SystemPrivilege::acquire("SeSecurityPrivilege")?;
            flags |= SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
        }

        obj.pDacl = Some(null_mut());
        obj.pSacl = if include_sacl { Some(null_mut()) } else { None };
        obj.pOwner = Some(PSID(null_mut()));
        obj.pGroup = Some(PSID(null_mut()));

        let ret = match *source {
            SDSource::Handle(handle) => unsafe {
                GetSecurityInfo(
                    handle,
                    obj_type,
                    flags,
                    obj.pOwner.as_mut().map(|r| r as *mut PSID),
                    obj.pGroup.as_mut().map(|r| r as *mut PSID),
                    obj.pDacl.as_mut().map(|r| r as *mut *mut _ACL),
                    obj.pSacl.as_mut().map(|r| r as *mut *mut _ACL),
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
                        obj.pOwner.as_mut().map(|r| r as *mut PSID),
                        obj.pGroup.as_mut().map(|r| r as *mut PSID),
                        obj.pDacl.as_mut().map(|r| r as *mut *mut _ACL),
                        obj.pSacl.as_mut().map(|r| r as *mut *mut _ACL),
                        &mut obj.pSecurityDescriptor,
                    )
                }
            }
        };

        if ret != ERROR_SUCCESS {
            let err = Error::from_hresult(HRESULT::from_win32(ret.0));
            return Err(err);
        }

        if obj.pDacl == Some(null_mut()) {
            obj.pDacl = None;
        }
        if obj.pSacl == Some(null_mut()) {
            obj.pSacl = None;
        }
        if obj.pOwner == Some(PSID(null_mut())) {
            obj.pOwner = None;
        }
        if obj.pGroup == Some(PSID(null_mut())) {
            obj.pGroup = None;
        }

        Ok(obj)
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
    pub fn write(
        &mut self,
        source: &SDSource,
        obj_type: SE_OBJECT_TYPE,
    ) -> Result<()> {
        let mut flags = OBJECT_SECURITY_INFORMATION(0);

        if self.dacl_changed {
            flags |= DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
        }

        if self.sacl_changed {
            let _ = SystemPrivilege::acquire("SeSecurityPrivilege")?;
            flags |= SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
        }

        let ret = match *source {
            SDSource::Handle(handle) => unsafe {
                SetSecurityInfo(
                    handle,
                    obj_type,
                    flags,
                    if ,
                    None,
                    self.pDacl,
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
