//! Contains helper functions for converting between raw SID and SID string representations.

#![allow(non_snake_case)]

use core::{
    ops::Drop,
    ptr::null_mut,
    fmt,
};
use windows::{
    core::{Result, Error, PWSTR, HRESULT},
    Win32::{
        Foundation::{
            ERROR_SUCCESS, HLOCAL, LocalFree, HANDLE,
        },
        Security::{
            Authorization::{
                SE_OBJECT_TYPE, GetNamedSecurityInfoW, GetSecurityInfo, SetNamedSecurityInfoW, 
                SetSecurityInfo,
            },
            DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION,
            OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
            PSID, SACL_SECURITY_INFORMATION, 
            ACL as _ACL, OBJECT_SECURITY_INFORMATION,
        },
    },
};

use crate::{
    utils::{SystemPrivilege, str_to_wstr, vec_as_pacl, MaybePtr},
    sid::{SIDRef, VSID},
};

#[derive(Debug)]
pub enum SDSource {
    Path(String),
    Handle(HANDLE),
}

/// This structure manages a Windows `SECURITY_DESCRIPTOR` object.
#[derive(Debug)]
pub struct SecurityDescriptor {
    pSecurityDescriptor: PSECURITY_DESCRIPTOR,

    dacl: MaybePtr<*const _ACL, Vec<u8>>,
    sacl: MaybePtr<*const _ACL, Vec<u8>>,
    owner: VSID<'static>,
    group: VSID<'static>,

    owner_changed: bool,
    group_changed: bool,

    include_sacl: bool,
}

impl Default for SecurityDescriptor {
    fn default() -> Self {
        Self {
            pSecurityDescriptor: PSECURITY_DESCRIPTOR(null_mut()),
            dacl: MaybePtr::None,
            sacl: MaybePtr::None,
            owner: VSID::empty(),
            group: VSID::empty(),
            owner_changed: false,
            group_changed: false,
            include_sacl: false,
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
        obj.include_sacl = include_sacl;

        obj.read( source, obj_type )?;

        Ok(obj)
    }

    pub fn read(
        &mut self,
        source: &SDSource,
        obj_type: SE_OBJECT_TYPE,
    ) -> Result<()> {
        let mut flags =
            DACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION;

        if self.include_sacl {
            let _ = SystemPrivilege::acquire("SeSecurityPrivilege")?;
            flags |= SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
        }

        let mut pDacl: *mut _ACL = null_mut();
        let mut pSacl: *mut _ACL = null_mut();
        let mut pOwner = PSID(null_mut());
        let mut pGroup = PSID(null_mut());

        let ret = match *source {
            SDSource::Handle(handle) => unsafe {
                GetSecurityInfo(
                    handle,
                    obj_type,
                    flags,
                    Some(&mut pOwner),
                    Some(&mut pGroup),
                    Some(&mut pDacl),
                    if self.include_sacl { Some(&mut pSacl) } else { None },
                    Some(&mut self.pSecurityDescriptor),
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
                        Some(&mut pOwner),
                        Some(&mut pGroup),
                        Some(&mut pDacl),
                        if self.include_sacl { Some(&mut pSacl) } else { None },
                        &mut self.pSecurityDescriptor,
                    )
                }
            }
        };

        if ret != ERROR_SUCCESS {
            let err = Error::from_hresult(HRESULT::from_win32(ret.0));
            return Err(err);
        }
        
        self.dacl = if !pDacl.is_null() { MaybePtr::Ptr(pDacl) } else { MaybePtr::None };
        self.sacl = if !pSacl.is_null() { MaybePtr::Ptr(pSacl) } else { MaybePtr::None };
        self.owner = unsafe { VSID::from_psid_or_empty(pOwner) };
        self.group = unsafe { VSID::from_psid_or_empty(pOwner) };

        self.owner_changed = false;
        self.group_changed = false;

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
        let mut dacl = None;
        let mut sacl = None;
        let mut owner = None;
        let mut group = None;

        let mut flags = OBJECT_SECURITY_INFORMATION(0);

        if let MaybePtr::Value(dacl_value) = &self.dacl {
            flags |= DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
            dacl = Some(vec_as_pacl(dacl_value));
        }

        if let MaybePtr::Value(sacl_value) = &self.sacl {
            let _ = SystemPrivilege::acquire("SeSecurityPrivilege")?;
            flags |= SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
            sacl = Some(vec_as_pacl(sacl_value));
        }

        if self.owner_changed {
            flags |= OWNER_SECURITY_INFORMATION;
            let psid = self.owner.psid().ok_or_else(|| Error::empty())?;
            owner = Some(psid);
        }

        if self.group_changed {
            flags |= GROUP_SECURITY_INFORMATION;
            let psid = self.group.psid().ok_or_else(|| Error::empty())?;
            group = Some(psid);
        }

        let ret = match *source {
            SDSource::Handle(handle) => unsafe {
                SetSecurityInfo(
                    handle,
                    obj_type,
                    flags,
                    owner,
                    group,
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
                        owner,
                        group,
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

        self.read(source, obj_type)?;

        Ok(())
    }

    pub fn dacl( &self ) -> Option<*const _ACL> {
        match &self.dacl {
            MaybePtr::None => {
                None
            },
            MaybePtr::Ptr(p) => {
                Some(*p)
            },
            MaybePtr::Value(v) => {
                Some(vec_as_pacl(v))
            }
        }
    }

    pub fn sacl( &self ) -> Option<*const _ACL> {
        match &self.sacl {
            MaybePtr::None => {
                None
            },
            MaybePtr::Ptr(p) => {
                Some(*p)
            },
            MaybePtr::Value(v) => {
                Some(vec_as_pacl(v))
            }
        }
    }

    pub fn owner<'s>( &'s self ) -> &VSID<'s> {
        &self.owner
    }

    pub fn group<'s>( &'s self ) -> &VSID<'s> {
        &self.group
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
    pub fn set_dacl(&mut self, dacl: Vec<u8>) -> Result<()> {
        self.dacl = MaybePtr::Value(dacl);
        Ok(())
    }

    pub fn set_sacl(&mut self, sacl: Vec<u8>) -> Result<()> {
        self.sacl = MaybePtr::Value(sacl);
        Ok(())
    }

    pub fn set_owner<'s>(&mut self, owner: SIDRef<'s>) -> Result<()> {
        self.owner = owner.to_owned_vsid()?;
        self.owner_changed = true;
        Ok(())
    }

    pub fn set_group<'s>(&mut self, group: SIDRef<'s>) -> Result<()> {
        self.group = group.to_owned_vsid()?;
        self.group_changed = true;
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

impl fmt::Debug for MaybePtr<*const _ACL, Vec<u8>> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_tuple("ACL");
        let f = match self {
            MaybePtr::None => {
                f.field(&"None")
            },
            MaybePtr::Ptr(p) => {
                f.field(p)
            },
            MaybePtr::Value(v) => {
                f.field(v)
            }
        };
        f.finish()
    }
}

