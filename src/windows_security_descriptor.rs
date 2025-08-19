//! Contains helper functions for converting between raw SID and SID string representations.

#![allow(non_snake_case)]

use core::{
    ops::Drop,
    ptr::{null, null_mut},
    fmt,
    ffi::c_void,
};
use windows::{
    core::{Result, Error, PWSTR, HRESULT, BOOL},
    Win32::{
        Foundation::{
            ERROR_SUCCESS, HLOCAL, LocalFree, HANDLE,
        },
        Security::{
            Authorization::{
                SE_OBJECT_TYPE, GetNamedSecurityInfoW, GetSecurityInfo, SetNamedSecurityInfoW, 
                SetSecurityInfo, INHERITED_FROMW, GetInheritanceSourceW, SE_FILE_OBJECT,
                FreeInheritedFromArray,
            },
            DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION,
            OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
            PSID, SACL_SECURITY_INFORMATION, UNPROTECTED_DACL_SECURITY_INFORMATION, 
            PROTECTED_SACL_SECURITY_INFORMATION, UNPROTECTED_SACL_SECURITY_INFORMATION,
            ACL as _ACL, OBJECT_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetSecurityDescriptorSacl,
            GetSecurityDescriptorOwner, GetSecurityDescriptorGroup, GetSecurityDescriptorControl,
            SE_DACL_PROTECTED, SECURITY_DESCRIPTOR_CONTROL, SE_SACL_PROTECTED, GENERIC_MAPPING,
        },
    },
};

use crate::{
    privilege::SystemPrivilege, 
    sid::{SIDRef, SID, VSID}, 
    utils::{str_to_wstr, vec_as_pacl, DebugIdent, MaybeSet}, 
    acl_kind::ACLKind,
    acl::ACL,
};

#[derive(Debug)]
pub enum SDSource {
    Path(String),
    Handle(HANDLE),
}

/// This structure manages a Windows `SECURITY_DESCRIPTOR` object.
#[derive(Debug)]
pub struct WindowsSecurityDescriptor {
    pSecurityDescriptor: PSECURITY_DESCRIPTOR,

    dacl: MaybeSet<*const _ACL, Option<Vec<u8>>>,
    sacl: MaybeSet<*const _ACL, Option<Vec<u8>>>,
    owner: MaybeSet<PSID, SID>,
    group: MaybeSet<PSID, SID>,

    dacl_is_protected: MaybeSet<bool, bool>,
    sacl_is_protected: MaybeSet<bool, bool>,
}

impl WindowsSecurityDescriptor {
    fn new() -> Self {
        Self {
            pSecurityDescriptor: PSECURITY_DESCRIPTOR(null_mut()),
            dacl: MaybeSet::Unset(null()),
            sacl: MaybeSet::Unset(null()),
            owner: MaybeSet::Unset(PSID(null_mut())),
            group: MaybeSet::Unset(PSID(null_mut())),
            dacl_is_protected: MaybeSet::Unset(false),
            sacl_is_protected: MaybeSet::Unset(false),
        }
    }

    fn free_descriptor( &mut self ) {
        if !self.pSecurityDescriptor.0.is_null() {
            unsafe { LocalFree(Some(HLOCAL(self.pSecurityDescriptor.0 as *mut c_void) )) };
        }

        self.pSecurityDescriptor = PSECURITY_DESCRIPTOR(null_mut());
    }

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
        let mut obj = Self::new();

        obj.read( source, obj_type, include_sacl )?;

        Ok(obj)
    }

    //

    pub fn read(
        &mut self,
        source: &SDSource,
        obj_type: SE_OBJECT_TYPE,
        include_sacl: bool,
    ) -> Result<()> {
        let mut privilege = if include_sacl {
            let mut privilege = SystemPrivilege::by_name("SeSecurityPrivilege")?;
            privilege.acquire()?;

            Some(privilege)
        } else {
            None
        };

        let result = self.read_with_privilege( source, obj_type, include_sacl );

        if let Some(privilege) = privilege.as_mut() {
            privilege.release()?;
        }

        result
    }

    fn read_with_privilege(
        &mut self,
        source: &SDSource,
        obj_type: SE_OBJECT_TYPE,
        include_sacl: bool,
    ) -> Result<()> {
        self.free_descriptor();

        let mut flags =
            DACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION;

        if include_sacl {
            flags |= SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
        };

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
                    if include_sacl { Some(&mut pSacl) } else { None },
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
                        if include_sacl { Some(&mut pSacl) } else { None },
                        &mut self.pSecurityDescriptor,
                    )
                }
            }
        };

        if ret != ERROR_SUCCESS {
            let err = Error::from_hresult(HRESULT::from_win32(ret.0));
            return Err(err);
        }
        
        self.dacl = MaybeSet::Unset(pDacl);
        self.sacl = MaybeSet::Unset(pSacl);
        self.owner = MaybeSet::Unset(pOwner);
        self.group = MaybeSet::Unset(pGroup);

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
        include_sacl: bool,
    ) -> Result<()> {
        let mut privilege = if matches!(&self.sacl, MaybeSet::Set(_)) || matches!(&self.sacl_is_protected, MaybeSet::Set(_)) {
            let mut privilege = SystemPrivilege::by_name("SeSecurityPrivilege")?;
            privilege.acquire()?;

            Some(privilege)
        } else {
            None
        };

        let result = self.write_with_privilege( source, obj_type, include_sacl );

        if let Some(privilege) = privilege.as_mut() {
            privilege.release()?;
        }

        result
    }

    fn write_with_privilege(
        &mut self,
        source: &SDSource,
        obj_type: SE_OBJECT_TYPE,
        include_sacl: bool,
    ) -> Result<()> {
        let mut dacl = None;
        let mut sacl = None;
        let mut owner = None;
        let mut group = None;

        let mut flags = OBJECT_SECURITY_INFORMATION(0);

        //

        if let MaybeSet::Set(dacl_value) = &self.dacl {
            flags |= DACL_SECURITY_INFORMATION;
            match dacl_value.as_ref() {
                Some(dacl_value) => {
                    dacl = Some(vec_as_pacl(dacl_value));
                },
                None => {
                    dacl = Some(null())
                }
            }
        }

        if let MaybeSet::Set(is_protected) = self.dacl_is_protected {
            flags |= if is_protected { PROTECTED_DACL_SECURITY_INFORMATION } else { UNPROTECTED_DACL_SECURITY_INFORMATION };
        }

        if let MaybeSet::Set(sacl_value) = &self.sacl {
            flags |= SACL_SECURITY_INFORMATION;
            match sacl_value.as_ref() {
                Some(sacl_value) => {
                    sacl = Some(vec_as_pacl(sacl_value));
                },
                None => {
                    sacl = Some(null())
                }
            }
        }

        if let MaybeSet::Set(is_protected) = self.sacl_is_protected {
            flags |= if is_protected { PROTECTED_SACL_SECURITY_INFORMATION } else { UNPROTECTED_SACL_SECURITY_INFORMATION };
        }

        if let MaybeSet::Set(owner_value) = &self.owner {
            flags |= OWNER_SECURITY_INFORMATION;
            let psid = owner_value.psid();
            owner = Some(psid);
        }

        if let MaybeSet::Set(group_value) = &self.owner {
            flags |= GROUP_SECURITY_INFORMATION;
            let psid = group_value.psid();
            group = Some(psid);
        }

        //

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

        self.read_with_privilege(source, obj_type, include_sacl)?;

        Ok(())
    }

    pub fn take_ownership<'s>(
        source: &SDSource,
        obj_type: SE_OBJECT_TYPE,
        owner: SIDRef<'s>
    ) -> Result<()> {
        let mut privilege = SystemPrivilege::by_name("SeTakeOwnershipPrivilege")?;
        privilege.acquire()?;

        let result = Self::take_ownership_with_privilege( source, obj_type, owner );

        privilege.release()?;

        result
    }

    fn take_ownership_with_privilege<'s>(
        source: &SDSource,
        obj_type: SE_OBJECT_TYPE,
        owner: SIDRef<'s>
    ) -> Result<()> {
        let flags = OWNER_SECURITY_INFORMATION;

        let ret = match *source {
            SDSource::Handle(handle) => unsafe {
                SetSecurityInfo(
                    handle,
                    obj_type,
                    flags,
                    Some(owner.psid()),
                    None,
                    None,
                    None,
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
                        Some(owner.psid()),
                        None,
                        None,
                        None,
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


    fn read_dacl_from_descriptor( &mut self ) -> Result<()> {
        let mut dacl_present: BOOL = BOOL(0);
        let mut dacl_defaulted: BOOL = BOOL(0);
        let mut pdacl: *mut _ACL = null_mut();
        
        unsafe {
            GetSecurityDescriptorDacl(
                self.pSecurityDescriptor,
                &mut dacl_present,
                &mut pdacl,
                &mut dacl_defaulted,
            )
        }?;

        self.dacl = MaybeSet::Unset(
            if dacl_present.as_bool() { pdacl as *const _ACL } else { null() }
        );

        Ok(())
    }

    fn read_sacl_from_descriptor( &mut self ) -> Result<()> {
        let mut sacl_present: BOOL = BOOL(0);
        let mut sacl_defaulted: BOOL = BOOL(0);
        let mut pdacl: *mut _ACL = null_mut();
        
        unsafe {
            GetSecurityDescriptorSacl(
                self.pSecurityDescriptor,
                &mut sacl_present,
                &mut pdacl,
                &mut sacl_defaulted,
            )
        }?;

        self.sacl = MaybeSet::Unset(
            if sacl_present.as_bool() { pdacl as *const _ACL } else { null() }
        );

        Ok(())
    }

    fn read_owner_from_descriptor( &mut self ) -> Result<()> {
        let mut psid: PSID = PSID(null_mut());
        let mut owner_defaulted: BOOL = BOOL(0);
        
        unsafe {
            GetSecurityDescriptorOwner(
                self.pSecurityDescriptor,
                &mut psid,
                &mut owner_defaulted,
            )
        }?;

        self.owner = MaybeSet::Unset(psid);

        Ok(())
    }

    fn read_group_from_descriptor( &mut self ) -> Result<()> {
        let mut psid: PSID = PSID(null_mut());
        let mut group_defaulted: BOOL = BOOL(0);
        
        unsafe {
            GetSecurityDescriptorGroup(
                self.pSecurityDescriptor,
                &mut psid,
                &mut group_defaulted,
            )
        }?;

        self.group = MaybeSet::Unset(psid);

        Ok(())
    }

    fn read_dacl_is_protected_from_descriptor( &mut self ) -> Result<()> {
        let mut control: u16 = 0;
        let mut revision: u32 = 0;
        
        unsafe {
            GetSecurityDescriptorControl(
                self.pSecurityDescriptor,
                &mut control,
                &mut revision,
            )
        }?;

        self.dacl_is_protected = MaybeSet::Unset(
            SECURITY_DESCRIPTOR_CONTROL(control).contains(SE_DACL_PROTECTED)
        );

        Ok(())
    }

    fn read_sacl_is_protected_from_descriptor( &mut self ) -> Result<()> {
        let mut control: u16 = 0;
        let mut revision: u32 = 0;
        
        unsafe {
            GetSecurityDescriptorControl(
                self.pSecurityDescriptor,
                &mut control,
                &mut revision,
            )
        }?;

        self.sacl_is_protected = MaybeSet::Unset(
            SECURITY_DESCRIPTOR_CONTROL(control).contains(SE_SACL_PROTECTED)
        );

        Ok(())
    }


    //

    pub fn dacl( &self ) -> Option<*const _ACL> {
        match &self.dacl {
            MaybeSet::Unset(p) => {
                if (*p).is_null() {
                    None
                } else {
                    Some(*p)
                }
            },
            MaybeSet::Set(None) => {
                None
            },
            MaybeSet::Set(Some(v)) => {
                Some(vec_as_pacl(v))
            }
        }
    }

    pub fn set_dacl(&mut self, dacl: Vec<u8>) -> Result<()> {
        self.dacl = MaybeSet::Set(Some(dacl));
        Ok(())
    }

    pub fn set_nonexistent_dacl(&mut self) -> Result<()> {
        self.dacl = MaybeSet::Set(None);
        Ok(())
    }

    pub fn unset_dacl(&mut self) -> Result<()> {
        self.read_dacl_from_descriptor()
    }

    //

    pub fn dacl_is_protected( &self ) -> bool {
        match &self.dacl_is_protected {
            MaybeSet::Unset(p) => {
                *p
            },
            MaybeSet::Set(v) => {
                *v
            },
        }
    }

    pub fn set_dacl_is_protected( &mut self, is_protected: bool ) -> Result<()> {
        self.dacl_is_protected = MaybeSet::Set(is_protected);
        Ok(())
    }

    pub fn unset_dacl_is_protected( &mut self ) -> Result<()> {
        self.read_dacl_is_protected_from_descriptor()
    }

    //

    pub fn sacl( &self ) -> Option<*const _ACL> {
        match &self.sacl {
            MaybeSet::Unset(p) => {
                if (*p).is_null() {
                    None
                } else {
                    Some(*p)
                }
            },
            MaybeSet::Set(None) => {
                None
            },
            MaybeSet::Set(Some(v)) => {
                Some(vec_as_pacl(v))
            }
        }
    }

    pub fn set_sacl(&mut self, sacl: Vec<u8>) -> Result<()> {
        self.sacl = MaybeSet::Set(Some(sacl));
        Ok(())
    }

    pub fn set_nonexistent_sacl(&mut self) -> Result<()> {
        self.sacl = MaybeSet::Set(None);
        Ok(())
    }

    pub fn unset_sacl(&mut self) -> Result<()> {
        self.read_sacl_from_descriptor()
    }

    //

    pub fn sacl_is_protected( &self ) -> bool {
        match &self.sacl_is_protected {
            MaybeSet::Unset(p) => {
                *p
            },
            MaybeSet::Set(v) => {
                *v
            },
        }
    }

    pub fn set_sacl_is_protected( &mut self, is_protected: bool ) -> Result<()> {
        self.sacl_is_protected = MaybeSet::Set(is_protected);
        Ok(())
    }

    pub fn unset_sacl_is_protected( &mut self ) -> Result<()> {
        self.read_sacl_is_protected_from_descriptor()
    }

    //

    pub fn owner<'s>( &'s self ) -> Result<Option<SIDRef<'s>>> {
        match &self.owner {
            MaybeSet::Unset(ppsid) => {
                Ok(SIDRef::from_psid(*ppsid)?)
            },
            MaybeSet::Set(sid) => {
                Ok(Some(sid.as_ref()))
            }
        }
    }

    pub fn set_owner<'s>(&mut self, owner: SIDRef<'s>) -> Result<()> {
        self.owner = MaybeSet::Set(owner.to_sid()?);
        Ok(())
    }

    pub fn unset_owner<'s>(&mut self) -> Result<()> {
        self.read_owner_from_descriptor()
    }

    //

    pub fn group<'s, 'r>( &'s self ) -> Result<Option<SIDRef<'s>>> {
        match &self.group {
            MaybeSet::Unset(ppsid) => {
                Ok(SIDRef::from_psid(*ppsid)?)
            },
            MaybeSet::Set(sid) => {
                Ok(Some(sid.as_ref()))
            }
        }
    }

    pub fn set_group<'s>(&mut self, group: SIDRef<'s>) -> Result<()> {
        self.group = MaybeSet::Set(group.to_sid()?);
        Ok(())
    }

    pub fn unset_group<'s>(&mut self) -> Result<()> {
        self.read_group_from_descriptor()
    }

    pub fn get_inheritance_source<'r, K: ACLKind>( 
        &self, 
        source: &SDSource,
        object_type: SE_OBJECT_TYPE,
        pacl: *const _ACL,
    ) -> Result<WindowsInheritedFrom> {
        if pacl.is_null() {
            return Err(Error::empty());
        }
        let SDSource::Path(path) = source else {
            return Err(Error::empty());
        };

        let generic_mapping = GENERIC_MAPPING {
            GenericRead: 0,
            GenericWrite: 0,
            GenericExecute: 0,
            GenericAll: 0,
        };

        let is_container = object_type == SE_FILE_OBJECT;

        let mut wPath: Vec<u16> = str_to_wstr(path);
        let wPath = PWSTR(wPath.as_mut_ptr() as *mut u16);

        let ace_count = unsafe { (*pacl).AceCount };
        let buffer_size = (ace_count as usize) * size_of::<INHERITED_FROMW>();
        let mut buffer = [0_u8].repeat(buffer_size);

        let pInheritArray = buffer.as_mut_ptr() as *mut INHERITED_FROMW;

        let ret = unsafe {
            GetInheritanceSourceW(
                wPath,
                object_type, 
                K::get_security_information_bit(),
                is_container,
                None,
                pacl,
                None, 
                &generic_mapping,
                pInheritArray
            )
        };

        if ret != ERROR_SUCCESS {
            let err = Error::from_hresult(HRESULT::from_win32(ret.0));
            return Err(err);
        }

        Ok(WindowsInheritedFrom {
            ace_count,
            buffer,
        })
    }

}

impl Drop for WindowsSecurityDescriptor {
    fn drop(&mut self) {
        self.free_descriptor();
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct WindowsInheritedFrom {
    ace_count: u16,
    buffer: Vec<u8>,
}

impl WindowsInheritedFrom {
    pub fn count( &self ) -> u16 {
        self.ace_count
    }

    pub fn get( &self, idx: u16 ) -> Option<&INHERITED_FROMW> {
        if idx >= self.ace_count {
            return None;
        }

        let pInheritArray = self.buffer.as_ptr() as *const INHERITED_FROMW;
        let pItem = unsafe { &* pInheritArray.offset(idx as isize) };
        Some(pItem)
    }

    pub fn generation_gap( item: &INHERITED_FROMW ) -> i32 {
        item.GenerationGap
    }

    pub fn ancestor_name( item: &INHERITED_FROMW ) -> Result<Option<String>> {
        if item.AncestorName.is_null() {
            return Ok(None)
        }
        
        let name = unsafe { item.AncestorName.to_string() }
            .map_err(|_| Error::empty())?;

        Ok(Some(name))
    }

    pub fn free( &mut self ) -> Result<()> {
        if self.buffer.is_empty() && self.ace_count == 0 {
            return Ok(());
        }

        let pInheritArray = self.buffer.as_ptr() as *const INHERITED_FROMW;
        let pInheritArray = unsafe { core::slice::from_raw_parts( pInheritArray, self.ace_count as usize ) };
        
        let ret = unsafe {
            FreeInheritedFromArray(
                pInheritArray,
                None
            )
        };

        if ret != ERROR_SUCCESS {
            let err = Error::from_hresult(HRESULT::from_win32(ret.0));
            return Err(err);
        };

        self.ace_count = 0;
        self.buffer.truncate(0);

        Ok(())
    }
}

impl Drop for WindowsInheritedFrom {
    fn drop(&mut self) {
        let _ = self.free();
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

impl fmt::Debug for MaybeSet<*const _ACL, Option<Vec<u8>>> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_tuple("ACL");
        let f = match self {
            MaybeSet::Unset(p) => {
                f.field(p)
            },
            MaybeSet::Set(None) => {
                f.field(&DebugIdent("None"))
            }
            MaybeSet::Set(Some(v)) => {
                f.field(v)
            }
        };
        f.finish()
    }
}

impl fmt::Debug for MaybeSet<PSID, SID> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_tuple("SID");
        let f = match self {
            MaybeSet::Unset(u) => {
                f.field(u)
            },
            MaybeSet::Set(s) => {
                f.field(s)
            }
        };
        f.finish()
    }
}

impl fmt::Debug for MaybeSet<bool, bool> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MaybeSet::Unset(u) => {
                fmt::Debug::fmt(u, f)
            },
            MaybeSet::Set(s) => {
                fmt::Debug::fmt(s, f)
            }
        }
    }
}

