//! Contains the ACL introspection and manipulation functionality

#![allow(non_snake_case)]

use crate::{
    ace::ACE,
    acl::{ACEWithInheritedFromIterator, ACLEntryIterator, ACLVecList, AceEntryIterator, ACL},
    acl_kind::{DACL, SACL},
    types::*,
    utils::DebugUnpretty,
    winapi::sid::{SIDRef},
    winapi::{
        api::ErrorExt,
        privilege::Privilege,
        security_descriptor::{SecurityDescriptorSource, WindowsSecurityDescriptor},
    },
    SID,
};
use core::{
    fmt, 
    ptr::{null},
};
use std::{os::windows::io::RawHandle, path::Path};
use windows::{
    core::{Error, Result},
    Win32::{
        Foundation::{ HANDLE},
        Security::{
            Authorization::{
                SE_FILE_OBJECT, SE_KERNEL_OBJECT,
                SE_OBJECT_TYPE, SE_REGISTRY_KEY, SE_REGISTRY_WOW64_32KEY,
            },
        },
    },
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/// `SD` represents the access control list (discretionary or oth discretionary/system) for a named object
pub struct SecurityDescriptor {
    descriptor: WindowsSecurityDescriptor,
    source: SecurityDescriptorSource,
    sacl_enabled: bool,
    allow_read_with_backup_privilege: bool,
    allow_write_with_restore_privilege: bool,
}

impl SecurityDescriptor {
    pub fn from_source(source: SecurityDescriptorSource) -> Self {
        Self {
            descriptor: WindowsSecurityDescriptor::new(),
            source,
            sacl_enabled: false,
            allow_read_with_backup_privilege: false,
            allow_write_with_restore_privilege: false,
        }
    }

    /// Creates an `SecurityDescriptor` object from a specified object handle.
    ///
    /// # Arguments
    /// * `handle` - An object handle.
    /// * `object_type` - The named object path's type. See [SE_OBJECT_TYPE](https://docs.microsoft.com/en-us/windows/desktop/api/accctrl/ne-accctrl-_se_object_type).
    /// * `include_sacl` - A boolean specifying whether the returned `SecurityDescriptor` object will be able to enumerate and set
    ///                System ACL entries.
    ///
    /// # Remarks
    /// For file, kernel object, and registry paths, it is better to use the simpler `from_file_handle`,
    /// `from_object_handle`, and `from_registry_handle` APIs.
    ///
    /// # Errors
    /// On error, a Windows error code is wrapped in an `Err` type.
    pub fn from_handle(handle: HANDLE, object_type: SE_OBJECT_TYPE) -> Self {
        Self::from_source(SecurityDescriptorSource::from_handle(handle, object_type))
    }

    /// Creates an `SD` object from a specified file handle.
    ///
    /// # Arguments
    /// * `handle` - A file handle.
    /// * `include_sacl` - A boolean specifying whether the returned `ACL` object will be able to enumerate and set
    ///                System ACL entries.
    ///
    /// # Remarks
    /// This function is a wrapper for `from_path`.
    ///
    /// # Errors
    /// On error, a Windows error code is wrapped in an `Err` type.
    pub fn from_file_handle(handle: HANDLE) -> Self {
        Self::from_handle(handle, SE_FILE_OBJECT)
    }

    pub fn from_file_raw_handle(handle: RawHandle) -> Self {
        Self::from_handle(HANDLE(handle), SE_FILE_OBJECT)
    }

    /// Creates an `SD` object from a specified kernel object handle.
    ///
    /// # Arguments
    /// * `handle` - A kernel object handle.
    /// * `include_sacl` - A boolean specifying whether the returned `SD` object will be able to enumerate and set
    ///                System ACL entries.
    ///
    /// # Remarks
    /// This function is a wrapper for `from_path`.
    ///
    /// # Errors
    /// On error, a Windows error code is wrapped in an `Err` type.
    pub fn from_object_handle(handle: HANDLE) -> Self {
        Self::from_handle(handle, SE_KERNEL_OBJECT)
    }

    /// Creates an `SD` object from a specified registry handle.
    ///
    /// # Arguments
    /// * `handle` - A registry key handle.
    /// * `include_sacl` - A boolean specifying whether the returned `SD` object will be able to enumerate and set
    ///                System ACL entries.
    ///
    /// # Remarks
    /// This function is a wrapper for `from_path`.
    ///
    /// # Errors
    /// On error, a Windows error code is wrapped in an `Err` type.
    pub fn from_registry_handle(handle: HANDLE, is_wow6432key: bool) -> Self {
        if is_wow6432key {
            Self::from_handle(handle, SE_REGISTRY_WOW64_32KEY)
        } else {
            Self::from_handle(handle, SE_REGISTRY_KEY)
        }
    }

    /// Creates an `SD` object from a specified named object path.
    ///
    /// # Arguments
    /// * `path` - A string containing the named object path.
    /// * `object_type` - The named object path's type. See [SE_OBJECT_TYPE](https://docs.microsoft.com/en-us/windows/desktop/api/accctrl/ne-accctrl-_se_object_type).
    /// * `include_sacl` - A boolean specifying whether the returned `SD` object will be able to enumerate and set
    ///                System ACL entries.
    ///
    /// # Remarks
    /// For file, kernel object, and registry paths, it is better to use the simpler `from_file_path`,
    /// `from_object_path`, and `from_registry_path` APIs.
    ///
    /// # Errors
    /// On error, a Windows error code is wrapped in an `Err` type.
    pub fn from_path(path: &Path, object_type: SE_OBJECT_TYPE) -> Self {
        Self::from_source(SecurityDescriptorSource::from_path(path, object_type))
    }

    /// Creates an `SD` object from a specified file path.
    ///
    /// # Arguments
    /// * `path` - A string containing the file path.
    /// * `include_sacl` - A boolean specifying whether the returned `SD` object will be able to enumerate and set
    ///                System ACL entries.
    ///
    /// # Remarks
    /// This function is a wrapper for `from_path`.
    ///
    /// # Errors
    /// On error, a Windows error code is wrapped in an `Err` type.
    pub fn from_file_path(path: &Path) -> Self {
        Self::from_path(path, SE_FILE_OBJECT)
    }

    /// Creates an `SD` object from a specified kernel object path.
    ///
    /// # Arguments
    /// * `path` - A string containing the kernel object path.
    /// * `include_sacl` - A boolean specifying whether the returned `SD` object will be able to enumerate and set
    ///                System ACL entries.
    ///
    /// # Remarks
    /// This function is a wrapper for `from_path`.
    ///
    /// # Errors
    /// On error, a Windows error code is wrapped in an `Err` type.
    pub fn from_object_path(path: &Path) -> Self {
        Self::from_path(path, SE_KERNEL_OBJECT)
    }

    /// Creates an `SD` object from a specified registry path.
    ///
    /// # Arguments
    /// * `path` - A string containing the registry path.
    /// * `include_sacl` - A boolean specifying whether the returned `SD` object will be able to enumerate and set
    ///                System ACL entries.
    ///
    /// # Remarks
    /// This function is a wrapper for `from_path`.
    ///
    /// # Errors
    /// On error, a Windows error code is wrapped in an `Err` type.
    pub fn from_registry_path(path: &Path, is_wow6432key: bool) -> Self {
        if is_wow6432key {
            Self::from_path(path, SE_REGISTRY_WOW64_32KEY)
        } else {
            Self::from_path(path, SE_REGISTRY_KEY)
        }
    }

    //

    pub fn enable_sacl(&mut self, enabled: bool) {
        self.sacl_enabled = enabled;
    }

    pub fn allow_read_with_backup_privilege(&mut self, allowed: bool) {
        self.allow_read_with_backup_privilege = allowed;
    }

    pub fn allow_write_with_restore_privilege(&mut self, allowed: bool) {
        self.allow_write_with_restore_privilege = allowed;
    }

    //

    /// Returns the `ObjectType` of the target named object path as specified during the creation of the `ACL` object
    pub fn object_type(&self) -> ObjectType {
        self.source.object_type().into()
    }

    //

    pub fn owner(&self) -> Result<Option<&SIDRef>> {
        self.descriptor.owner()
    }

    pub fn set_owner<'s>(&mut self, owner: &SIDRef) -> Result<()> {
        self.descriptor.set_owner(owner)
    }

    pub fn unset_owner<'s>(&mut self) -> Result<()> {
        self.descriptor.unset_owner()
    }

    //

    pub fn group(&self) -> Result<Option<&SIDRef>> {
        self.descriptor.group()
    }

    pub fn set_group<'s>(&mut self, group: &SIDRef) -> Result<()> {
        self.descriptor.set_group(group)
    }

    pub fn unset_group<'s>(&mut self) -> Result<()> {
        self.descriptor.unset_group()
    }

    //

    pub fn dacl(&self) -> ACL<'_, DACL> {
        let dacl = self.descriptor.dacl().unwrap_or(null());
        unsafe { ACL::from_pacl(dacl) }
    }

    unsafe fn dacl_as_static(&self) -> ACL<'static, DACL> {
        let dacl = self.descriptor.dacl().unwrap_or(null());
        unsafe { ACL::from_pacl(dacl) }
    }

    pub fn set_dacl(&mut self, dacl: ACLVecList<DACL>) -> Result<()> {
        self.descriptor.set_dacl(dacl.into_vec())
    }

    pub fn update_dacl<'s, 't, 'r, R, F>(&'s mut self, f: F) -> Result<()>
    where
        's: 't,
        't: 'r,
        F: Fn(AceEntryIterator<'t, DACL>) -> Result<R>,
        R: ACLEntryIterator<'r, DACL>,
    {
        // Dirty hack :(. But it works in proper way.
        let dacl = unsafe { self.dacl_as_static() };
        let iter = dacl.iter();

        let new_dacl = f(iter)?.try_collect::<ACLVecList<DACL>>()?;

        self.set_dacl(new_dacl)
    }

    pub fn iter_dacl_with_inheritance_source(
        &self,
    ) -> Result<ACEWithInheritedFromIterator<'_, DACL>> {
        let dacl = self.descriptor.dacl().unwrap_or(null());

        let inherited_from = self
            .descriptor
            .get_inheritance_source::<DACL>(&self.source, dacl)?;

        let iter = ACEWithInheritedFromIterator::new(dacl, inherited_from);

        Ok(iter)
    }

    //

    pub fn dacl_is_protected(&self) -> bool {
        self.descriptor.dacl_is_protected()
    }

    pub fn set_dacl_is_protected(&mut self, is_protected: bool) -> Result<()> {
        self.descriptor.set_dacl_is_protected(is_protected)
    }

    pub fn unset_dacl_is_protected(&mut self) -> Result<()> {
        self.descriptor.unset_dacl_is_protected()
    }

    //

    pub fn sacl(&self) -> ACL<'_, SACL> {
        if !self.sacl_enabled {
            return ACL::from_null();
        }

        let sacl = self.descriptor.sacl().unwrap_or(null());
        unsafe { ACL::from_pacl(sacl) }
    }

    unsafe fn sacl_as_static(&self) -> ACL<'static, SACL> {
        let sacl = self.descriptor.sacl().unwrap_or(null());
        unsafe { ACL::from_pacl(sacl) }
    }

    pub fn set_sacl(&mut self, dacl: ACLVecList<SACL>) -> Result<()> {
        if !self.sacl_enabled {
            return Err(Error::empty());
        }

        self.descriptor.set_sacl(dacl.into_vec())
    }

    pub fn update_sacl<'s, 't, 'r, R, F>(&'s mut self, f: F) -> Result<()>
    where
        's: 't,
        't: 'r,
        F: Fn(AceEntryIterator<'t, SACL>) -> Result<R>,
        R: ACLEntryIterator<'r, SACL>,
    {
        if !self.sacl_enabled {
            return Err(Error::empty());
        }

        // Dirty hack :(. But it works in proper way.
        let sacl = unsafe { self.sacl_as_static() };
        let iter = sacl.iter();

        let new_sacl = f(iter)?.try_collect()?;

        self.set_sacl(new_sacl)
    }

    pub fn iter_sacl_with_inheritance_source(
        &self,
    ) -> Result<ACEWithInheritedFromIterator<'_, SACL>> {
        if !self.sacl_enabled {
            return Err(Error::empty());
        }

        let sacl = self.descriptor.sacl().unwrap_or(null());

        let inherited_from = self
            .descriptor
            .get_inheritance_source::<SACL>(&self.source, sacl)?;

        let iter = ACEWithInheritedFromIterator::new(sacl, inherited_from);

        Ok(iter)
    }

    //

    pub fn sacl_is_protected(&self) -> bool {
        if !self.sacl_enabled {
            return false;
        }

        self.descriptor.sacl_is_protected()
    }

    pub fn set_sacl_is_protected(&mut self, is_protected: bool) -> Result<()> {
        if !self.sacl_enabled {
            return Err(Error::empty());
        }

        self.descriptor.set_sacl_is_protected(is_protected)
    }

    pub fn unset_sacl_is_protected(&mut self) -> Result<()> {
        if !self.sacl_enabled {
            return Err(Error::empty());
        }

        self.descriptor.unset_sacl_is_protected()
    }

    //

    /// Update the current named object path's security descriptor. Returns a boolean denoting the status of the reload operation.
    ///
    /// # Remarks
    /// This is invoked automatically after any add/remove entry operation.
    pub fn read(&mut self) -> Result<()> {
        if self.sacl_enabled {
            Privilege::with_security(|| self.inner_read())
        } else {
            self.inner_read()
        }
    }

    fn inner_read(&mut self) -> Result<()> {
        match self.descriptor.read(&self.source, self.sacl_enabled) {
            Ok(()) => {
                return Ok(());
            }
            Err(e) if e.is_access_denied() && self.allow_read_with_backup_privilege => {}
            Err(e) => {
                return Err(e);
            }
        };

        Privilege::with_backup(|| self.descriptor.read(&self.source, self.sacl_enabled))
    }

    //

    pub fn write(&mut self) -> Result<()> {
        if self.sacl_enabled && self.descriptor.sacl_is_modified() {
            Privilege::with_security(|| self.inner_write())
        } else {
            self.inner_write()
        }
    }

    fn inner_write(&mut self) -> Result<()> {
        match self.descriptor.write(&self.source, self.sacl_enabled) {
            Ok(()) => {
                return Ok(());
            }
            Err(e) if e.is_access_denied() && self.allow_write_with_restore_privilege => {}
            Err(e) => {
                return Err(e);
            }
        };

        Privilege::with_restore(|| self.descriptor.write(&self.source, self.sacl_enabled))
    }

    //

    pub fn write_and_reload(&mut self) -> Result<()> {
        if self.sacl_enabled {
            Privilege::with_security(|| self.inner_write_and_reload())
        } else {
            self.inner_write_and_reload()
        }
    }

    fn inner_write_and_reload(&mut self) -> Result<()> {
        self.inner_write()?;
        self.inner_read()
    }

    //

    pub fn take_ownership<'s>(&self) -> Result<()> {
        let current_user = SID::current_user()?;
        Privilege::with_take_ownership(|| {
            WindowsSecurityDescriptor::take_ownership(&self.source, current_user.as_ref())
        })
    }

    //

    pub fn get_effective_access_rigths(&self, sid: &SIDRef) -> Result<ACCESS_MASK> {
        let access_mask = self.descriptor.get_effective_access_rights(sid)?;
        Ok(ACCESS_MASK(access_mask))
    }

    fn dacl_all(&self) -> Result<Vec<ACE<'_, DACL>>> {
        let d = self.dacl();
        d.all()
    }
}

impl fmt::Debug for SecurityDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let dacl_entries = self.dacl_all().unwrap_or_default();
        let sacl_entries = self.sacl().all().unwrap_or_default();
        let owner = self.owner().unwrap_or_default();
        let group = self.group().unwrap_or_default();

        f.debug_struct("SD")
            .field("dacl_is_protected", &self.dacl_is_protected())
            .field("sacl_is_protected", &self.sacl_is_protected())
            .field("dacl", &dacl_entries)
            .field("sacl", &sacl_entries)
            .field("owner", &DebugUnpretty(owner))
            .field("group", &DebugUnpretty(group))
            .finish()
    }
}
