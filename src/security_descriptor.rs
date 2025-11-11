//! Contains the ACL introspection and manipulation functionality

#![allow(non_snake_case)]

use core::{
    mem::offset_of,
    ffi::c_void,
    ptr::{null, null_mut},
    mem::MaybeUninit,
    marker::PhantomData,
    fmt,
    hash,
};
use std::{
    os::windows::io::RawHandle
};
use windows::{
    core::{
        Error, Result, HRESULT, PWSTR,
    },
    Win32::{
        Foundation::{
            HANDLE, ERROR_SUCCESS,
        },
        Security::{
            Authorization::{
                SE_FILE_OBJECT, SE_KERNEL_OBJECT, SE_OBJECT_TYPE,
                SE_REGISTRY_KEY, SE_REGISTRY_WOW64_32KEY, INHERITED_FROMW, GetInheritanceSourceW, TRUSTEE_W,
            },
            AddAccessAllowedAceEx, AddAccessDeniedAceEx, AddAce, AddAuditAccessAceEx, AddMandatoryAce,
            GetAce, GetAclInformation, InitializeAcl, IsValidAcl,
            AclSizeInformation, ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_CALLBACK_ACE,
            ACCESS_ALLOWED_CALLBACK_OBJECT_ACE, ACCESS_ALLOWED_OBJECT_ACE, ACCESS_DENIED_ACE,
            ACCESS_DENIED_CALLBACK_ACE, ACCESS_DENIED_CALLBACK_OBJECT_ACE, ACCESS_DENIED_OBJECT_ACE,
            ACL as _ACL, ACL_REVISION_DS, ACL_SIZE_INFORMATION, CONTAINER_INHERIT_ACE,
            FAILED_ACCESS_ACE_FLAG, INHERITED_ACE, OBJECT_INHERIT_ACE, PSID, 
            SUCCESSFUL_ACCESS_ACE_FLAG, SYSTEM_AUDIT_ACE, SYSTEM_AUDIT_CALLBACK_ACE,
            SYSTEM_AUDIT_CALLBACK_OBJECT_ACE, SYSTEM_AUDIT_OBJECT_ACE,
            SYSTEM_MANDATORY_LABEL_ACE, SYSTEM_RESOURCE_ATTRIBUTE_ACE, ACE_HEADER, ACE_FLAGS, GENERIC_MAPPING,
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
    ace::ACE, acl::{
        ACEWithInheritedFromIterator, ACLEntryIterator, ACLVecList, AceEntryIterator, ACL
    }, 
    acl_kind::{ACLKind, DACL, SACL}, 
    winapi::sid::{SIDRef, VSID}, 
    types::*, 
    utils::DebugUnpretty, 
    winapi::security_descriptor::{
        SecurityDescriptorSource, WindowsSecurityDescriptor,
    }, SID 
    
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/// `SD` represents the access control list (discretionary or oth discretionary/system) for a named object
pub struct SecurityDescriptor {
    descriptor: WindowsSecurityDescriptor,
    source: SecurityDescriptorSource,
    include_sacl: bool,
}

impl SecurityDescriptor {
    pub fn from_source(
        source: SecurityDescriptorSource,
        include_sacl: bool,
    ) -> Result<Self> {
        let mut descriptor = WindowsSecurityDescriptor::new();
        descriptor.read(&source, include_sacl)?;
        Ok(
            Self {
                descriptor,
                source,
                include_sacl,
            }
        )
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
    pub fn from_handle(
        handle: HANDLE,
        object_type: SE_OBJECT_TYPE,
        include_sacl: bool,
    ) -> Result<Self> {
        let source = SecurityDescriptorSource::from_handle(handle, object_type);

        let mut descriptor = WindowsSecurityDescriptor::new();
        descriptor.read(&source, include_sacl)?;

        Ok(
            Self {
                descriptor,
                source,
                include_sacl,
            }
        )
    }

    pub fn from_handle_empty(
        handle: HANDLE,
        object_type: SE_OBJECT_TYPE,
        include_sacl: bool,
    ) -> Self {
        let source = SecurityDescriptorSource::from_handle(handle, object_type);

        let descriptor = WindowsSecurityDescriptor::new();

        Self {
            descriptor,
            source,
            include_sacl,
        }
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
    pub fn from_file_handle(handle: HANDLE, include_sacl: bool) -> Result<Self> {
        Self::from_handle(handle, SE_FILE_OBJECT, include_sacl)
    }

    pub fn from_file_handle_empty(handle: HANDLE, include_sacl: bool) -> Self {
        Self::from_handle_empty(handle, SE_FILE_OBJECT, include_sacl)
    }

    pub fn from_file_raw_handle(handle: RawHandle, include_sacl: bool) -> Result<Self> {
        Self::from_handle(HANDLE(handle), SE_FILE_OBJECT, include_sacl)
    }

    pub fn from_file_raw_handle_empty(handle: RawHandle, include_sacl: bool) -> Self {
        Self::from_handle_empty(HANDLE(handle), SE_FILE_OBJECT, include_sacl)
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
    pub fn from_object_handle(handle: HANDLE, include_sacl: bool) -> Result<Self> {
        Self::from_handle(handle, SE_KERNEL_OBJECT, include_sacl)
    }

    pub fn from_object_handle_empty(handle: HANDLE, include_sacl: bool) -> Self {
        Self::from_handle_empty(handle, SE_KERNEL_OBJECT, include_sacl)
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
    pub fn from_registry_handle(
        handle: HANDLE,
        is_wow6432key: bool,
        include_sacl: bool,
    ) -> Result<Self> {
        if is_wow6432key {
            Self::from_handle(handle, SE_REGISTRY_WOW64_32KEY, include_sacl)
        } else {
            Self::from_handle(handle, SE_REGISTRY_KEY, include_sacl)
        }
    }

    pub fn from_registry_handle_empty(
        handle: HANDLE,
        is_wow6432key: bool,
        include_sacl: bool,
    ) -> Self {
        if is_wow6432key {
            Self::from_handle_empty(handle, SE_REGISTRY_WOW64_32KEY, include_sacl)
        } else {
            Self::from_handle_empty(handle, SE_REGISTRY_KEY, include_sacl)
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
    pub fn from_path(
        path: &str,
        object_type: SE_OBJECT_TYPE,
        include_sacl: bool,
    ) -> Result<Self> {
        let source = SecurityDescriptorSource::from_path(path, object_type);

        let mut descriptor = WindowsSecurityDescriptor::new();
        descriptor.read(&source, include_sacl)?;

        Ok(
            Self {
                descriptor,
                source,
                include_sacl,
            }
        )
    }

    pub fn from_path_empty(
        path: &str,
        object_type: SE_OBJECT_TYPE,
        include_sacl: bool,
    ) -> Self {
        let source = SecurityDescriptorSource::from_path(path, object_type);

        let descriptor = WindowsSecurityDescriptor::new();
        
        Self {
            descriptor,
            source,
            include_sacl,
        }
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
    pub fn from_file_path(path: &str, include_sacl: bool) -> Result<Self> {
        Self::from_path(path, SE_FILE_OBJECT, include_sacl)
    }

    pub fn from_file_path_empty(path: &str, include_sacl: bool) -> Self {
        Self::from_path_empty(path, SE_FILE_OBJECT, include_sacl)
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
    pub fn from_object_path(path: &str, include_sacl: bool) -> Result<Self> {
        Self::from_path(path, SE_KERNEL_OBJECT, include_sacl)
    }

    pub fn from_object_path_empty(path: &str, include_sacl: bool) -> Self {
        Self::from_path_empty(path, SE_KERNEL_OBJECT, include_sacl)
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
    pub fn from_registry_path(
        path: &str,
        is_wow6432key: bool,
        include_sacl: bool,
    ) -> Result<Self> {
        if is_wow6432key {
            Self::from_path(path, SE_REGISTRY_WOW64_32KEY, include_sacl)
        } else {
            Self::from_path(path, SE_REGISTRY_KEY, include_sacl)
        }
    }

    pub fn from_registry_path_empty(
        path: &str,
        is_wow6432key: bool,
        include_sacl: bool,
    ) -> Self {
        if is_wow6432key {
            Self::from_path_empty(path, SE_REGISTRY_WOW64_32KEY, include_sacl)
        } else {
            Self::from_path_empty(path, SE_REGISTRY_KEY, include_sacl)
        }
    }
    //

    /// Returns the `ObjectType` of the target named object path as specified during the creation of the `ACL` object
    pub fn object_type(&self) -> ObjectType {
        self.source.object_type().into()
    }

    //

    pub fn owner<'s>(&'s self) -> Result<Option<SIDRef<'s>>> {
        self.descriptor.owner()
    }

    pub fn set_owner<'s>(&mut self, owner: SIDRef<'s>) -> Result<()> {
        self.descriptor.set_owner(owner)
    }

    pub fn unset_owner<'s>(&mut self) -> Result<()> {
        self.descriptor.unset_owner()
    }

    //

    pub fn group<'s>(&'s self) -> Result<Option<SIDRef<'s>>> {
        self.descriptor.group()
    }

    pub fn set_group<'s>(&mut self, group: SIDRef<'s>) -> Result<()> {
        self.descriptor.set_group(group)
    }

    pub fn unset_group<'s>(&mut self) -> Result<()> {
        self.descriptor.unset_group()
    }

    //

    pub fn dacl( &self ) -> ACL<'_, DACL> {
        let dacl = self.descriptor.dacl().unwrap_or(null());
        ACL::from_pacl(dacl)
    }

    pub fn set_dacl( &mut self, dacl: ACLVecList<DACL> ) -> Result<()> {
        self.descriptor.set_dacl(dacl.into_vec())
    }

    fn inner_set_dacl( &mut self, dacl: Vec<u8> ) -> Result<()> {
        self.descriptor.set_dacl(dacl)
    }

    pub fn update_dacl<'s, 'r, F, R>( &'s mut self, f: F ) -> Result<()>
    where
        F: Fn(AceEntryIterator<'s, DACL>) -> Result<R>,
        R: ACLEntryIterator<'r, DACL>,
    {
        let dacl = self.descriptor.dacl().unwrap_or(null());
        let dacl = ACL::from_pacl(dacl);

        let new_dacl = f(dacl.iter())?
            .try_collect::<ACLVecList<DACL>>()?
            .into_vec();

        self.inner_set_dacl(new_dacl)
    }

    pub fn iter_dacl_with_inheritance_source( &self ) -> Result<ACEWithInheritedFromIterator<'_, DACL>> {
        let dacl = self.descriptor.dacl().unwrap_or(null());

        let inherited_from = self.descriptor.get_inheritance_source::<DACL>(
            &self.source,
            dacl,
        )?;

        let iter = ACEWithInheritedFromIterator::new( 
            dacl, 
            inherited_from
        );

        Ok(iter)
    }

    //

    pub fn dacl_is_protected( &self ) -> bool {
        self.descriptor.dacl_is_protected()
    }

    pub fn set_dacl_is_protected( &mut self, is_protected: bool ) -> Result<()> {
        self.descriptor.set_dacl_is_protected(is_protected)
    }

    pub fn unset_dacl_is_protected( &mut self ) -> Result<()> {
        self.descriptor.unset_dacl_is_protected()
    }

    //

    pub fn sacl( &self ) -> ACL<'_, SACL> {
        let sacl = self.descriptor.sacl().unwrap_or(null());
        ACL::from_pacl(sacl)
    }

    pub fn set_sacl( &mut self, dacl: ACLVecList<SACL> ) -> Result<()> {
        if !self.include_sacl {
            return Err(Error::empty());
        }

        self.descriptor.set_sacl(dacl.into_vec())
    }

    fn inner_set_sacl( &mut self, sacl: Vec<u8> ) -> Result<()> {
        self.descriptor.set_sacl(sacl)
    }

    pub fn update_sacl<'s, 'r, F, R>( &'s mut self, f: F ) -> Result<()>
    where
        F: Fn(AceEntryIterator<'s, SACL>) -> Result<R>,
        R: ACLEntryIterator<'r, SACL>,
    {
        if !self.include_sacl {
            return Err(Error::empty());
        }

        let sacl = self.descriptor.sacl().unwrap_or(null());
        let sacl = ACL::from_pacl(sacl);

        let new_sacl = f(sacl.iter())?
            .try_collect::<ACLVecList<SACL>>()?
            .into_vec();

        self.inner_set_sacl(new_sacl)
    }

    pub fn iter_sacl_with_inheritance_source( &self ) -> Result<ACEWithInheritedFromIterator<'_, SACL>> {
        let sacl = self.descriptor.sacl().unwrap_or(null());

        let inherited_from = self.descriptor.get_inheritance_source::<SACL>(
            &self.source,
            sacl,
        )?;

        let iter = ACEWithInheritedFromIterator::new( 
            sacl, 
            inherited_from
        );

        Ok(iter)
    }

    //

    pub fn sacl_is_protected( &self ) -> bool {
        self.descriptor.sacl_is_protected()
    }

    pub fn set_sacl_is_protected( &mut self, is_protected: bool ) -> Result<()> {
        if !self.include_sacl {
            return Err(Error::empty());
        }

        self.descriptor.set_sacl_is_protected(is_protected)
    }

    pub fn unset_sacl_is_protected( &mut self ) -> Result<()> {
        if !self.include_sacl {
            return Err(Error::empty());
        }

        self.descriptor.unset_sacl_is_protected()
    }

    //

    /// Update the current named object path's security descriptor. Returns a boolean denoting the status of the reload operation.
    ///
    /// # Remarks
    /// This is invoked automatically after any add/remove entry operation.
    pub fn reload(&mut self) -> Result<()> {
        self.descriptor.read(
            &self.source,
            self.include_sacl,
        )?;
        Ok(())
    }

    pub fn write( &mut self ) -> Result<()> {
        self.descriptor.write(
            &self.source,
            self.include_sacl,
        )
    }

    //

    pub fn take_ownership_from_file_path<'s>( path: &str ) -> Result<()> {
        let source = SecurityDescriptorSource::from_file_path(path);
        let current_user = SID::current_user()?;
        WindowsSecurityDescriptor::take_ownership(&source, current_user.as_ref())
    }

    //

    pub fn get_effective_access_rigths( &self, sid: SIDRef<'_> ) -> Result<ACCESS_MASK> {
        let access_mask = self.descriptor.get_effective_access_rigths(sid)?;
        Ok(ACCESS_MASK(access_mask))
    }

}

impl fmt::Debug for SecurityDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let dacl_entries = self.dacl().all().unwrap_or_default();
        let sacl_entries = self.sacl().all().unwrap_or_default();
        let owner = self.owner().unwrap_or_default();
        let group = self.group().unwrap_or_default();

        f.debug_struct("SD")
            .field("dacl_is_protected", &self.dacl_is_protected() )
            .field("sacl_is_protected", &self.sacl_is_protected() )
            .field("dacl", &dacl_entries )
            .field("sacl", &sacl_entries )
            .field("owner", &DebugUnpretty(owner) )
            .field("group", &DebugUnpretty(group) )
            .finish()
    }
}