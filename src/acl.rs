//! Contains the ACL introspection and manipulation functionality

#![allow(non_snake_case)]

use core::{
    mem::offset_of,
    ffi::c_void,
    ptr::{null, null_mut},
    mem,
};
use std::os::windows::io::RawHandle;
use windows::{
    core::{
        Error, Result,
    },
    Win32::{
        Foundation::{
            HANDLE,
        },
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
            ACL as _ACL, ACL_REVISION_DS, ACL_SIZE_INFORMATION, CONTAINER_INHERIT_ACE,
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
            FILE_ACCESS_RIGHTS,
        }
    },
};

use crate::{
    acl_entry::ACLEntry, sd::{
        SDSource, SecurityDescriptor,
    }, sid::{SIDRef, VSID}, types::*, utils::{as_ppvoid_mut, as_pvoid_mut, vec_as_pacl_mut}
};

/// `ACL` represents the access control list (discretionary or oth discretionary/system) for a named object
#[derive(Debug)]
pub struct ACL {
    descriptor: SecurityDescriptor,
    source: SDSource,
    object_type: ObjectType,
    // include_sacl: bool,
}

macro_rules! process_entry {
    ($entry: ident, $typ: path, $ptr: ident => $cls: path) => {
        {
            let entry_ptr: *mut $cls = $ptr as *mut $cls;
            let sid_offset = offset_of!($cls, SidStart);
            let pSid: PSID = PSID(entry_ptr.wrapping_byte_add(sid_offset) as *mut _);

            $entry.entry_type = $typ;
            $entry.mask = FILE_ACCESS_RIGHTS(unsafe { (*entry_ptr).Mask });
            // $entry.size = unsafe { (*$ptr).AceSize };
            $entry.flags = ACE_FLAGS(unsafe { (*$ptr).AceFlags } as u32);
            $entry.sid = unsafe{ VSID::from_psid(pSid) }?;
        }
    };
}

enum EntryCallbackResult {
    Continue,
    Break,
}

trait EntryCallback<'e> {
    fn on_entry(&mut self, hdr: *mut ACE_HEADER, entry: ACLEntry<'e>) -> Result<EntryCallbackResult>;
}

fn acl_size(pacl: *const _ACL) -> Result<u32> {
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

pub(crate) fn acl_entry_size(entry_type: AceType) -> Result<u32> {
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

fn enumerate_acl_entries<'e, T: EntryCallback<'e>>(pAcl: *const _ACL, callback: &mut T) -> Result<()> {
    if pAcl.is_null() {
        return Err(Error::empty());
    }

    let mut hdr: *mut ACE_HEADER = null_mut();
    let ace_count = unsafe { (*pAcl).AceCount };

    for i in 0..ace_count {
        unsafe { 
            GetAce(
                pAcl,
                i as u32,
                as_ppvoid_mut(&mut hdr)
            )
        }?;

        let mut entry = ACLEntry::new();

        match unsafe { (*hdr).AceType } as u32 {
            ACCESS_ALLOWED_ACE_TYPE => {
                process_entry!(
                    entry,
                    AceType::AccessAllow,
                    hdr => ACCESS_ALLOWED_ACE
                )
            },
            ACCESS_ALLOWED_CALLBACK_ACE_TYPE => {
                process_entry!(
                    entry,
                    AceType::AccessAllowCallback,
                    hdr => ACCESS_ALLOWED_CALLBACK_ACE
                )
            },
            ACCESS_ALLOWED_OBJECT_ACE_TYPE => {
                process_entry!(
                    entry,
                    AceType::AccessAllowObject,
                    hdr => ACCESS_ALLOWED_OBJECT_ACE
                )
            },
            ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE => {
                process_entry!(
                    entry,
                    AceType::AccessAllowCallbackObject,
                    hdr => ACCESS_ALLOWED_CALLBACK_OBJECT_ACE
                )
            },
            ACCESS_DENIED_ACE_TYPE => {
                process_entry!(
                    entry,
                    AceType::AccessDeny,
                    hdr => ACCESS_DENIED_ACE
                )
            },
            ACCESS_DENIED_CALLBACK_ACE_TYPE => {
                process_entry!(
                    entry,
                    AceType::AccessDenyCallback,
                    hdr => ACCESS_DENIED_CALLBACK_ACE
                )
            },
            ACCESS_DENIED_OBJECT_ACE_TYPE => {
                process_entry!(
                    entry,
                    AceType::AccessDenyObject,
                    hdr => ACCESS_DENIED_OBJECT_ACE
                )
            },
            ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE => {
                process_entry!(
                    entry,
                    AceType::AccessDenyCallbackObject,
                    hdr => ACCESS_DENIED_CALLBACK_OBJECT_ACE
                )
            },
            SYSTEM_AUDIT_ACE_TYPE => {
                process_entry!(
                    entry,
                    AceType::SystemAudit,
                    hdr => SYSTEM_AUDIT_ACE
                )
            },
            SYSTEM_AUDIT_CALLBACK_ACE_TYPE => {
                process_entry!(
                    entry,
                    AceType::SystemAuditCallback,
                    hdr => SYSTEM_AUDIT_CALLBACK_ACE
                )
            },
            SYSTEM_AUDIT_OBJECT_ACE_TYPE => {
                process_entry!(
                    entry,
                    AceType::SystemAuditObject,
                    hdr => SYSTEM_AUDIT_OBJECT_ACE
                )
            },
            SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE => {
                process_entry!(
                    entry,
                    AceType::SystemAuditCallbackObject,
                    hdr => SYSTEM_AUDIT_CALLBACK_OBJECT_ACE
                )
            },
            SYSTEM_MANDATORY_LABEL_ACE_TYPE => {
                process_entry!(
                    entry,
                    AceType::SystemMandatoryLabel,
                    hdr => SYSTEM_MANDATORY_LABEL_ACE
                )
            },
            SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE => {
                process_entry!(
                    entry,
                    AceType::SystemResourceAttribute,
                    hdr => SYSTEM_RESOURCE_ATTRIBUTE_ACE
                )
            },
            _ => {}
        }

        match callback.on_entry(hdr, entry)? {
            EntryCallbackResult::Continue => {},
            EntryCallbackResult::Break => {
                break;
            }
        }
    }

    Ok(())
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

struct GetEntryCallback<'r, 's> {
    entries: Vec<ACLEntry<'r>>,
    target_sid: SIDRef<'s>,
    target_type: Option<AceType>,
}

impl<'r, 's, 'e: 'r> EntryCallback<'e> for GetEntryCallback<'r, 's> {
    fn on_entry(&mut self, _hdr: *mut ACE_HEADER, entry: ACLEntry<'e>) -> Result<EntryCallbackResult> {
        if !entry.sid.eq_to_ref(self.target_sid) {
            return Ok(EntryCallbackResult::Continue);
        }

        if let Some(ref t) = self.target_type {
            if entry.entry_type != *t {
                return Ok(EntryCallbackResult::Continue);
            }
        }

        self.entries.push(entry);

        Ok(EntryCallbackResult::Continue)
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

struct AllEntryCallback<'r> {
    entries: Vec<ACLEntry<'r>>,
}

impl<'r, 'e: 'r> EntryCallback<'e> for AllEntryCallback<'r> {
    fn on_entry(&mut self, _hdr: *mut ACE_HEADER, entry: ACLEntry<'e>) -> Result<EntryCallbackResult> {
        self.entries.push(entry);
        Ok(EntryCallbackResult::Continue)
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

struct AddEntryCallback<'s> {
    new_acl: Vec<u8>,
    entry_sid: SIDRef<'s>,
    entry_type: AceType,
    entry_flags: ACE_FLAGS,
    entry_mask: FILE_ACCESS_RIGHTS,
    already_added: bool,
}

impl<'s> AddEntryCallback<'s> {
    fn new(
        old_acl: *const _ACL,
        sid: SIDRef<'s>,
        entry_type: AceType,
        flags: ACE_FLAGS,
        mask: FILE_ACCESS_RIGHTS,
    ) -> Result<Self> {
        let mut new_acl_size = acl_size(old_acl)?;
        new_acl_size += ACLEntry::calculate_entry_size(entry_type, sid)?;

        let mut obj = AddEntryCallback {
            new_acl: Vec::with_capacity(new_acl_size as usize),
            entry_sid: sid,
            entry_type,
            entry_flags: flags,
            entry_mask: mask,
            already_added: false,
        };

        unsafe {
            InitializeAcl(
                vec_as_pacl_mut(&mut obj.new_acl),
                new_acl_size as u32,
                ACL_REVISION_DS,
            )
        }?;

        Ok(obj)
    }

    fn insert_entry(&mut self) -> Result<()> {
        let psid = self.entry_sid.psid();
        let pacl = vec_as_pacl_mut(&mut self.new_acl);

        match self.entry_type {
            AceType::AccessAllow => unsafe {
                AddAccessAllowedAceEx(
                    pacl,
                    ACL_REVISION_DS,
                    self.entry_flags,
                    self.entry_mask.0,
                    psid,
                )
            },
            AceType::AccessDeny => unsafe {
                AddAccessDeniedAceEx(
                    pacl,
                    ACL_REVISION_DS,
                    self.entry_flags,
                    self.entry_mask.0,
                    psid,
                )
            },
            AceType::SystemAudit => unsafe {
                AddAuditAccessAceEx(
                    pacl,
                    ACL_REVISION_DS,
                    self.entry_flags,
                    self.entry_mask.0,
                    psid,
                    false,
                    false,
                )
            },
            AceType::SystemMandatoryLabel => unsafe {
                AddMandatoryAce(
                    pacl,
                    ACL_REVISION_DS,
                    self.entry_flags,
                    self.entry_mask.0,
                    psid,
                )
            },
            _ => Err(Error::empty()),
        }
    }
}

impl<'s, 'e: 's> EntryCallback<'e> for AddEntryCallback<'s> {
    fn on_entry(&mut self, hdr: *mut ACE_HEADER, entry: ACLEntry<'e>) -> Result<EntryCallbackResult> {
        // NOTE(andy): Our assumption here is that the access control list are in the proper order
        //             See https://msdn.microsoft.com/en-us/library/windows/desktop/aa379298(v=vs.85).aspx

        if !self.already_added {
            if entry.flags.contains(INHERITED_ACE) {
                if !entry.sid.is_valid() {
                    return Err(Error::empty());
                }

                if entry.entry_type == self.entry_type && entry.sid.eq_to_ref(self.entry_sid) {
                    // NOTE(andy): We found an entry that matches the type and sid of the one we were going
                    //             to add (uninherited). Instead of adding the old one and the new one, we
                    //             replace the old entry with the new entry.
                    self.insert_entry()?;

                    self.already_added = true;

                    // NOTE(andy): Since we are replacing the matching entry, return true and exit the current
                    //             entry handler
                    return Ok(EntryCallbackResult::Continue);
                }

                if entry.entry_type == AceType::AccessAllow
                    && self.entry_type == AceType::AccessDeny
                {
                    // NOTE(andy): Assuming proper ordering, we just hit an uninherited access allowed ACE while
                    //             trying to add an access deny ACE. This implies that we just reached the end of
                    //             the deny ACEs. We should add the deny ACE here.
                    self.insert_entry()?;
                    self.already_added = true;
                }
            } else {
                // NOTE(andy): Assuming proper ordering, our enumeration hit an inherited ACE while trying
                //             to add an access allowed, access denied, audit, or mandatory label ACE. This
                //             implies that we reached the end of the explicit ACEs. It is a good place to
                //             add access allowed, access denied, audit, or mandatory label ACE.
                self.insert_entry()?;
                self.already_added = true;
            }
        }

        unsafe {
            AddAce(
                vec_as_pacl_mut(&mut self.new_acl),
                ACL_REVISION_DS,
                MAXDWORD,
                hdr as *const c_void,
                (*hdr).AceSize as u32,
            )
        }?;

        Ok(EntryCallbackResult::Continue)
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

struct RemoveEntryCallback<'s> {
    removed_count: usize,
    new_acl: Vec<u8>,
    target_sid: SIDRef<'s>,
    target_type: Option<AceType>,
    target_flags: Option<ACE_FLAGS>,
}

impl<'s> RemoveEntryCallback<'s> {
    fn new(
        old_acl: *const _ACL,
        target_sid: SIDRef<'s>,
        target_type: Option<AceType>,
        target_flags: Option<ACE_FLAGS>,
    ) -> Result<Self> {
        let new_acl_size = acl_size(old_acl)?;

        let mut obj = RemoveEntryCallback {
            removed_count: 0,
            target_sid,
            target_type,
            target_flags,
            new_acl: Vec::with_capacity(new_acl_size as usize),
        };

        unsafe {
            InitializeAcl(
                vec_as_pacl_mut(&mut obj.new_acl),
                new_acl_size,
                ACL_REVISION_DS,
            )
        }?;

        Ok(obj)
    }
}

impl<'s, 'e: 's> EntryCallback<'e> for RemoveEntryCallback<'s> {
    fn on_entry(&mut self, hdr: *mut ACE_HEADER, entry: ACLEntry) -> Result<EntryCallbackResult> {
        if !entry.sid.is_valid() {
            return Err(Error::empty());
        }

        if entry.sid.eq_to_ref(self.target_sid) {
            let mut target_reached = true;

            if let Some(ref t) = self.target_type {
                if entry.entry_type != *t {
                    target_reached = false;
                }
            }
            
            if let Some(target_mask) = self.target_flags {
                if !entry.flags.contains(target_mask) {
                    target_reached = false;
                }
            }
            
            if target_reached {
                self.removed_count += 1;
                return Ok(EntryCallbackResult::Continue);
            }
        }

        unsafe {
            AddAce(
                vec_as_pacl_mut(&mut self.new_acl),
                ACL_REVISION_DS,
                MAXDWORD,
                hdr as *mut c_void,
                (*hdr).AceSize as u32,
            )
        }?;

        Ok(EntryCallbackResult::Continue)
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

impl ACL {
    /// Creates an `ACL` object from a specified object handle.
    ///
    /// # Arguments
    /// * `handle` - An object handle.
    /// * `object_type` - The named object path's type. See [SE_OBJECT_TYPE](https://docs.microsoft.com/en-us/windows/desktop/api/accctrl/ne-accctrl-_se_object_type).
    /// * `include_sacl` - A boolean specifying whether the returned `ACL` object will be able to enumerate and set
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
        let source = SDSource::Handle(handle);
        let descriptor = SecurityDescriptor::from_source(&source, object_type, include_sacl)?;
        Ok(
            Self {
                descriptor,
                source,
                object_type: object_type.into(),
                // include_sacl,
            }
        )
    }

    /// Creates an `ACL` object from a specified file handle.
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

    pub fn from_file_raw_handle(handle: RawHandle, include_sacl: bool) -> Result<Self> {
        Self::from_handle(HANDLE(handle), SE_FILE_OBJECT, include_sacl)
    }

    /// Creates an `ACL` object from a specified kernel object handle.
    ///
    /// # Arguments
    /// * `handle` - A kernel object handle.
    /// * `include_sacl` - A boolean specifying whether the returned `ACL` object will be able to enumerate and set
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

    /// Creates an `ACL` object from a specified registry handle.
    ///
    /// # Arguments
    /// * `handle` - A registry key handle.
    /// * `include_sacl` - A boolean specifying whether the returned `ACL` object will be able to enumerate and set
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

    /// Creates an `ACL` object from a specified named object path.
    ///
    /// # Arguments
    /// * `path` - A string containing the named object path.
    /// * `object_type` - The named object path's type. See [SE_OBJECT_TYPE](https://docs.microsoft.com/en-us/windows/desktop/api/accctrl/ne-accctrl-_se_object_type).
    /// * `include_sacl` - A boolean specifying whether the returned `ACL` object will be able to enumerate and set
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
        let source = SDSource::Path(path.to_owned());
        let descriptor = SecurityDescriptor::from_source(&source, object_type, include_sacl)?;
        Ok(
            Self {
                descriptor,
                source,
                // include_sacl,
                object_type: object_type.into(),
            }
        )
    }

    /// Creates an `ACL` object from a specified file path.
    ///
    /// # Arguments
    /// * `path` - A string containing the file path.
    /// * `include_sacl` - A boolean specifying whether the returned `ACL` object will be able to enumerate and set
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

    /// Creates an `ACL` object from a specified kernel object path.
    ///
    /// # Arguments
    /// * `path` - A string containing the kernel object path.
    /// * `include_sacl` - A boolean specifying whether the returned `ACL` object will be able to enumerate and set
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

    /// Creates an `ACL` object from a specified registry path.
    ///
    /// # Arguments
    /// * `path` - A string containing the registry path.
    /// * `include_sacl` - A boolean specifying whether the returned `ACL` object will be able to enumerate and set
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

    /// Returns the `ObjectType` of the target named object path as specified during the creation of the `ACL` object
    pub fn object_type(&self) -> ObjectType {
        self.object_type
    }

    pub fn owner<'s>(&'s self) -> Result<Option<SIDRef<'s>>> {
        Ok(self.descriptor.owner().as_ref())
    }

    pub fn group<'s>(&'s self) -> Result<Option<SIDRef<'s>>> {
        Ok(self.descriptor.group().as_ref())
    }

    pub fn set_owner<'s>(&mut self, owner: SIDRef<'s>) -> Result<()> {
        self.descriptor.set_owner(owner)
    }

    pub fn set_group<'s>(&mut self, group: SIDRef<'s>) -> Result<()> {
        self.descriptor.set_group(group)
    }

    /// Returns a `Vec<ACLEntry>` of access control list entries for the specified named object path.
    pub fn all(&self) -> Result<Vec<ACLEntry>> {
        let mut callback = AllEntryCallback {
            entries: Vec::new(),
        };

        for acl in [self.descriptor.dacl(), self.descriptor.sacl()].into_iter().filter_map(|p| p) {
            if !acl.is_null() {
                enumerate_acl_entries(acl, &mut callback)?;
            }
        }

        Ok(callback.entries)
    }

    /// Retrieves a list of access control entries matching the target SID entity and optionally, a access control entry type.
    ///
    /// # Arguments
    /// * `sid` - The raw SID of the target entity.
    /// * `entry_type` - The access control entry type or `None`.
    ///
    /// # Errors
    /// On error, a Windows error code is wrapped in an `Err` type.
    pub fn get<'s>(&self, sid: SIDRef<'s>, entry_type: Option<AceType>) -> Result<Vec<ACLEntry>> {
        let mut callback = GetEntryCallback {
            target_sid: sid,
            target_type: entry_type,
            entries: Vec::new(),
        };

        for acl in [self.descriptor.dacl(), self.descriptor.sacl()].into_iter().filter_map(|p| p) {
            if !acl.is_null() {
                enumerate_acl_entries(acl, &mut callback)?;
            }
        }

        Ok(callback.entries)
    }

    /// Update the current named object path's security descriptor. Returns a boolean denoting the status of the reload operation.
    ///
    /// # Remarks
    /// This is invoked automatically after any add/remove entry operation.
    pub fn reload(&mut self) -> Result<()> {
        self.descriptor.read(
            &self.source,
            self.object_type().into(),
        )?;
        Ok(())
    }

    /// Adds a custom entry into the access control list.
    ///
    /// # Arguments
    /// * `sid` - The target entity's raw SID.
    /// * `entry_type` - The entry's type. Currently, only `AccessAllow`, `AccessDeny`, `SystemAudit`, and `SystemMandatoryLabel` are supported.
    /// * `flags` - See [ACE_HEADER](https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_ace_header) documentation.
    /// * `mask` - The permissions allotted for the target entity.
    ///
    /// # Remarks
    /// We only support (for now) adding access allow, access deny, system audit, and system mandatory label entries. After adding the entry,
    /// the security descriptor is automatically reloaded to reflect changes.
    ///
    /// # Errors
    /// On error, a Windows error code is wrapped in an `Err` type. If the error code is 0, the provided `entry_type` is invalid.
    pub fn add_entry<'s>(
        &mut self,
        sid: SIDRef<'s>,
        entry_type: AceType,
        flags: ACE_FLAGS,
        mask: FILE_ACCESS_RIGHTS,
    ) -> Result<bool> {
        let is_dacl;

        let acl: *const _ACL = match entry_type {
            AceType::AccessAllow | AceType::AccessDeny => {
                is_dacl = true;
                self.descriptor.dacl().unwrap_or(null())
            }
            AceType::SystemAudit | AceType::SystemMandatoryLabel => {
                is_dacl = false;
                self.descriptor.sacl().unwrap_or(null())
            },
            _ => {
                return Err(Error::empty());
            }
        };

        // acl may be NULL
        let mut add_callback = AddEntryCallback::new(acl, sid, entry_type, flags, mask)?;

        if !acl.is_null() {
            enumerate_acl_entries(acl, &mut add_callback)?;
        }

        // NOTE(andy): After enumerating the ACL, we still did not add our ACL, at this point, add it to the end
        if !add_callback.already_added {
            add_callback.insert_entry()?;
            add_callback.already_added = true;
        }

        if is_dacl {
            self.descriptor.set_dacl(add_callback.new_acl)?;
        } else {
            self.descriptor.set_sacl(add_callback.new_acl)?;
        };

        Ok(true)
    }

    /// Removes access control list entries that match the specified parameters.
    ///
    /// # Arguments
    /// * `sid` - The target entry's raw SID.
    /// * `entry_type` - The entry's type.
    /// * `flags` - See [ACE_HEADER](https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_ace_header) documentation.
    ///
    /// # Remarks
    /// After removing the entry, the security descriptor is reloaded automatically to reflect changes.
    ///
    /// # Errors
    /// On error, a Windows error code wrapped in a `Err` type.
    pub fn remove_entry<'s>(
        &mut self,
        sid: SIDRef<'s>,
        entry_type: Option<AceType>,
        flags: Option<ACE_FLAGS>,
    ) -> Result<usize> {
        let mut removed_entries_count = 0;

        if let Some(dacl) = self.descriptor.dacl() {
            if !dacl.is_null() {
                let mut dacl_callback = RemoveEntryCallback::new(dacl, sid, entry_type, flags)?;

                enumerate_acl_entries(dacl, &mut dacl_callback)?;
                removed_entries_count += dacl_callback.removed_count;

                self.descriptor.set_dacl(dacl_callback.new_acl)?;
            }
        };

        if let Some(sacl) = self.descriptor.sacl() {
            if !sacl.is_null() {
                let mut sacl_callback = RemoveEntryCallback::new(sacl, sid, entry_type, flags)?;

                enumerate_acl_entries(sacl, &mut sacl_callback)?;
                removed_entries_count += sacl_callback.removed_count;

                self.descriptor.set_sacl(sacl_callback.new_acl)?;
            }
        }

        Ok(removed_entries_count)
    }

    /// Adds an access allow entry to the access control list.
    ///
    /// # Arguments
    /// * `sid` - The target entity's raw SID.
    /// * `inheritable` - Denotes whether this entry should be inheritable by child objects.
    /// * `mask` - The allowed permissions for the target entity.
    ///
    /// # Remarks
    /// This is a wrapper over `add_entry`.
    ///
    /// # Errors
    /// On error, a Windows error code is wrapped in an `Err` type. If the error code is 0, the provided `entry_type` is invalid.
    pub fn allow<'s>(&mut self, sid: SIDRef<'s>, inheritable: bool, mask: FILE_ACCESS_RIGHTS) -> Result<bool> {
        let mut flags: ACE_FLAGS = ACE_FLAGS(0);

        if inheritable {
            flags = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;
        }
        self.add_entry(sid, AceType::AccessAllow, flags, mask)
    }

    /// Adds an access deny entry to the access control list.
    ///
    /// # Arguments
    /// * `sid` - The target entity's raw SID.
    /// * `inheritable` - Denotes whether this entry should be inheritable by child objects.
    /// * `mask` - The denied permissions for the target entity.
    ///
    /// # Remarks
    /// This is a wrapper over `add_entry`
    ///
    /// # Errors
    /// On error, a Windows error code is wrapped in an `Err` type. If the error code is 0, the provided `entry_type` is invalid.
    pub fn deny<'s>(&mut self, sid: SIDRef<'s>, inheritable: bool, mask: FILE_ACCESS_RIGHTS) -> Result<bool> {
        let mut flags: ACE_FLAGS = ACE_FLAGS(0);

        if inheritable {
            flags = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;
        }
        self.add_entry(sid, AceType::AccessDeny, flags, mask)
    }

    /// Adds a system audit entry to the access control list.
    ///
    /// # Arguments
    /// * `sid` - The target entity's raw SID.
    /// * `inheritable` - Denotes whether this entry should be inheritable by child objects.
    /// * `mask` - The permissions to audit.
    /// * `audit_success` - Denotes that success events should be audited.
    /// * `audit_fails` - Denotes that failure events should be audited.
    ///
    /// # Remarks
    /// This is a wrapper over `add_entry`
    ///
    /// # Errors
    /// On error, a Windows error code is wrapped in an `Err` type. If the error code is 0, the provided `entry_type` is invalid.
    pub fn audit<'s>(
        &mut self,
        sid: SIDRef<'s>,
        inheritable: bool,
        mask: FILE_ACCESS_RIGHTS,
        audit_success: bool,
        audit_fails: bool,
    ) -> Result<bool> {
        let mut flags: ACE_FLAGS = ACE_FLAGS(0);

        if inheritable {
            flags = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;
        }

        if audit_success {
            flags |= SUCCESSFUL_ACCESS_ACE_FLAG;
        }

        if audit_fails {
            flags |= FAILED_ACCESS_ACE_FLAG;
        }

        self.add_entry(sid, AceType::SystemAudit, flags, mask)
    }

    /// Adds a system mandatory level entry to the access control list. This sets the mandatory integrity level for the named object path.
    ///
    /// # Arguments
    /// * `label_sid` - See `pLabelSid` in [AddMandatoryAce](https://docs.microsoft.com/en-us/windows/desktop/api/securitybaseapi/nf-securitybaseapi-addmandatoryace)
    /// * `inheritable` - Denotes whether this entry should be inheritable by child objects.
    /// * `policy` - See `MandatoryPolicy` in [AddMandatoryAce](https://docs.microsoft.com/en-us/windows/desktop/api/securitybaseapi/nf-securitybaseapi-addmandatoryace)
    ///
    /// # Remarks
    /// This is a wrapper over `add_entry`
    ///
    /// # Errors
    /// On error, a Windows error code is wrapped in an `Err` type. If the error code is 0, the provided `entry_type` is invalid.
    pub fn integrity_level<'s>(
        &mut self,
        label_sid: SIDRef<'s>,
        inheritable: bool,
        policy: FILE_ACCESS_RIGHTS,
    ) -> Result<bool> {
        let mut flags: ACE_FLAGS = ACE_FLAGS(0);

        if inheritable {
            flags = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;
        }
        self.add_entry(label_sid, AceType::SystemMandatoryLabel, flags, policy)
    }

    /// Removes access control list entries that match the specified parameters.
    ///
    /// # Arguments
    /// * `sid` - The target entry's raw SID.
    /// * `entry_type` - The entry's type.
    /// * `inheritable` - Denotes whether this entry should be inheritable by child objects.
    ///
    /// # Remarks
    /// This is a wrapper over `remove_entry`
    ///
    /// # Errors
    /// On error, a Windows error code is wrapped in an `Err` type.
    pub fn remove<'s>(
        &mut self,
        sid: SIDRef<'s>,
        entry_type: Option<AceType>,
        inheritable: Option<bool>,
    ) -> Result<usize> {
        let mut flags: Option<ACE_FLAGS> = None;
        if let Some(inherit) = inheritable {
            if inherit {
                flags = Some(CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE);
            }
        }

        self.remove_entry(sid, entry_type, flags)
    }

    pub fn set<'s>(&mut self, acl: &[ACLEntry<'s>], is_dacl: bool) -> Result<usize> {
        let mut new_acl_size = mem::size_of::<_ACL>() as u32;
        for ace in acl {
            if !ace.sid.is_valid() {
                return Err(Error::empty());
            }

            new_acl_size += ace.size()?;
        }

        let mut new_acl: Vec<u8> = Vec::with_capacity(new_acl_size as usize);

        unsafe {
            InitializeAcl(
                vec_as_pacl_mut(&mut new_acl),
                new_acl_size as u32,
                ACL_REVISION_DS,
            )
        }?;

        for ace in acl {
            let psid = ace.psid().unwrap();

            match ace.entry_type {
                AceType::AccessAllow => {
                    unsafe {
                        AddAccessAllowedAceEx(
                            new_acl.as_mut_ptr() as *mut _ACL,
                            ACL_REVISION_DS,
                            ace.flags,
                            ace.mask.0,
                            psid,
                        )
                    }?;
                },
                AceType::AccessDeny => {
                    unsafe {
                        AddAccessDeniedAceEx(
                            new_acl.as_mut_ptr() as *mut _ACL,
                            ACL_REVISION_DS,
                            ace.flags,
                            ace.mask.0,
                            psid,
                        )
                    }?;
                },
                AceType::SystemAudit => {
                    unsafe {
                        AddAuditAccessAceEx(
                            new_acl.as_mut_ptr() as *mut _ACL,
                            ACL_REVISION_DS,
                            ace.flags,
                            ace.mask.0,
                            psid,
                            false,
                            false,
                        )
                    }?;
                },
                AceType::SystemMandatoryLabel => {
                    unsafe {
                        AddMandatoryAce(
                            new_acl.as_mut_ptr() as *mut _ACL,
                            ACL_REVISION_DS,
                            ace.flags,
                            ace.mask.0,
                            psid,
                        )
                    }?;
                },
                _ => {
                    return Err(Error::empty());
                },
            };

        }

        if is_dacl {
            self.descriptor.set_dacl(new_acl)?;
        } else {
            self.descriptor.set_sacl(new_acl)?;
        }

        Ok(acl.len())
    }

    pub fn write( &mut self ) -> Result<()> {
        self.descriptor.write(
            &self.source,
            self.object_type.into()
        )
    }
}

impl Drop for ACL {
    fn drop(&mut self) {}
}
