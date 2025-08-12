//! Contains the ACL introspection and manipulation functionality

#![allow(non_snake_case)]

use core::{
    mem::offset_of,
    ffi::c_void,
    ptr::{null_mut},
};
use crate::utils::{sid_to_string, SDSource, SecurityDescriptor, vec_as_psid};
use std::{
    fmt,
    mem,
};
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
                SE_DS_OBJECT, SE_DS_OBJECT_ALL, SE_FILE_OBJECT, SE_KERNEL_OBJECT, SE_LMSHARE, SE_OBJECT_TYPE,
                SE_PRINTER, SE_PROVIDER_DEFINED_OBJECT, SE_REGISTRY_KEY, SE_REGISTRY_WOW64_32KEY, SE_SERVICE,
                SE_UNKNOWN_OBJECT_TYPE, SE_WINDOW_OBJECT, SE_WMIGUID_OBJECT,
            },
            AddAccessAllowedAceEx, AddAccessDeniedAceEx, AddAce, AddAuditAccessAceEx, AddMandatoryAce,
            CopySid, EqualSid, GetAce, GetAclInformation, GetLengthSid, InitializeAcl, IsValidAcl,
            IsValidSid, AclSizeInformation, ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_CALLBACK_ACE,
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
            FILE_GENERIC_READ, FILE_GENERIC_EXECUTE, SYNCHRONIZE, FILE_ALL_ACCESS, FILE_ACCESS_RIGHTS,
        }
    },
};

use crate::{
    acl::acl_entry_size,
    utils::{as_pvoid_mut, as_ppvoid_mut},
    types::*,
    sid::SID,
};

/// `ACLEntry` represents a single access control entry in an access control list
#[derive(Clone, Debug, PartialEq)]
pub struct ACLEntry {
    /// The entry's type
    pub entry_type: AceType,

    /// See `AceSize` in [ACE_HEADER](https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_ace_header)
    pub size: u16,

    /// See `AceFlags` in [ACE_HEADER](https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_ace_header)
    pub flags: ACE_FLAGS,

    /// See [ACCESS_MASK](https://docs.microsoft.com/en-us/windows/desktop/secauthz/access-mask)
    pub mask: FILE_ACCESS_RIGHTS,

    /// The target entity's raw SID
    pub sid: SID,
}

#[allow(dead_code)]
impl ACLEntry {
    /// Returns an `ACLEntry` object with default values.
    #[inline]
    pub fn new() -> ACLEntry {
        ACLEntry {
            entry_type: AceType::Unknown,
            size: 0,
            flags: ACE_FLAGS(0),
            mask: FILE_ACCESS_RIGHTS(0),
            sid: SID::empty(),
        }
    }

    /// The target entity's SID in string representation
    pub fn string_sid(&self) -> Result<Option<String>> {
        self.sid.to_string()
    }

    pub(crate) fn psid(&self) -> Option<PSID> {
        self.sid.psid()
    }

    pub fn size(&self) -> Result<u32> {
        Self::calculate_entry_size( self.entry_type, &self.sid )
    }

    pub fn calculate_entry_size(entry_type: AceType, sid: &SID) -> Result<u32> {
        if sid.is_empty() {
            return Err(Error::empty());
        }
        
        let size = acl_entry_size(entry_type)? + sid.len() - (mem::size_of::<u32>() as u32);
        Ok(size)
    }
}

