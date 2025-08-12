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

/// This enum is almost a direct mapping with the values described in
/// [SE_OBJECT_TYPE](https://docs.microsoft.com/en-us/windows/desktop/api/accctrl/ne-accctrl-_se_object_type)
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ObjectType {
    Unknown = 0,
    FileObject,
    ServiceObject,
    PrinterObject,
    RegistryKey,
    LmShare,
    KernelObject,
    WindowObject,
    DsObject,
    DsObjectAll,
    ProviderDefinedObject,
    WmiGuidObject,
    RegistryWow6432Key,
}

impl From<ObjectType> for SE_OBJECT_TYPE {
    fn from(obj_type: ObjectType) -> Self {
        match obj_type {
            ObjectType::FileObject => SE_FILE_OBJECT,
            ObjectType::ServiceObject => SE_SERVICE,
            ObjectType::PrinterObject => SE_PRINTER,
            ObjectType::RegistryKey => SE_REGISTRY_KEY,
            ObjectType::LmShare => SE_LMSHARE,
            ObjectType::KernelObject => SE_KERNEL_OBJECT,
            ObjectType::WindowObject => SE_WINDOW_OBJECT,
            ObjectType::DsObject => SE_DS_OBJECT,
            ObjectType::DsObjectAll => SE_DS_OBJECT_ALL,
            ObjectType::ProviderDefinedObject => SE_PROVIDER_DEFINED_OBJECT,
            ObjectType::WmiGuidObject => SE_WMIGUID_OBJECT,
            ObjectType::RegistryWow6432Key => SE_REGISTRY_WOW64_32KEY,
            _ => SE_UNKNOWN_OBJECT_TYPE,
        }
    }
}

impl From<SE_OBJECT_TYPE> for ObjectType {
    fn from(obj_type: SE_OBJECT_TYPE) -> Self {
        match obj_type {
            SE_FILE_OBJECT => ObjectType::FileObject,
            SE_SERVICE => ObjectType::ServiceObject,
            SE_PRINTER => ObjectType::PrinterObject,
            SE_REGISTRY_KEY => ObjectType::RegistryKey,
            SE_LMSHARE => ObjectType::LmShare,
            SE_KERNEL_OBJECT => ObjectType::KernelObject,
            SE_WINDOW_OBJECT => ObjectType::WindowObject,
            SE_DS_OBJECT => ObjectType::DsObject,
            SE_DS_OBJECT_ALL => ObjectType::DsObjectAll,
            SE_PROVIDER_DEFINED_OBJECT => ObjectType::ProviderDefinedObject,
            SE_WMIGUID_OBJECT => ObjectType::WmiGuidObject,
            SE_REGISTRY_WOW64_32KEY => ObjectType::RegistryWow6432Key,
            _ => ObjectType::Unknown,
        }
    }
}

/// This enum is a almost direct mapping with the values described under `AceType` in
/// [ACE_HEADER](https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_ace_header)
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AceType {
    Unknown = 0,
    AccessAllow = 1,
    AccessAllowCallback,
    AccessAllowObject,
    AccessAllowCallbackObject,
    AccessDeny = 5,
    AccessDenyCallback,
    AccessDenyObject,
    AccessDenyCallbackObject,
    SystemAudit = 9,
    SystemAuditCallback,
    SystemAuditObject,
    SystemAuditCallbackObject,
    SystemMandatoryLabel = 13,
    SystemResourceAttribute,
}


// const ACCESS_MIN_MS_ACE_TYPE: u8                  = 0x0;
// const ACCESS_ALLOWED_ACE_TYPE: u8                 = 0x0;
// const ACCESS_DENIED_ACE_TYPE: u8                  = 0x1;
// const SYSTEM_AUDIT_ACE_TYPE: u8                   = 0x2;
// const SYSTEM_ALARM_ACE_TYPE: u8                   = 0x3;
// const ACCESS_MAX_MS_V2_ACE_TYPE: u8               = 0x3;

// const ACCESS_ALLOWED_COMPOUND_ACE_TYPE: u8        = 0x4;
// const ACCESS_MAX_MS_V3_ACE_TYPE: u8               = 0x4;

// const ACCESS_MIN_MS_OBJECT_ACE_TYPE: u8           = 0x5;
// const ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8          = 0x5;
// const ACCESS_DENIED_OBJECT_ACE_TYPE: u8           = 0x6;
// const SYSTEM_AUDIT_OBJECT_ACE_TYPE: u8            = 0x7;
// const SYSTEM_ALARM_OBJECT_ACE_TYPE: u8            = 0x8;
// const ACCESS_MAX_MS_OBJECT_ACE_TYPE: u8           = 0x8;

// const ACCESS_MAX_MS_V4_ACE_TYPE: u8               = 0x8;
// const ACCESS_MAX_MS_ACE_TYPE: u8                  = 0x8;

// const ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8        = 0x9;
// const ACCESS_DENIED_CALLBACK_ACE_TYPE: u8         = 0xA;
// const ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE: u8 = 0xB;
// const ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE: u8  = 0xC;
// const SYSTEM_AUDIT_CALLBACK_ACE_TYPE: u8          = 0xD;
// const SYSTEM_ALARM_CALLBACK_ACE_TYPE: u8          = 0xE;
// const SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE: u8   = 0xF;
// const SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE: u8   = 0x10;

// const SYSTEM_MANDATORY_LABEL_ACE_TYPE: u8         = 0x11;
// const SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE: u8      = 0x12;
// const SYSTEM_SCOPED_POLICY_ID_ACE_TYPE: u8        = 0x13;
// const SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE: u8     = 0x14;
// const SYSTEM_ACCESS_FILTER_ACE_TYPE: u8           = 0x15;
// const ACCESS_MAX_MS_V5_ACE_TYPE: u8               = 0x15;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SidType {
    User = 1,
    Group,
    Domain,
    Alias,
    WellKnownGroup,
    DeletedAccount,
    Invalid,
    Unknown,
    Computer,
    Label,
    LogonSession
}