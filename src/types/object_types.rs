#![allow(non_snake_case)]

use windows::{
    Win32::{
        Security::Authorization::{
            SE_DS_OBJECT, SE_DS_OBJECT_ALL, SE_FILE_OBJECT, SE_KERNEL_OBJECT, SE_LMSHARE,
            SE_OBJECT_TYPE, SE_PRINTER, SE_PROVIDER_DEFINED_OBJECT, SE_REGISTRY_KEY,
            SE_REGISTRY_WOW64_32KEY, SE_SERVICE, SE_UNKNOWN_OBJECT_TYPE, SE_WINDOW_OBJECT,
            SE_WMIGUID_OBJECT,
        },
    },
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

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
