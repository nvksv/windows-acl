#![allow(non_snake_case)]

// use core::{default, fmt, ops};
// use windows::{
//     core::Result,
//     Win32::{
//         Security::Authorization::{
//             SE_DS_OBJECT, SE_DS_OBJECT_ALL, SE_FILE_OBJECT, SE_KERNEL_OBJECT, SE_LMSHARE,
//             SE_OBJECT_TYPE, SE_PRINTER, SE_PROVIDER_DEFINED_OBJECT, SE_REGISTRY_KEY,
//             SE_REGISTRY_WOW64_32KEY, SE_SERVICE, SE_UNKNOWN_OBJECT_TYPE, SE_WINDOW_OBJECT,
//             SE_WMIGUID_OBJECT,
//         },
//         Storage::FileSystem::{
//             DELETE, FILE_ACCESS_RIGHTS, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_APPEND_DATA,
//             FILE_DELETE_CHILD, FILE_EXECUTE, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ,
//             FILE_GENERIC_WRITE, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_READ_DATA,
//             FILE_READ_EA, FILE_TRAVERSE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA,
//             READ_CONTROL, SPECIFIC_RIGHTS_ALL, STANDARD_RIGHTS_ALL, STANDARD_RIGHTS_EXECUTE,
//             STANDARD_RIGHTS_READ, STANDARD_RIGHTS_REQUIRED, STANDARD_RIGHTS_WRITE, SYNCHRONIZE,
//             WRITE_DAC, WRITE_OWNER,
//         },
//     },
// };

// use crate::utils::DebugIdent;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

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
    LogonSession,
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
