//! Contains helper functions for converting between raw SID and SID string representations.

#![allow(non_snake_case)]

use core::fmt;
use std::{
    ffi::{c_void, OsStr},
    iter::once,
    mem,
    ops::Drop,
    os::windows::ffi::OsStrExt,
};
use windows::{
    core::{
        Error, Result, HRESULT, PWSTR
    },
    Win32::{
        Foundation::{
            CloseHandle, ERROR_INSUFFICIENT_BUFFER, HANDLE, INVALID_HANDLE_VALUE
        }, Security::{
            AddResourceAttributeAce, AdjustTokenPrivileges, LookupPrivilegeValueW, ACL as _ACL, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_PRIVILEGES_ATTRIBUTES, TOKEN_QUERY 
        }, System::{
            Threading::{
                GetCurrentProcess, OpenProcessToken,
            },
            WindowsProgramming::GetUserNameW,
        }
    },
};
use windows::{
    Win32::{
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
            ACL_REVISION_DS, ACL_SIZE_INFORMATION, CONTAINER_INHERIT_ACE,
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
            // FILE_ACCESS_RIGHTS,
        }
    },
};

use crate::utils::str_to_wstr;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct SystemPrivilege {
    tkp: TOKEN_PRIVILEGES,
}

impl SystemPrivilege {
    pub fn by_name(name: &str) -> Result<Self> {
        let mut tkp = unsafe { mem::zeroed::<TOKEN_PRIVILEGES>() };
        
        let mut wPrivilegeName: Vec<u16> = str_to_wstr(name);
        let wPrivilegeName = PWSTR(wPrivilegeName.as_mut_ptr() as *mut u16);

        unsafe {
            LookupPrivilegeValueW(
                PWSTR::null(),
                wPrivilegeName,
                &mut tkp.Privileges[0].Luid,
            )
        }?;

        tkp.PrivilegeCount = 1;

        Ok(Self {
            tkp
        })
    }

    pub fn acquire( &mut self ) -> Result<()> {
        self.adjust_privilege( true )
    }

    pub fn release(&mut self) -> Result<()> {
        self.adjust_privilege( false )
    }

    fn adjust_privilege( &mut self, enabled: bool ) -> Result<()> {

        if enabled {
            self.tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        } else {
            self.tkp.Privileges[0].Attributes = TOKEN_PRIVILEGES_ATTRIBUTES(0);
        }

        let mut hToken: HANDLE = INVALID_HANDLE_VALUE;
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut hToken,
            )
        }?;

        match unsafe {
            AdjustTokenPrivileges(
                hToken,
                false,
                Some(&mut self.tkp),
                0,
                None,
                None,
            )
        } {
            Ok(()) => {
                unsafe { CloseHandle(hToken) }?;
            },
            Err(e) => {
                let _ = unsafe { CloseHandle(hToken) };
                return Err(e);
            }
        };

        Ok(())
    }
}

impl Drop for SystemPrivilege {
    fn drop(&mut self) {
        self.release();
    }
}


