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
pub struct Privilege {
    tkp: TOKEN_PRIVILEGES,
    previous_tkp: TOKEN_PRIVILEGES,
    privilege_was_acquired: bool,
}

impl Privilege {
    pub fn by_name(name: &str) -> Result<Self> {
        let mut tkp = unsafe { mem::zeroed::<TOKEN_PRIVILEGES>() };
        let mut previous_tkp = unsafe { mem::zeroed::<TOKEN_PRIVILEGES>() };
        
        tkp.PrivilegeCount = 1;
        previous_tkp.PrivilegeCount = 1;

        let mut wPrivilegeName: Vec<u16> = str_to_wstr(name);
        let wPrivilegeName = PWSTR(wPrivilegeName.as_mut_ptr() as *mut u16);

        unsafe {
            LookupPrivilegeValueW(
                PWSTR::null(),
                wPrivilegeName,
                &mut tkp.Privileges[0].Luid,
            )
        }?;

        Ok(Self {
            tkp,
            previous_tkp,
            privilege_was_acquired: false,
        })
    }

    pub fn acquire( &mut self ) -> Result<()> {
        if self.privilege_was_acquired {
            unreachable!()
        }

        self.adjust_privilege( true )?;

        self.privilege_was_acquired = true;
        Ok(())
    }

    pub fn release(&mut self) -> Result<()> {
        if !self.privilege_was_acquired {
            unreachable!()
        }

        self.restore_privilege()?;

        self.privilege_was_acquired = false;
        Ok(())
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

        let mut previous_state_length: u32 = 0;

        match unsafe { 
            AdjustTokenPrivileges(
                hToken,
                false,
                Some(&mut self.tkp),
                mem::size_of_val(&self.previous_tkp) as u32,
                Some(&mut self.previous_tkp),
                Some(&mut previous_state_length),
            )
        } {
            Ok(()) => {},
            Err(e) => {
                let _ = unsafe { CloseHandle(hToken) };
                return Err(e);
            },
        };

        unsafe { CloseHandle(hToken) }?;

        Ok(())
    }

    fn restore_privilege( &mut self ) -> Result<()> {

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
                Some(&mut self.previous_tkp),
                0,
                None,
                None,
            )
        } {
            Ok(()) => {},
            Err(e) => {
                let _ = unsafe { CloseHandle(hToken) };
                return Err(e);
            },
        };

        unsafe { CloseHandle(hToken) }?;

        Ok(())
    }
}

impl Drop for Privilege {
    fn drop(&mut self) {
        if self.privilege_was_acquired {
            let _ = self.release();
        }
    }
}


