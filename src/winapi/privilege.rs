//! Contains helper functions for converting between raw SID and SID string representations.

#![allow(non_snake_case)]

use std::{
    mem,
    ops::Drop,
};
use windows::{
    core::{
        Result, PWSTR
    },
    Win32::{
        Foundation::{
            CloseHandle, HANDLE, INVALID_HANDLE_VALUE
        }, 
        Security::{
            AdjustTokenPrivileges, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED, 
            TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_PRIVILEGES_ATTRIBUTES, TOKEN_QUERY, 
        }, 
        System::{
            Threading::{
                GetCurrentProcess, OpenProcessToken,
            },
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

        let result = (|| {
            unsafe {
                AdjustTokenPrivileges(
                    hToken,
                    false,
                    Some(&mut self.tkp),
                    0,
                    None,
                    None,
                )
            }
        })();

        let _ = unsafe { CloseHandle(hToken) };

        result
    }
}

impl Drop for SystemPrivilege {
    fn drop(&mut self) {
        let _ = self.release();
    }
}


