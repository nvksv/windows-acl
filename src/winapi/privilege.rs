//! Contains helper functions for converting between raw SID and SID string representations.

#![allow(non_snake_case)]

use std::{
    cell::LazyCell,
    mem,
    ops::Drop,
    ptr,
};
use windows::Win32::{
    Foundation::LUID,
    Security::{
        GetTokenInformation, TokenPrivileges,
        SE_ASSIGNPRIMARYTOKEN_NAME, SE_AUDIT_NAME,
        SE_BACKUP_NAME, SE_CHANGE_NOTIFY_NAME, SE_CREATE_GLOBAL_NAME, SE_CREATE_PAGEFILE_NAME,
        SE_CREATE_PERMANENT_NAME, SE_CREATE_SYMBOLIC_LINK_NAME, SE_CREATE_TOKEN_NAME,
        SE_DEBUG_NAME, SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME, SE_ENABLE_DELEGATION_NAME,
        SE_IMPERSONATE_NAME, SE_INCREASE_QUOTA_NAME, SE_INC_BASE_PRIORITY_NAME,
        SE_INC_WORKING_SET_NAME, SE_LOAD_DRIVER_NAME, SE_LOCK_MEMORY_NAME, SE_MACHINE_ACCOUNT_NAME,
        SE_MANAGE_VOLUME_NAME, SE_PROF_SINGLE_PROCESS_NAME, SE_RELABEL_NAME,
        SE_REMOTE_SHUTDOWN_NAME, SE_RESTORE_NAME, SE_SECURITY_NAME, SE_SHUTDOWN_NAME,
        SE_SYNC_AGENT_NAME, SE_SYSTEMTIME_NAME, SE_SYSTEM_ENVIRONMENT_NAME, SE_SYSTEM_PROFILE_NAME,
        SE_TAKE_OWNERSHIP_NAME, SE_TCB_NAME, SE_TIME_ZONE_NAME, SE_TRUSTED_CREDMAN_ACCESS_NAME,
        SE_UNDOCK_NAME, SE_UNSOLICITED_INPUT_NAME, 
    },
};
use windows::{
    core::{Error, Result, PCWSTR},
    Win32::{
        Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
        Security::{
            AdjustTokenPrivileges, LookupPrivilegeValueW,
            LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
            TOKEN_PRIVILEGES_ATTRIBUTES, TOKEN_QUERY,
        },
        System::{
            Threading::{GetCurrentProcess, OpenProcessToken},
        },
    },
};

use super::api::ErrorExt;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

macro_rules! privileges {
    ($({
        $name:expr,
        $luid:ident,
        $field_name: ident,
        $new_fn_name:ident,
        $with_fn_name:ident
    }),+) => {
        $(
            pub const $luid: LazyCell<Option<LUID>> = LazyCell::new(|| lookup_privilege_value($name));
        )+

        pub struct AvailablePrivileges {
            $(
                pub $field_name: Option<bool>,
            )+
        }

        impl Default for AvailablePrivileges {
            fn default() -> Self {
                Self {
                    $(
                        $field_name: None,
                    )+
                }
            }
        }

        impl Privilege {
            $(
                pub fn $new_fn_name() -> Result<Self> {
                    let mut tkp = unsafe { mem::zeroed::<TOKEN_PRIVILEGES>() };

                    tkp.PrivilegeCount = 1;
                    tkp.Privileges[0].Attributes    = TOKEN_PRIVILEGES_ATTRIBUTES(0);
                    tkp.Privileges[0].Luid          = $luid.ok_or_else(|| Error::empty())?;

                    Ok(Self {
                        tkp,
                        previous_tkp: unsafe { mem::zeroed::<TOKEN_PRIVILEGES>() },
                        privilege_was_acquired: false,
                    })
                }

                pub fn $with_fn_name<F, R, E>( f: F ) -> ::core::result::Result<R, E>
                where
                    F: FnOnce() -> ::core::result::Result<R, E>,
                    E: From<Error>,
                {
                    let mut privilege = Self::$new_fn_name()?;
                    privilege.acquire()?;

                    let result = f();

                    privilege.release()?;
                    result
                }
            )+

            pub fn get_avaliable() -> Result<AvailablePrivileges> {
                let h_current_process = unsafe { GetCurrentProcess() };
                let mut h_process_token: HANDLE = HANDLE(ptr::null_mut());

                unsafe {
                    OpenProcessToken(
                        h_current_process,
                        TOKEN_QUERY,
                        &mut h_process_token
                    )?;
                }

                let mut buffer_length: u32 = 0;

                match unsafe {
                    GetTokenInformation(
                        h_process_token,
                        TokenPrivileges,
                        None,
                        0,
                        &mut buffer_length,
                    )
                } {
                    Ok(_) => {
                        let _ = unsafe { CloseHandle(h_process_token) };
                        let _ = unsafe { CloseHandle(h_current_process) };
                        return Err(Error::empty());
                    },
                    Err(e) if e.is_insufficient_buffer() => {},
                    Err(e) => {
                        let _ = unsafe { CloseHandle(h_process_token) };
                        let _ = unsafe { CloseHandle(h_current_process) };
                        return Err(e);
                    },
                }

                let mut buffer = vec![0_u8; buffer_length as usize];

                match unsafe {
                    GetTokenInformation(
                        h_process_token,
                        TokenPrivileges,
                        Some(buffer.as_mut_ptr() as *mut _),
                        buffer_length,
                        &mut buffer_length,
                    )
                } {
                    Ok(_) => {},
                    Err(e) => {
                        let _ = unsafe { CloseHandle(h_process_token) };
                        let _ = unsafe { CloseHandle(h_current_process) };
                        return Err(e);
                    },
                }

                let token_privileges = unsafe { &*(buffer.as_ptr() as *const TOKEN_PRIVILEGES) };

                let _ = unsafe { CloseHandle(h_process_token) };
                let _ = unsafe { CloseHandle(h_current_process) };

                //

                let privileges_count = token_privileges.PrivilegeCount;
                let luid_and_attributes = &token_privileges.Privileges[0] as *const LUID_AND_ATTRIBUTES;

                let mut available_privileges = AvailablePrivileges::default();

                for i in 0..privileges_count {
                    let data = unsafe { &* luid_and_attributes.offset(i as isize) };

                    match data.Luid {
                        $(
                            luid if *$luid == Some(luid) => {
                                let enabled = (data.Attributes & SE_PRIVILEGE_ENABLED == SE_PRIVILEGE_ENABLED);
                                available_privileges.$field_name = Some(enabled);
                            },
                        )+
                        _ => {},
                    }
                }

                Ok(available_privileges)
            }
        }
    };
}

privileges!(
    {
        SE_ASSIGNPRIMARYTOKEN_NAME,
        SE_ASSIGNPRIMARYTOKEN_LUID,
        assign_primary_token,
        new_assign_primary_token,
        with_assign_primary_token
    },
    {
        SE_AUDIT_NAME,
        SE_AUDIT_LUID,
        audit,
        new_audit,
        with_audit
    },
    {
        SE_BACKUP_NAME,
        SE_BACKUP_LUID,
        backup,
        new_backup,
        with_backup
    },
    {
        SE_CHANGE_NOTIFY_NAME,
        SE_CHANGE_NOTIFY_LUID,
        change_notify,
        new_change_notify,
        with_change_notify
    },
    {
        SE_CREATE_GLOBAL_NAME,
        SE_CREATE_GLOBAL_LUID,
        create_global,
        new_create_global,
        with_create_global
    },
    {
        SE_CREATE_PAGEFILE_NAME,
        SE_CREATE_PAGEFILE_LUID,
        create_pagefile,
        new_create_pagefile,
        with_create_pagefile
    },
    {
        SE_CREATE_PERMANENT_NAME,
        SE_CREATE_PERMANENT_LUID,
        create_permanent,
        new_create_permanent,
        with_create_permanent
    },
    {
        SE_CREATE_SYMBOLIC_LINK_NAME,
        SE_CREATE_SYMBOLIC_LINK_LUID,
        create_symbolic_link,
        new_create_symbolic_link,
        with_create_symbolic_link
    },
    {
        SE_CREATE_TOKEN_NAME,
        SE_CREATE_TOKEN_LUID,
        create_token,
        new_create_token,
        with_create_token
    },
    {
        SE_DEBUG_NAME,
        SE_DEBUG_LUID,
        debug,
        new_debug,
        with_debug
    },
    {
        SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME,
        SE_DELEGATE_SESSION_USER_IMPERSONATE_LUID,
        delegate_session_user_impersonate,
        new_delegate_session_user_impersonate,
        with_delegate_session_user_impersonate
    },
    {
        SE_ENABLE_DELEGATION_NAME,
        SE_ENABLE_DELEGATION_LUID,
        enable_delegation,
        new_enable_delegation,
        with_enable_delegation
    },
    {
        SE_IMPERSONATE_NAME,
        SE_IMPERSONATE_LUID,
        impersonate,
        new_impersonate,
        with_impersonate
    },
    {
        SE_INC_BASE_PRIORITY_NAME,
        SE_INC_BASE_PRIORITY_LUID,
        increase_base_priority,
        new_increase_base_priority,
        with_increase_base_priority
    },
    {
        SE_INCREASE_QUOTA_NAME,
        SE_INCREASE_QUOTA_LUID,
        increase_quota,
        new_increase_quota,
        with_increase_quota
    },
    {
        SE_INC_WORKING_SET_NAME,
        SE_INC_WORKING_SET_LUID,
        increase_working_set,
        new_increase_working_set,
        with_increase_working_set
    },
    {
        SE_LOAD_DRIVER_NAME,
        SE_LOAD_DRIVER_LUID,
        load_driver,
        new_load_driver,
        with_load_driver
    },
    {
        SE_LOCK_MEMORY_NAME,
        SE_LOCK_MEMORY_LUID,
        lock_memory,
        new_lock_memory,
        with_lock_memory
    },
    {
        SE_MACHINE_ACCOUNT_NAME,
        SE_MACHINE_ACCOUNT_LUID,
        machine_account,
        new_machine_account,
        with_machine_account
    },
    {
        SE_MANAGE_VOLUME_NAME,
        SE_MANAGE_VOLUME_LUID,
        manage_volume,
        new_manage_volume,
        with_manage_volume
    },
    {
        SE_PROF_SINGLE_PROCESS_NAME,
        SE_PROF_SINGLE_PROCESS_LUID,
        profile_single_process,
        new_profile_single_process,
        with_profile_single_process
    },
    {
        SE_RELABEL_NAME,
        SE_RELABEL_LUID,
        relabel,
        new_relabel,
        with_relabel
    },
    {
        SE_REMOTE_SHUTDOWN_NAME,
        SE_REMOTE_SHUTDOWN_LUID,
        remote_shutdown,
        new_remote_shutdown,
        with_remote_shutdown
    },
    {
        SE_RESTORE_NAME,
        SE_RESTORE_LUID,
        restore,
        new_restore,
        with_restore
    },
    {
        SE_SECURITY_NAME,
        SE_SECURITY_LUID,
        security,
        new_security,
        with_security
    },
    {
        SE_SHUTDOWN_NAME,
        SE_SHUTDOWN_LUID,
        shutdown,
        new_shutdown,
        with_shutdown
    },
    {
        SE_SYNC_AGENT_NAME,
        SE_SYNC_AGENT_LUID,
        sync_agent,
        new_sync_agent,
        with_sync_agent
    },
    {
        SE_SYSTEM_ENVIRONMENT_NAME,
        SE_SYSTEM_ENVIRONMENT_LUID,
        system_environment,
        new_system_environment,
        with_system_environment
    },
    {
        SE_SYSTEM_PROFILE_NAME,
        SE_SYSTEM_PROFILE_LUID,
        system_profile,
        new_system_profile,
        with_system_profile
    },
    {
        SE_SYSTEMTIME_NAME,
        SE_SYSTEMTIME_LUID,
        systemtime,
        new_systemtime,
        with_systemtime
    },
    {
        SE_TAKE_OWNERSHIP_NAME,
        SE_TAKE_OWNERSHIP_LUID,
        take_ownership,
        new_take_ownership,
        with_take_ownership
    },
    {
        SE_TCB_NAME,
        SE_TCB_LUID,
        tcb,
        new_tcb,
        with_tcb
    },
    {
        SE_TIME_ZONE_NAME,
        SE_TIME_ZONE_LUID,
        time_zone,
        new_time_zone,
        with_time_zone
    },
    {
        SE_TRUSTED_CREDMAN_ACCESS_NAME,
        SE_TRUSTED_CREDMAN_ACCESS_LUID,
        trusted_credman_access,
        new_trusted_credman_access,
        with_trusted_credman_access
    },
    {
        SE_UNDOCK_NAME,
        SE_UNDOCK_LUID,
        undock,
        new_undock,
        with_undock
    },
    {
        SE_UNSOLICITED_INPUT_NAME,
        SE_UNSOLICITED_INPUT_LUID,
        unsolicited_input,
        new_unsolicited_input,
        with_unsolicited_input
    }
);

fn lookup_privilege_value(privilege_name: PCWSTR) -> Option<LUID> {
    let mut privilege_luid = LUID::default();

    unsafe { LookupPrivilegeValueW(PCWSTR::null(), privilege_name, &mut privilege_luid) }.ok()?;

    Some(privilege_luid)
}

fn get_privilege_enabled_tkp(privilege_luid: LUID) -> TOKEN_PRIVILEGES {
    let mut tkp = unsafe { mem::zeroed::<TOKEN_PRIVILEGES>() };

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    tkp.Privileges[0].Luid = privilege_luid;

    tkp
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct Privilege {
    tkp: TOKEN_PRIVILEGES,
    previous_tkp: TOKEN_PRIVILEGES,
    privilege_was_acquired: bool,
}

impl Privilege {
    // pub fn by_name(name: &str) -> Result<Self> {
    //     let mut tkp = unsafe { mem::zeroed::<TOKEN_PRIVILEGES>() };
    //     let mut previous_tkp = unsafe { mem::zeroed::<TOKEN_PRIVILEGES>() };

    //     tkp.PrivilegeCount = 1;
    //     previous_tkp.PrivilegeCount = 1;

    //     let mut wPrivilegeName: Vec<u16> = str_to_wstr(name);
    //     let wPrivilegeName = PWSTR(wPrivilegeName.as_mut_ptr() as *mut u16);

    //     unsafe {
    //         LookupPrivilegeValueW(
    //             PWSTR::null(),
    //             wPrivilegeName,
    //             &mut tkp.Privileges[0].Luid,
    //         )
    //     }?;

    //     Ok(Self {
    //         tkp,
    //         previous_tkp,
    //         privilege_was_acquired: false,
    //     })
    // }

    pub fn acquire(&mut self) -> Result<()> {
        if self.privilege_was_acquired {
            unreachable!()
        }

        self.adjust_privilege(true)?;

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

    fn adjust_privilege(&mut self, enabled: bool) -> Result<()> {
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
            Ok(()) => {}
            Err(e) => {
                let _ = unsafe { CloseHandle(hToken) };
                return Err(e);
            }
        };

        unsafe { CloseHandle(hToken) }?;

        Ok(())
    }

    fn restore_privilege(&mut self) -> Result<()> {
        let mut hToken: HANDLE = INVALID_HANDLE_VALUE;
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut hToken,
            )
        }?;

        match unsafe {
            AdjustTokenPrivileges(hToken, false, Some(&mut self.previous_tkp), 0, None, None)
        } {
            Ok(()) => {}
            Err(e) => {
                let _ = unsafe { CloseHandle(hToken) };
                return Err(e);
            }
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
