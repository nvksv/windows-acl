#![cfg(windows)]

use crate::{
    utils::current_user_account_name, ACLEntry, ACLKind, AceType, ACL, SID, VSID, ACLEntryIterator, ACLEntryMask, ACCESS_MASK,
};
use std::{
    env::current_exe,
    fs::{File, OpenOptions},
    os::windows::{
        fs::OpenOptionsExt,
        io::AsRawHandle,
    },
    path::PathBuf,
    process::Command,
};
use core::ffi::c_void;
use windows::{
    core::{
        Error, Result, HRESULT,
    },
    Win32::{
        Foundation::{
            GENERIC_READ, GENERIC_WRITE, HANDLE, ERROR_NOT_ALL_ASSIGNED,
        }, Security::{
            AclSizeInformation, AddAccessAllowedAceEx, AddAccessDeniedAceEx, AddAce, AddAuditAccessAceEx, AddMandatoryAce, Authorization::{
                SE_DS_OBJECT, SE_DS_OBJECT_ALL, SE_FILE_OBJECT, SE_KERNEL_OBJECT, SE_LMSHARE, SE_OBJECT_TYPE,
                SE_PRINTER, SE_PROVIDER_DEFINED_OBJECT, SE_REGISTRY_KEY, SE_REGISTRY_WOW64_32KEY, SE_SERVICE,
                SE_UNKNOWN_OBJECT_TYPE, SE_WINDOW_OBJECT, SE_WMIGUID_OBJECT,
            }, CopySid, EqualSid, GetAce, GetAclInformation, GetLengthSid, InitializeAcl, IsValidAcl, IsValidSid, ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_CALLBACK_ACE, ACCESS_ALLOWED_CALLBACK_OBJECT_ACE, ACCESS_ALLOWED_OBJECT_ACE, ACCESS_DENIED_ACE, ACCESS_DENIED_CALLBACK_ACE, ACCESS_DENIED_CALLBACK_OBJECT_ACE, ACCESS_DENIED_OBJECT_ACE, ACE_FLAGS, ACE_HEADER, ACL as _ACL, ACL_REVISION_DS, ACL_SIZE_INFORMATION, CONTAINER_INHERIT_ACE, FAILED_ACCESS_ACE_FLAG, INHERITED_ACE, OBJECT_INHERIT_ACE, PSID, SUCCESSFUL_ACCESS_ACE_FLAG, SYSTEM_AUDIT_ACE, SYSTEM_AUDIT_CALLBACK_ACE, SYSTEM_AUDIT_CALLBACK_OBJECT_ACE, SYSTEM_AUDIT_OBJECT_ACE, SYSTEM_MANDATORY_LABEL_ACE, SYSTEM_RESOURCE_ATTRIBUTE_ACE, WELL_KNOWN_SID_TYPE, SECURITY_WORLD_SID_AUTHORITY, WinAccountGuestSid, WinWorldSid,
        }, Storage::FileSystem::{
            FILE_ACCESS_RIGHTS, FILE_ALL_ACCESS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, SYNCHRONIZE, WRITE_DAC
        }, System::SystemServices::{
            ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, ACCESS_DENIED_CALLBACK_ACE_TYPE, ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_DENIED_OBJECT_ACE_TYPE, DOMAIN_USER_RID_GUEST, MAXDWORD, SYSTEM_AUDIT_ACE_TYPE, SYSTEM_AUDIT_CALLBACK_ACE_TYPE, SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE, SYSTEM_AUDIT_OBJECT_ACE_TYPE, SYSTEM_MANDATORY_LABEL_ACE_TYPE, SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP, SYSTEM_MANDATORY_LABEL_NO_READ_UP, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE, SECURITY_WORLD_RID, DOMAIN_USER_RID_ADMIN, DOMAIN_GROUP_RID_USERS,
        }
    },
};

fn support_path() -> Option<PathBuf> {
    if let Ok(mut path) = current_exe() {
        for _ in 0..6 {
            path.pop();

            path.push("support");

            if path.exists() {
                path.push("testfiles");
                return Some(path);
            }

            path.pop();
        }
    } else {
        assert!(false, "current_exe failed");
    }

    None
}

fn run_ps_script(file_name: &str) -> bool {
    if let Some(mut path) = support_path() {
        path.pop();
        path.push(file_name);

        if let Some(script_path) = path.to_str() {
            let mut process = match Command::new("PowerShell.exe")
                .args(["-ExecutionPolicy", "bypass", "-File", script_path])
                .spawn()
            {
                Ok(process) => process,
                _ => {
                    return false;
                }
            };

            return match process.wait() {
                Ok(_code) => true,
                Err(_code) => false,
            };
        }
    }

    false
}

fn string_sid_by_user(user: &str) -> String {
    let user_sid = SID::from_account_name(user, None).unwrap();
    let user_string_sid = user_sid.to_string().unwrap();

    user_string_sid
}

fn current_user_string_sid() -> String {
    let username = current_user_account_name().unwrap();

    string_sid_by_user(&username)
}

// #[test]
// fn lookupname_unit_test() {
//     let sids = SIDs::new();

//     // let world_name = "Everyone";
//     let world_string_sid = "S-1-1-0";

//     let raw_world_sid = SID::from_account_name(world_name, None).unwrap();
//     assert_eq!(&raw_world_sid, &sids.world);

//     let sid_string = raw_world_sid.to_string().unwrap();
//     assert_eq!(sid_string, world_string_sid);
// }

#[test]
fn sidstring_unit_test() {
    let world_string_sid = "S-1-5-21";

    let sid = SID::from_str(world_string_sid).unwrap();

    let sid_string = sid.to_string().unwrap();
    assert_eq!(sid_string, world_string_sid);
}

fn acl_entry_exists<'r, 'e, K: ACLKind>(entries: &Vec<ACLEntry<'r, K>>, expected: &ACLEntry<'e, K>) -> Option<usize> {
    println!("entries = {:?}", entries);
    println!("expected = {:?}", expected);

    for i in 0..(entries.len()) {
        let entry = &entries[i];

        if entry == expected {
            return Some(i);
        }
    }

    None
}

struct SIDs {
    current_user: SID,
    current_domain: SID,
    guest: SID,
    world: SID,
}

impl SIDs {
    fn new() -> Self {
        let current_user = SID::current_user().unwrap();
        let current_domain = current_user.get_domain_of().unwrap(); 
        let guest = SID::well_known( WinAccountGuestSid, Some(&current_domain) ).unwrap();
        let world = SID::well_known( WinWorldSid, None ).unwrap();

        assert_eq!( world.to_string().unwrap(), "S-1-1-0" );

        Self {
            current_user,
            current_domain,
            guest,
            world,
        }
    }
}

// Make sure we can read DACL entries set by an external tool (PowerShell)
#[test]
fn query_dacl_unit_test() {
    let sids = SIDs::new();

    let mut path_obj = support_path().unwrap_or_default();
    path_obj.push("query_test");
    assert!(path_obj.exists());

    let path = path_obj.to_str().unwrap();

    let acl_result = ACL::from_file_path(path, false);
    assert!(acl_result.is_ok());

    let acl = acl_result.unwrap();
    let entries = acl.dacl().all().unwrap();
    assert_ne!(entries.len(), 0);

    let expected = ACLEntry::new_deny(
        sids.guest.to_vsid().unwrap(),
        ACE_FLAGS(0),
        ((FILE_GENERIC_READ | FILE_GENERIC_EXECUTE) & !SYNCHRONIZE).into(),
    );

    let deny_idx = match acl_entry_exists(&entries, &expected) {
        Some(i) => i,
        None => {
            println!("Expected AccessDeny entry does not exist!");
            assert!(false);
            return;
        }
    };

    //

    let expected = ACLEntry::new_allow(
        sids.guest.to_vsid().unwrap(),
        ACE_FLAGS(0),
        ((FILE_GENERIC_READ | FILE_GENERIC_EXECUTE) & !SYNCHRONIZE).into(),
    );

    // // NOTE(andy): For ACL entries added by CmdLets on files, SYNCHRONIZE is not set
    // expected.access_mask = FILE_ALL_ACCESS.into();

    let allow_idx = match acl_entry_exists(&entries, &expected) {
        Some(i) => i,
        None => {
            println!("Expected AccessAllow entry does not exist!");
            assert!(false);
            return;
        }
    };

    assert!(deny_idx < allow_idx);
}

// Make sure we can read SACL entries set by external tools (PowerShell/.NET)
#[test]
fn query_sacl_unit_test() {
    let sids = SIDs::new();

    let mut path_obj = support_path().unwrap();
    path_obj.push("query_sacl_test");
    assert!(path_obj.exists());

    let path = path_obj.to_str().unwrap();

    let acl = match ACL::from_file_path(path, true) {
        Ok(obj) => obj,
        Err(err) => {
            assert_eq!(err.code(), ERROR_NOT_ALL_ASSIGNED.into());
            println!("INFO: Terminating query_sacl_unit_test early because we are not Admin.");
            return;
        }
    };

    let entries = acl.sacl().all().unwrap();
    assert_ne!(entries.len(), 0);

    let expected = ACLEntry::new_audit(
        sids.world.to_vsid().unwrap(),
        SUCCESSFUL_ACCESS_ACE_FLAG | FAILED_ACCESS_ACE_FLAG,
        ((FILE_GENERIC_READ | FILE_GENERIC_WRITE) & !SYNCHRONIZE).into(),
    );

    let allow_idx = match acl_entry_exists(&entries, &expected) {
        Some(i) => i,
        None => {
            println!("Expected SystemAudit entry does not exist!");
            assert!(false);
            return;
        }
    };

    // assert!(allow_idx > 0);
}


// Ensure that we can add and remove DACL access allow entries
fn add_and_remove_dacl_allow(use_handle: bool) {
    let sids = SIDs::new();

    let mut path_obj = support_path().unwrap();
    path_obj.push(if use_handle {
        "dacl_allow_handle"
    } else {
        "dacl_allow_file"
    });
    assert!(path_obj.exists());

    let path = path_obj.to_str().unwrap();

    // NOTE(andy): create() opens for write only or creates new if path doesn't exist. Since we know
    //             that the path exists (see line 289), this will attempt to open for write, which
    //             should fail
    // NOTE(nvksv): create() successfully opens existing file, so assert always fail
    //              ("will create a file if it does not exist, and will truncate it if it does" --
    //              https://doc.rust-lang.org/std/fs/struct.File.html#method.create )
    //assert!(File::create(path).is_err());
    let file: File;

    let mut acl = if use_handle {
        file = OpenOptions::new()
            .access_mode(GENERIC_READ.0 | WRITE_DAC.0 )
            .open(path)
            .unwrap();
        ACL::from_file_raw_handle(file.as_raw_handle(), false).unwrap()
    } else {
        ACL::from_file_path(path, false).unwrap()
    };

    acl.update_dacl(|dacl| {
        dacl.add_allow(
            sids.current_user.to_vsid().unwrap(),
            ACE_FLAGS(0),
            (FILE_GENERIC_READ | FILE_GENERIC_WRITE).into(),
            None,
        )
    }).unwrap();

    acl.write().unwrap();

    // NOTE(andy): Our explicit allow entry should make this pass now
    assert!(File::create(path).is_ok());

    let mut entries = acl.dacl().all().unwrap();
    assert_ne!(entries.len(), 0);

    let expected = ACLEntry::new_allow(
        sids.current_user.to_vsid().unwrap(),
        ACE_FLAGS(0),
        (FILE_GENERIC_READ | FILE_GENERIC_WRITE).into(),
    );

    match acl_entry_exists(&entries, &expected) {
        Some(_i) => {}
        None => {
            println!("Expected AccessAllow entry does not exist!");
            assert!(false);
            return;
        }
    };

    acl.update_dacl(|dacl| {
        dacl.remove(
            sids.current_user.as_ref().unwrap(),
            Some(ACLEntryMask::new().set_entry_type(AceType::AccessAllow)),
        )
    }).unwrap();

    // assert!(File::create(path).is_err());

    entries = acl.dacl().all().unwrap();
    match acl_entry_exists(&entries, &expected) {
        None => {}
        Some(i) => {
            println!("Did not expect to find AccessAllow entry at {}", i);
            assert!(false);
        }
    }
}

#[test]
fn add_and_remove_dacl_allow_path_test() {
    add_and_remove_dacl_allow(false);
}

#[test]
fn add_and_remove_dacl_allow_handle_test() {
    add_and_remove_dacl_allow(true);
}

// Ensure we can add and remove DACL access deny entries
fn add_and_remove_dacl_deny(use_handle: bool) {
    let sids = SIDs::new();

    let mut path_obj = support_path().unwrap_or_default();
    path_obj.push(if use_handle {
        "dacl_deny_handle"
    } else {
        "dacl_deny_file"
    });
    assert!(path_obj.exists());

    let path = path_obj.to_str().unwrap_or("");
    assert_ne!(path.len(), 0);

    // NOTE(andy): create() opens for write only or creates new if path doesn't exist. Since we know
    //             that the path exists (see line 375), this will attempt to open for write, which
    //             should succeed
    let create_res = OpenOptions::new()
        .access_mode((GENERIC_WRITE.0 | WRITE_DAC.0) )
        .open(path);
    assert!(create_res.is_ok());
    let file = create_res.unwrap();

    let mut acl = if use_handle {
        ACL::from_file_raw_handle(file.as_raw_handle(), false).unwrap()
    } else {
        ACL::from_file_path(path, false).unwrap()
    };

    acl.update_dacl(|dacl| {
        dacl.add_deny(
            sids.current_user.to_vsid().unwrap(), 
            ACE_FLAGS(0), 
            FILE_GENERIC_WRITE.into(),
            None
        ) 
    }).unwrap();
        

    // NOTE(andy): Since we added a deny entry for WRITE, this should fail
    assert!(File::create(path).is_err());

    let mut entries = acl.dacl().all().unwrap();
    assert_ne!(entries.len(), 0);

    let expected = ACLEntry::new_deny(
        sids.current_user.to_vsid().unwrap(),
        ACE_FLAGS(0),
        FILE_GENERIC_WRITE.into(),
    );

    match acl_entry_exists(&entries, &expected) {
        Some(_i) => {}
        None => {
            println!("Expected AccessDeny entry does not exist!");
            assert!(false);
            return;
        }
    }

    acl.update_dacl(|dacl| {
        dacl.remove(
            sids.current_user.as_ref().unwrap(),
            Some(ACLEntryMask::new().set_entry_type(AceType::AccessDeny)),
        )
    }).unwrap();

    assert!(File::open(path).is_ok());

    entries = acl.dacl().all().unwrap_or(Vec::new());
    assert_ne!(entries.len(), 0);

    match acl_entry_exists(&entries, &expected) {
        None => {}
        Some(i) => {
            println!("AccessDeny unexpectedly exists at {}", i);
            assert!(false);
        }
    }
}

#[test]
fn add_and_remove_dacl_deny_path_test() {
    add_and_remove_dacl_deny(false);
}

#[test]
fn add_and_remove_dacl_deny_handle_test() {
    add_and_remove_dacl_deny(true);
}

// Ensure we can add and remove a SACL mandatory level entry
#[test]
fn add_remove_sacl_mil() {
    let low_mil_sid = SID::from_str("S-1-16-4096").unwrap();

    let mut path_obj = support_path().unwrap_or_default();
    path_obj.push("sacl_mil_file");
    assert!(path_obj.exists());

    let path = path_obj.to_str().unwrap_or("");
    assert_ne!(path.len(), 0);

    let mut acl = ACL::from_file_path(path, true).unwrap();

    acl.update_sacl(|sacl| {
        sacl.add_mandatory_label(
            low_mil_sid.to_vsid().unwrap(),
            ACE_FLAGS(0),
            ACCESS_MASK(SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | SYSTEM_MANDATORY_LABEL_NO_READ_UP | SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP),
            None
        )
    }).unwrap();

    let mut entries = acl.sacl().all().unwrap_or_default();
    assert_ne!(entries.len(), 0);

    let expected = ACLEntry::new_mandatory_label(
        low_mil_sid.to_vsid().unwrap(),
        ACE_FLAGS(0),
        ACCESS_MASK(SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | SYSTEM_MANDATORY_LABEL_NO_READ_UP | SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP)
    );

    assert!(acl_entry_exists(&entries, &expected).is_some());

    acl.update_sacl(|sacl| {
        sacl.remove(
            low_mil_sid.as_ref().unwrap(),
            Some(ACLEntryMask::new().set_entry_type(AceType::SystemMandatoryLabel))
        )
    }).unwrap();

    entries = acl.sacl().all().unwrap();

    assert!(acl_entry_exists(&entries, &expected).is_none());
}

// Make sure we can add and remove a SACL audit entry
#[test]
fn add_remove_sacl_audit() {
    let sids = SIDs::new();

    let mut path_obj = support_path().unwrap_or_default();
    path_obj.push("sacl_audit_file");
    assert!(path_obj.exists());

    let path = path_obj.to_str().unwrap_or("");
    assert_ne!(path.len(), 0);

    let mut acl = ACL::from_file_path(path, true).unwrap();
    acl.update_sacl(|sacl| {
        sacl.add_audit(
            sids.current_user.to_vsid().unwrap(),
            ACE_FLAGS(0),
            FILE_GENERIC_READ.into(),
            None
        )
    }).unwrap();

    let mut entries = acl.sacl().all().unwrap_or_default();
    assert_ne!(entries.len(), 0);

    let mut expected = ACLEntry::new_audit(
        sids.current_user.to_vsid().unwrap(),
        ACE_FLAGS((SUCCESSFUL_ACCESS_ACE_FLAG | FAILED_ACCESS_ACE_FLAG).0),
        FILE_GENERIC_READ.into()
    );

    assert!(acl_entry_exists(&entries, &expected).is_some());

    acl.update_sacl(|sacl| {
        sacl.remove(
            sids.current_user.as_ref().unwrap(), 
            None
        )
    }).unwrap();

    entries = acl.sacl().all().unwrap();

    assert!(acl_entry_exists(&entries, &expected).is_none());
}

// Make sure ACL::get and ACL::remove work as we expect
#[test]
fn acl_get_and_remove_test() {
    let sids = SIDs::new();

    let mut path_obj = support_path().unwrap_or_default();
    path_obj.push("acl_get_and_remove");
    assert!(path_obj.exists());

    let path = path_obj.to_str().unwrap();

    let mut acl = ACL::from_file_path(path, true).unwrap();

    let mut results = acl.dacl().all_filtered(
        sids.world.as_ref().unwrap(),
        None
    ).unwrap();
    assert_eq!(results.len(), 0);

    results = acl.dacl().all_filtered(
        sids.world.as_ref().unwrap(),
        None
    ).unwrap();
    assert_eq!(results.len(), 3);

    results = acl.dacl().all_filtered(
        sids.guest.as_ref().unwrap(),
        Some(ACLEntryMask::new().set_entry_type(AceType::AccessAllow))
    ).unwrap();
    assert_eq!(results.len(), 1);

    results = acl.dacl().all_filtered(
        sids.guest.as_ref().unwrap(),
        Some(ACLEntryMask::new().set_entry_type(AceType::AccessAllow))
    ).unwrap();
    assert_eq!(results.len(), 1);

    let results = acl.sacl().all_filtered(
        sids.guest.as_ref().unwrap(),
        Some(ACLEntryMask::new().set_entry_type(AceType::SystemAudit))
    ).unwrap();
    assert_eq!(results.len(), 1);

    let mut removed = acl.dacl().iter()
        .remove(
            sids.guest.as_ref().unwrap(), 
            Some(ACLEntryMask::new().set_entry_type(AceType::AccessDeny))
        ).unwrap()
        .try_collect::<Vec<_>>().unwrap();
    assert_eq!(removed.len(), 1);

    let results = acl.dacl().all_filtered(
        sids.guest.as_ref().unwrap(), 
        None
    ).unwrap();
    assert_eq!(results.len(), 2);

    removed = acl.dacl().iter()
        .remove(
        sids.guest.as_ref().unwrap(), 
        None
        ).unwrap()
        .try_collect::<Vec<_>>().unwrap();
    assert_eq!(removed.len(), 1);

}
