#![cfg(windows)]

use crate::{
    utils::current_user_account_name, ACE, ACLKind, AceType, SecurityDescriptor, SID, VSID, ACLEntryIterator, ACEFilter, ACEMask, IntoOptionalACEFilter, IntoOptionalACEMask, ACCESS_MASK,
    helper::DebugUnpretty,
    winapi::api::ErrorExt,
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
            ERROR_NOT_ALL_ASSIGNED, GENERIC_ALL, GENERIC_READ, GENERIC_WRITE, HANDLE
        }, Security::{
            AclSizeInformation, AddAccessAllowedAceEx, AddAccessDeniedAceEx, AddAce, AddAuditAccessAceEx, AddMandatoryAce, Authorization::{
                SE_DS_OBJECT, SE_DS_OBJECT_ALL, SE_FILE_OBJECT, SE_KERNEL_OBJECT, SE_LMSHARE, SE_OBJECT_TYPE,
                SE_PRINTER, SE_PROVIDER_DEFINED_OBJECT, SE_REGISTRY_KEY, SE_REGISTRY_WOW64_32KEY, SE_SERVICE,
                SE_UNKNOWN_OBJECT_TYPE, SE_WINDOW_OBJECT, SE_WMIGUID_OBJECT,
            }, CopySid, EqualSid, GetAce, GetAclInformation, GetLengthSid, InitializeAcl, IsValidAcl, IsValidSid, WinAccountGuestSid, WinWorldSid, ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_CALLBACK_ACE, ACCESS_ALLOWED_CALLBACK_OBJECT_ACE, ACCESS_ALLOWED_OBJECT_ACE, ACCESS_DENIED_ACE, ACCESS_DENIED_CALLBACK_ACE, ACCESS_DENIED_CALLBACK_OBJECT_ACE, ACCESS_DENIED_OBJECT_ACE, ACE_FLAGS, ACE_HEADER, ACL as _ACL, ACL_REVISION_DS, ACL_SIZE_INFORMATION, CONTAINER_INHERIT_ACE, FAILED_ACCESS_ACE_FLAG, INHERITED_ACE, OBJECT_INHERIT_ACE, PSID, SECURITY_WORLD_SID_AUTHORITY, SUCCESSFUL_ACCESS_ACE_FLAG, SYSTEM_AUDIT_ACE, SYSTEM_AUDIT_CALLBACK_ACE, SYSTEM_AUDIT_CALLBACK_OBJECT_ACE, SYSTEM_AUDIT_OBJECT_ACE, SYSTEM_MANDATORY_LABEL_ACE, SYSTEM_RESOURCE_ATTRIBUTE_ACE, WELL_KNOWN_SID_TYPE
        }, Storage::FileSystem::{
            FILE_ACCESS_RIGHTS, FILE_ALL_ACCESS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, SYNCHRONIZE, WRITE_DAC
        }, System::SystemServices::{
            ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, ACCESS_DENIED_CALLBACK_ACE_TYPE, ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_DENIED_OBJECT_ACE_TYPE, DOMAIN_GROUP_RID_USERS, DOMAIN_USER_RID_ADMIN, DOMAIN_USER_RID_GUEST, MAXDWORD, SECURITY_WORLD_RID, SYSTEM_AUDIT_ACE_TYPE, SYSTEM_AUDIT_CALLBACK_ACE_TYPE, SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE, SYSTEM_AUDIT_OBJECT_ACE_TYPE, SYSTEM_MANDATORY_LABEL_ACE_TYPE, SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP, SYSTEM_MANDATORY_LABEL_NO_READ_UP, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE
        }
    },
};
use fallible_iterator::FallibleIterator;

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
    let (user_sid, _user_domain) = SID::from_account_name(user, None).unwrap();
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

fn acl_entry_exists<'r, 'e, K: ACLKind>(entries: &Vec<ACE<'r, K>>, expected: &ACE<'e, K>, mask: impl IntoOptionalACEMask) -> Option<usize> {
    // println!("entries = {:#?}", entries);
    // println!("expected = {:#?}", expected);

    let mask = mask.into_optional_mask();

    for i in 0..(entries.len()) {
        let entry = &entries[i];

        if entry.is_eq(expected, &mask) {
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
    test: SID,
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
            test: SID::from_account_name("test", Some("ksv-auto")).unwrap().0,
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

    let mut sd = SecurityDescriptor::from_file_path(path);
    sd.read().unwrap();
    println!("sd = {:#?}", &sd);

    let entries = sd.dacl().all().unwrap();
    assert_ne!(entries.len(), 0);

    let expected = ACE::new_deny(
        &sids.guest,
        0,
        (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE) & !SYNCHRONIZE,
    );

    let mask = ACEMask::new()
        .set_entry_type()
        .set_flags(0xFFFF)
        .set_access_mask((FILE_GENERIC_READ | FILE_GENERIC_EXECUTE) & !SYNCHRONIZE);

    let deny_idx = match acl_entry_exists(&entries, &expected, mask) {
        Some(i) => i,
        None => {
            println!("Expected AccessDeny entry does not exist!");
            assert!(false);
            return;
        }
    };

    //

    let expected = ACE::new_allow(
        &sids.current_user,
        0,
        (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE) & !SYNCHRONIZE,
    );

    // // NOTE(andy): For ACL entries added by CmdLets on files, SYNCHRONIZE is not set
    // expected.access_mask = FILE_ALL_ACCESS.into();

    let mask = ACEMask::new()
        .set_entry_type()
        .set_flags(0xFFFF)
        .set_access_mask((FILE_GENERIC_READ | FILE_GENERIC_EXECUTE) & !SYNCHRONIZE);

    let allow_idx = match acl_entry_exists(&entries, &expected, mask) {
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

    let mut sd = SecurityDescriptor::from_file_path(path);
    sd.enable_sacl(true);
    match sd.read() {
        Ok(obj) => obj,
        Err(err) => {
            assert!(err.is_not_all_assigned());
            println!("INFO: Terminating query_sacl_unit_test early because we are not Admin.");
            return;
        }
    };

    let entries = sd.sacl().all().unwrap();
    assert_ne!(entries.len(), 0);

    let expected = ACE::new_audit(
        &sids.world,
        SUCCESSFUL_ACCESS_ACE_FLAG | FAILED_ACCESS_ACE_FLAG,
        (FILE_GENERIC_READ | FILE_GENERIC_WRITE) & !SYNCHRONIZE,
    );

    let allow_idx = match acl_entry_exists(&entries, &expected, None) {
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

    let mut sd = if use_handle {
        file = OpenOptions::new()
            .access_mode(GENERIC_READ.0 | WRITE_DAC.0 )
            .open(path)
            .unwrap();
        SecurityDescriptor::from_file_raw_handle(file.as_raw_handle())
    } else {
        SecurityDescriptor::from_file_path(path)
    };
    sd.read().unwrap();

    sd.update_dacl(|dacl| {
        dacl.add_allow(
            &sids.current_user,
            0,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            None,
        )
    }).unwrap();

    sd.write().unwrap();

    //

    // NOTE(andy): Our explicit allow entry should make this pass now
    assert!(File::create(path).is_ok());

    let mut entries = sd.dacl().all().unwrap();
    assert_ne!(entries.len(), 0);

    let expected = ACE::new_allow(
        &sids.current_user,
        0,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE,
    );

    match acl_entry_exists(&entries, &expected, None) {
        Some(_i) => {}
        None => {
            println!("Expected AccessAllow entry does not exist!");
            assert!(false);
            return;
        }
    };

    sd.update_dacl(|dacl| {
        dacl.remove(
            sids.current_user.as_ref(),
            ACEFilter::new().set_entry_type(AceType::AccessAllow),
        )
    }).unwrap();

    sd.write().unwrap();

    //

    // assert!(File::create(path).is_err());

    entries = sd.dacl().all().unwrap();
    match acl_entry_exists(&entries, &expected, None) {
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
        .access_mode(GENERIC_WRITE.0 | WRITE_DAC.0 )
        .open(path);
    assert!(create_res.is_ok());
    let file = create_res.unwrap();

    let mut sd = if use_handle {
        SecurityDescriptor::from_file_raw_handle(file.as_raw_handle())
    } else {
        SecurityDescriptor::from_file_path(path)
    };
    sd.read().unwrap();

    sd.update_dacl(|dacl| {
        dacl.add_deny(
            &sids.current_user, 
            0, 
            FILE_GENERIC_WRITE,
            None
        ) 
    }).unwrap();

    sd.write().unwrap();

    //

    // NOTE(andy): Since we added a deny entry for WRITE, this should fail
    assert!(File::create(path).is_err());

    let mut entries = sd.dacl().all().unwrap();
    assert_ne!(entries.len(), 0);

    let expected = ACE::new_deny(
        &sids.current_user,
        0,
        FILE_GENERIC_WRITE,
    );

    match acl_entry_exists(&entries, &expected, None) {
        Some(_i) => {}
        None => {
            println!("Expected AccessDeny entry does not exist!");
            assert!(false);
            return;
        }
    }

    sd.update_dacl(|dacl| {
        dacl.remove(
            sids.current_user.as_ref(),
            ACEFilter::new().set_entry_type(AceType::AccessDeny),
        )
    }).unwrap();

    sd.write().unwrap();

    //

    assert!(File::open(path).is_ok());

    entries = sd.dacl().all().unwrap_or(Vec::new());
    assert_ne!(entries.len(), 0);

    match acl_entry_exists(&entries, &expected, None) {
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

    let mut sd = SecurityDescriptor::from_file_path(path);
    sd.enable_sacl(true);
    sd.read().unwrap();

    sd.update_sacl(|sacl| {
        sacl.add_mandatory_label(
            &low_mil_sid,
            0,
            SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | SYSTEM_MANDATORY_LABEL_NO_READ_UP | SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP,
            None
        )
    }).unwrap();

    sd.write().unwrap();

    //

    let mut entries = sd.sacl().all().unwrap_or_default();
    assert_ne!(entries.len(), 0);

    let expected = ACE::new_mandatory_label(
        &low_mil_sid,
        0,
        SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | SYSTEM_MANDATORY_LABEL_NO_READ_UP | SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP
    );

    assert!(acl_entry_exists(&entries, &expected, None).is_some());

    sd.update_sacl(|sacl| {
        sacl.remove(
            low_mil_sid.as_ref(),
            ACEFilter::new().set_entry_type(AceType::SystemMandatoryLabel)
        )
    }).unwrap();

    sd.write().unwrap();

    //

    entries = sd.sacl().all().unwrap();

    assert!(acl_entry_exists(&entries, &expected, None).is_none());
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

    let mut sd = SecurityDescriptor::from_file_path(path);
    sd.enable_sacl(true);
    sd.read().unwrap();

    sd.update_sacl(|sacl| {
        sacl.add_audit(
            &sids.current_user,
            0,
            FILE_GENERIC_READ,
            None
        )
    }).unwrap();

    sd.write().unwrap();

    //

    let entries = sd.sacl().all().unwrap_or_default();
    assert_ne!(entries.len(), 0);

    let expected = ACE::new_audit(
        &sids.current_user,
        SUCCESSFUL_ACCESS_ACE_FLAG | FAILED_ACCESS_ACE_FLAG,
        FILE_GENERIC_READ
    );

    assert!(acl_entry_exists(&entries, &expected, None).is_some());

    sd.update_sacl(|sacl| {
        sacl.remove(
            sids.current_user.as_ref(), 
            None
        )
    }).unwrap();

    sd.write().unwrap();

    //

    let entries = sd.sacl().all().unwrap();

    assert!(acl_entry_exists(&entries, &expected, None).is_none());
}

// Make sure ACL::get and ACL::remove work as we expect
#[test]
fn acl_get_and_remove_test() {
    let sids = SIDs::new();

    let mut path_obj = support_path().unwrap_or_default();
    path_obj.push("acl_get_and_remove");
    assert!(path_obj.exists());

    let path = path_obj.to_str().unwrap();

    let mut sd = SecurityDescriptor::from_file_path(path);
    sd.enable_sacl(true);
    sd.read().unwrap();

    //

    let results = sd.dacl().all_filtered(
        sids.world.as_ref(),
        None
    ).unwrap();
    assert_eq!(results.len(), 0);

    let results = sd.dacl().all_filtered(
        sids.guest.as_ref(),
        None
    ).unwrap();
    assert_eq!(results.len(), 3);

    let results = sd.dacl().all_filtered(
        sids.guest.as_ref(),
        ACEFilter::new().set_entry_type(AceType::AccessAllow)
    ).unwrap();
    assert_eq!(results.len(), 1);

    let results = sd.dacl().all_filtered(
        sids.guest.as_ref(),
        ACEFilter::new().set_entry_type(AceType::AccessDeny)
    ).unwrap();
    assert_eq!(results.len(), 1);

    let results = sd.sacl().all_filtered(
        sids.guest.as_ref(),
        ACEFilter::new().set_entry_type(AceType::SystemAudit)
    ).unwrap();
    assert_eq!(results.len(), 1);

    //

    sd.update_dacl(|dacl| {
        dacl.remove(
            sids.guest.as_ref(), 
            ACEFilter::new().set_entry_type(AceType::AccessDeny)
        )
    }).unwrap();

    let results = sd.dacl().all_filtered(
        sids.guest.as_ref(), 
        None
    ).unwrap();
    assert_eq!(results.len(), 2);

    sd.update_dacl(|dacl| {
        dacl.remove(
        sids.guest.as_ref(), 
        None
        )
    }).unwrap();

}


#[test]
fn my_test() {
    let sids = SIDs::new();

    let mut path_obj = support_path().unwrap_or_default();
    path_obj.push("query_test");
    assert!(path_obj.exists());

    let path = path_obj.to_str().unwrap();

    SecurityDescriptor::take_ownership_from_file_path(path).expect("take_ownership_from_path");

    let mut sd = SecurityDescriptor::from_file_path(path);
    sd.read().expect("from_file_path");
    
    println!("1) sd = {:#?}", &sd);

    let entries = sd.iter_dacl_with_inheritance_source().expect("iter_dacl_with_inheritance_source")
        .collect::<Vec::<_>>().expect("collect");
    println!("entries = {:#?}", &entries);

    // // sd.set_owner(sids.current_user.as_ref()).expect("set_owner");
    sd.update_dacl(|dacl| {
        dacl.add_allow( 
            sids.current_user.as_ref(), 
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
            FILE_ALL_ACCESS,
            None
        )?
        .remove_any_sid(
            ACEFilter::new().set_inherited_flag(true)
        )
    }).expect("update_dacl");

    sd.set_dacl_is_protected( true ).expect("set_dacl_is_protected");
    println!("2) sd = {:#?}", &sd);

    sd.write().expect("write");
    println!("3) sd = {:#?}", &sd);

}