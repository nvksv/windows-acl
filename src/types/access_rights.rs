#![allow(non_snake_case)]

use core::{ops, default, fmt};
use std::marker::PhantomData;
use windows::{
    core::Result,
    Win32::{
        Foundation::{
            GENERIC_ACCESS_RIGHTS,
        },
        Security::{
            Authorization::{
                SE_DS_OBJECT, SE_DS_OBJECT_ALL, SE_FILE_OBJECT, SE_KERNEL_OBJECT, SE_LMSHARE, SE_OBJECT_TYPE,
                SE_PRINTER, SE_PROVIDER_DEFINED_OBJECT, SE_REGISTRY_KEY, SE_REGISTRY_WOW64_32KEY, SE_SERVICE,
                SE_UNKNOWN_OBJECT_TYPE, SE_WINDOW_OBJECT, SE_WMIGUID_OBJECT, 
            }, 
        },
        Storage::FileSystem::{
            FILE_ACCESS_RIGHTS, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_APPEND_DATA, DELETE, FILE_DELETE_CHILD,
            FILE_EXECUTE, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_LIST_DIRECTORY,
            FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_READ_EA, FILE_TRAVERSE, FILE_WRITE_ATTRIBUTES,
            FILE_WRITE_DATA, FILE_WRITE_EA, READ_CONTROL, SPECIFIC_RIGHTS_ALL, STANDARD_RIGHTS_ALL,
            STANDARD_RIGHTS_EXECUTE, STANDARD_RIGHTS_READ, STANDARD_RIGHTS_REQUIRED, STANDARD_RIGHTS_WRITE,
            SYNCHRONIZE, WRITE_DAC, WRITE_OWNER, 
        },
    },
};

use crate::utils::DebugIdent;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ACCESS_MASK(pub u32);

impl ACCESS_MASK {
    pub const fn contains(&self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}
impl ops::BitOr for ACCESS_MASK {
    type Output = Self;
    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}
impl ops::BitAnd for ACCESS_MASK {
    type Output = Self;
    fn bitand(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
}
impl ops::BitOrAssign for ACCESS_MASK {
    fn bitor_assign(&mut self, other: Self) {
        self.0.bitor_assign(other.0)
    }
}
impl ops::BitAndAssign for ACCESS_MASK {
    fn bitand_assign(&mut self, other: Self) {
        self.0.bitand_assign(other.0)
    }
}
impl ops::Not for ACCESS_MASK {
    type Output = Self;
    fn not(self) -> Self {
        Self(self.0.not())
    }
}

impl default::Default for ACCESS_MASK {
    fn default() -> Self {
        Self(0)
    }
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub trait IntoAccessMask {
    fn into_access_mask( self ) -> ACCESS_MASK;
}

impl IntoAccessMask for ACCESS_MASK {
    #[inline]
    fn into_access_mask( self ) -> ACCESS_MASK {
        self
    }
}

impl IntoAccessMask for u32 {
    #[inline]
    fn into_access_mask( self ) -> ACCESS_MASK {
        ACCESS_MASK(self)
    }
}

impl IntoAccessMask for FILE_ACCESS_RIGHTS {
    #[inline]
    fn into_access_mask( self ) -> ACCESS_MASK {
        ACCESS_MASK(self.0)
    }
}

impl IntoAccessMask for GENERIC_ACCESS_RIGHTS {
    #[inline]
    fn into_access_mask( self ) -> ACCESS_MASK {
        ACCESS_MASK(self.0)
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub enum AccessMaskDebugMode {
    Tuple,
    PlainList,
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub trait AccessMaskIdents {
    const MODE: AccessMaskDebugMode = AccessMaskDebugMode::Tuple;
    const NAME: &'static str = "ACCESS_MASK";

    fn generic_full_access() -> Option<DebugIdent> {
        None
    }

    fn generic_modify() -> Option<DebugIdent> {
        None
    }

    fn generic_read_and_execute() -> Option<DebugIdent> {
        None
    }

    fn generic_list_folder_contents() -> Option<DebugIdent> {
        None
    }

    fn generic_read() -> Option<DebugIdent> {
        None
    }

    fn generic_write() -> Option<DebugIdent> {
        None
    }

    fn generic_special_permissions() -> Option<DebugIdent> {
        None
    }

    fn bit_0000_0001() -> Option<DebugIdent> {
        Some(DebugIdent("0x01"))
    }

    fn bit_0000_0002() -> Option<DebugIdent> {
        Some(DebugIdent("0x02"))
    }

    fn bit_0000_0004() -> Option<DebugIdent> {
        Some(DebugIdent("0x04"))
    }

    fn bit_0000_0008() -> Option<DebugIdent> {
        Some(DebugIdent("0x08"))
    }

    fn bit_0000_0010() -> Option<DebugIdent> {
        Some(DebugIdent("0x10"))
    }

    fn bit_0000_0020() -> Option<DebugIdent> {
        Some(DebugIdent("0x20"))
    }

    fn bit_0000_0040() -> Option<DebugIdent> {
        Some(DebugIdent("0x40"))
    }

    fn bit_0000_0080() -> Option<DebugIdent> {
        Some(DebugIdent("0x80"))
    }

    fn bit_0000_0100() -> Option<DebugIdent> {
        Some(DebugIdent("0x0100"))
    }

    fn bit_0000_0200() -> Option<DebugIdent> {
        Some(DebugIdent("0x0200"))
    }

    fn bit_0000_0400() -> Option<DebugIdent> {
        Some(DebugIdent("0x0400"))
    }

    fn bit_0000_0800() -> Option<DebugIdent> {
        Some(DebugIdent("0x0800"))
    }

    fn bit_0000_1000() -> Option<DebugIdent> {
        Some(DebugIdent("0x1000"))
    }

    fn bit_0000_2000() -> Option<DebugIdent> {
        Some(DebugIdent("0x2000"))
    }

    fn bit_0000_4000() -> Option<DebugIdent> {
        Some(DebugIdent("0x4000"))
    }

    fn bit_0000_8000() -> Option<DebugIdent> {
        Some(DebugIdent("0x8000"))
    }

    fn bit_0001_0000() -> Option<DebugIdent> {
        Some(DebugIdent("0x010000"))
    }

    fn bit_0002_0000() -> Option<DebugIdent> {
        Some(DebugIdent("0x020000"))
    }

    fn bit_0004_0000() -> Option<DebugIdent> {
        Some(DebugIdent("0x040000"))
    }

    fn bit_0008_0000() -> Option<DebugIdent> {
        Some(DebugIdent("0x080000"))
    }

    fn bit_0010_0000() -> Option<DebugIdent> {
        Some(DebugIdent("0x100000"))
    }

    fn bit_0020_0000() -> Option<DebugIdent> {
        Some(DebugIdent("0x200000"))
    }

    fn bit_0040_0000() -> Option<DebugIdent> {
        Some(DebugIdent("0x400000"))
    }

    fn bit_0080_0000() -> Option<DebugIdent> {
        Some(DebugIdent("0x800000"))
    }

    fn bit_0100_0000() -> Option<DebugIdent> {
        Some(DebugIdent("0x01000000"))
    }

    fn bit_0200_0000() -> Option<DebugIdent> {
        Some(DebugIdent("0x02000000"))
    }

    fn bit_0400_0000() -> Option<DebugIdent> {
        Some(DebugIdent("0x04000000"))
    }

    fn bit_0800_0000() -> Option<DebugIdent> {
        Some(DebugIdent("0x08000000"))
    }

    fn bit_1000_0000() -> Option<DebugIdent> {
        Some(DebugIdent("0x10000000"))
    }

    fn bit_2000_0000() -> Option<DebugIdent> {
        Some(DebugIdent("0x20000000"))
    }

    fn bit_4000_0000() -> Option<DebugIdent> {
        Some(DebugIdent("0x40000000"))
    }

    fn bit_8000_0000() -> Option<DebugIdent> {
        Some(DebugIdent("0x80000000"))
    }

    fn bits_0000_FFFF() -> Option<DebugIdent> {
        None
    }

    fn bits_0012_0089() -> Option<DebugIdent> {
        None
    }

    fn bits_0012_00A0() -> Option<DebugIdent> {
        None
    }

    fn bits_0012_0116() -> Option<DebugIdent> {
        None
    }

    fn bits_000F_0000() -> Option<DebugIdent> {
        None
    }

    fn bits_001F_0000() -> Option<DebugIdent> {
        None
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct AccessMaskGenericFlags {
    full_access: bool,
    modify: bool,
    read_and_execute: bool,
    list_folder_contents: bool,
    read: bool,
    write: bool,
    special_permissions: Option<ACCESS_MASK>,
    other: Option<ACCESS_MASK>,
}

fn access_mask_to_file_rights_generic_flags( access_mask: ACCESS_MASK, is_directory: bool ) -> AccessMaskGenericFlags {
    let G_WRITE = FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA;
    let G_READ = FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_READ_EA | READ_CONTROL; 
    let G_READ_AND_EXECUTE = FILE_EXECUTE | G_READ;
    let G_MODIFY = DELETE | G_READ_AND_EXECUTE | G_WRITE;
    let G_FULL_ACCESS = G_MODIFY | WRITE_DAC | WRITE_OWNER | if is_directory { FILE_DELETE_CHILD } else { FILE_ACCESS_RIGHTS(0) };

    let G_WRITE: ACCESS_MASK = G_WRITE.into_access_mask();
    let G_READ: ACCESS_MASK = G_READ.into_access_mask(); 
    let G_READ_AND_EXECUTE: ACCESS_MASK = G_READ_AND_EXECUTE.into_access_mask();
    let G_MODIFY: ACCESS_MASK = G_MODIFY.into_access_mask();
    let G_FULL_ACCESS: ACCESS_MASK = G_FULL_ACCESS.into_access_mask();

    let mut standard_bits = access_mask & G_FULL_ACCESS;
    let other_bits = access_mask & !G_FULL_ACCESS;

    let mut full_access = false;
    let mut modify = false;
    let mut read_and_execute = false;
    let mut list_folder_contents = false;
    let mut read = false;
    let mut write = false;
    let mut special_permissions = None;
    let mut other = None;

    if standard_bits.contains(G_FULL_ACCESS) {
        debug_assert!( !standard_bits.contains(!G_FULL_ACCESS) );
        full_access = true;
    } else {
        if standard_bits.contains(G_MODIFY) {
            modify = true;
            standard_bits &= !G_MODIFY;    
        }

        if standard_bits.contains(G_READ_AND_EXECUTE) {
            read_and_execute = true;
            standard_bits &= !G_READ_AND_EXECUTE;    
        }

        if standard_bits.contains(G_WRITE) {
            write = true;
            standard_bits &= !G_READ_AND_EXECUTE;    
        }

        if standard_bits.contains(G_READ) {
            read = true;
            standard_bits &= !G_READ_AND_EXECUTE;    
        }
    }

    if is_directory {
        list_folder_contents = read_and_execute;
    }

    if standard_bits.0 != 0 {
        special_permissions = Some(standard_bits);
    }

    if other_bits.0 != 0 {
        other = Some(other_bits);
    }

    AccessMaskGenericFlags {
        full_access,
        modify,
        read_and_execute,
        list_folder_contents,
        read,
        write,
        special_permissions,
        other,
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct FileAccessRightsFullIdents {}

impl AccessMaskIdents for FileAccessRightsFullIdents {
    const MODE: AccessMaskDebugMode = AccessMaskDebugMode::Tuple;

    fn generic_full_access() -> Option<DebugIdent> {
        Some(DebugIdent("GENERIC_ALL"))
    }

    fn generic_modify() -> Option<DebugIdent> {
        Some(DebugIdent("GENERIC_MODIFY"))
    }

    fn generic_read_and_execute() -> Option<DebugIdent> {
        Some(DebugIdent("GENERIC_READ_AND_EXECUTE"))
    }

    fn generic_list_folder_contents() -> Option<DebugIdent> {
        Some(DebugIdent("GENERIC_LIST_FOLDER_CONTENTS"))
    }

    fn generic_read() -> Option<DebugIdent> {
        Some(DebugIdent("GENERIC_READ"))
    }

    fn generic_write() -> Option<DebugIdent> {
        Some(DebugIdent("GENERIC_WRITE"))
    }

    fn generic_special_permissions() -> Option<DebugIdent> {
        Some(DebugIdent("GENERIC_SPECIAL_PERMISSIONS"))
    }

    fn bit_0000_0001() -> Option<DebugIdent> {
        debug_assert!( FILE_LIST_DIRECTORY == FILE_READ_DATA );
        Some(DebugIdent("LIST_DIRECTORY/READ_DATA"))
    }

    fn bit_0000_0002() -> Option<DebugIdent> {
        debug_assert!( FILE_ADD_FILE == FILE_WRITE_DATA );
        Some(DebugIdent("ADD_FILE/WRITE_DATA"))
    }

    fn bit_0000_0004() -> Option<DebugIdent> {
        debug_assert!( FILE_ADD_SUBDIRECTORY == FILE_APPEND_DATA );
        Some(DebugIdent("ADD_SUBDIRECTORY/APPEND_DATA"))
    }

    fn bit_0000_0008() -> Option<DebugIdent> {
        Some(DebugIdent("READ_EA"))
    }

    fn bit_0000_0010() -> Option<DebugIdent> {
        Some(DebugIdent("WRITE_EA"))
    }

    fn bit_0000_0020() -> Option<DebugIdent> {
        Some(DebugIdent("EXECUTE/TRAVERSE"))
    }

    fn bit_0000_0040() -> Option<DebugIdent> {
        Some(DebugIdent("DELETE_CHILD"))
    }

    fn bit_0000_0080() -> Option<DebugIdent> {
        Some(DebugIdent("READ_ATTRIBUTES"))
    }

    fn bit_0000_0100() -> Option<DebugIdent> {
        Some(DebugIdent("WRITE_ATTRIBUTES"))
    }

    fn bit_0001_0000() -> Option<DebugIdent> {
        Some(DebugIdent("DELETE"))
    }

    fn bit_0002_0000() -> Option<DebugIdent> {
        // pub const STANDARD_RIGHTS_EXECUTE: FILE_ACCESS_RIGHTS = FILE_ACCESS_RIGHTS(131072u32);
        // pub const STANDARD_RIGHTS_READ: FILE_ACCESS_RIGHTS = FILE_ACCESS_RIGHTS(131072u32);
        // pub const STANDARD_RIGHTS_REQUIRED: FILE_ACCESS_RIGHTS = FILE_ACCESS_RIGHTS(983040u32);
        // pub const STANDARD_RIGHTS_WRITE: FILE_ACCESS_RIGHTS = FILE_ACCESS_RIGHTS(131072u32);
        Some(DebugIdent("READ_CONTROL"))
    }

    fn bit_0004_0000() -> Option<DebugIdent> {
        Some(DebugIdent("WRITE_DAC"))
    }

    fn bit_0008_0000() -> Option<DebugIdent> {
        Some(DebugIdent("WRITE_OWNER"))
    }

    fn bit_0010_0000() -> Option<DebugIdent> {
        Some(DebugIdent("SYNCHRONIZE"))
    }

    fn bits_0000_FFFF() -> Option<DebugIdent> {
        Some(DebugIdent("SPECIFIC_RIGHTS_ALL"))
    }

    fn bits_000F_0000() -> Option<DebugIdent> {
        Some(DebugIdent("STANDARD_RIGHTS_REQUIRED"))
    }

    fn bits_0012_0089() -> Option<DebugIdent> {
        Some(DebugIdent("GENERIC_READ"))
    }

    fn bits_0012_00A0() -> Option<DebugIdent> {
        Some(DebugIdent("GENERIC_EXECUTE"))
    }

    fn bits_0012_0116() -> Option<DebugIdent> {
        Some(DebugIdent("GENERIC_WRITE"))
    }

    fn bits_001F_0000() -> Option<DebugIdent> {
        Some(DebugIdent("STANDARD_RIGHTS_ALL"))
    }

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct FileAccessRightsShortIdents {}

impl AccessMaskIdents for FileAccessRightsShortIdents {
    fn generic_full_access() -> Option<DebugIdent> {
        Some(DebugIdent("ALL"))
    }

    fn generic_modify() -> Option<DebugIdent> {
        Some(DebugIdent("M"))
    }

    fn generic_read_and_execute() -> Option<DebugIdent> {
        Some(DebugIdent("RE"))
    }

    fn generic_list_folder_contents() -> Option<DebugIdent> {
        Some(DebugIdent("L"))
    }

    fn generic_read() -> Option<DebugIdent> {
        Some(DebugIdent("R"))
    }

    fn generic_write() -> Option<DebugIdent> {
        Some(DebugIdent("W"))
    }

    fn generic_special_permissions() -> Option<DebugIdent> {
        Some(DebugIdent("SP"))
    }

    // LIST_DIRECTORY/READ_DATA
    fn bit_0000_0001() -> Option<DebugIdent> {
        debug_assert!( FILE_LIST_DIRECTORY == FILE_READ_DATA );
        Some(DebugIdent("LD/R"))
    }

    // ADD_FILE/WRITE_DATA
    fn bit_0000_0002() -> Option<DebugIdent> {
        debug_assert!( FILE_ADD_FILE == FILE_WRITE_DATA );
        Some(DebugIdent("AF/W"))
    }

    // ADD_SUBDIRECTORY/APPEND_DATA
    fn bit_0000_0004() -> Option<DebugIdent> {
        debug_assert!( FILE_ADD_SUBDIRECTORY == FILE_APPEND_DATA );
        Some(DebugIdent("AD/A"))
    }

    // READ_EA
    fn bit_0000_0008() -> Option<DebugIdent> {
        Some(DebugIdent("RE"))
    }

    // WRITE_EA
    fn bit_0000_0010() -> Option<DebugIdent> {
        Some(DebugIdent("WE"))
    }

    // EXECUTE/TRAVERSE
    fn bit_0000_0020() -> Option<DebugIdent> {
        Some(DebugIdent("E/T"))
    }

    // DELETE_CHILD
    fn bit_0000_0040() -> Option<DebugIdent> {
        Some(DebugIdent("DC"))
    }

    // READ_ATTRIBUTES
    fn bit_0000_0080() -> Option<DebugIdent> {
        Some(DebugIdent("RA"))
    }

    // WRITE_ATTRIBUTES
    fn bit_0000_0100() -> Option<DebugIdent> {
        Some(DebugIdent("WA"))
    }

    // DELETE
    fn bit_0001_0000() -> Option<DebugIdent> {
        Some(DebugIdent("D"))
    }

    // READ_CONTROL
    fn bit_0002_0000() -> Option<DebugIdent> {
        // pub const STANDARD_RIGHTS_EXECUTE: FILE_ACCESS_RIGHTS = FILE_ACCESS_RIGHTS(131072u32);
        // pub const STANDARD_RIGHTS_READ: FILE_ACCESS_RIGHTS = FILE_ACCESS_RIGHTS(131072u32);
        // pub const STANDARD_RIGHTS_REQUIRED: FILE_ACCESS_RIGHTS = FILE_ACCESS_RIGHTS(983040u32);
        // pub const STANDARD_RIGHTS_WRITE: FILE_ACCESS_RIGHTS = FILE_ACCESS_RIGHTS(131072u32);
        Some(DebugIdent("RC"))
    }

    // WRITE_DAC
    fn bit_0004_0000() -> Option<DebugIdent> {
        Some(DebugIdent("WD"))
    }

    // WRITE_OWNER
    fn bit_0008_0000() -> Option<DebugIdent> {
        Some(DebugIdent("WO"))
    }

    // SYNCHRONIZE
    fn bit_0010_0000() -> Option<DebugIdent> {
        Some(DebugIdent("S"))
    }

    // SPECIFIC_RIGHTS_ALL
    fn bits_0000_FFFF() -> Option<DebugIdent> {
        Some(DebugIdent("SPRA"))
    }

    // STANDARD_RIGHTS_REQUIRED
    fn bits_000F_0000() -> Option<DebugIdent> {
        Some(DebugIdent("STDR"))
    }

    // GENERIC_READ
    fn bits_0012_0089() -> Option<DebugIdent> {
        Some(DebugIdent("GR"))
    }

    // GENERIC_EXECUTE
    fn bits_0012_00A0() -> Option<DebugIdent> {
        Some(DebugIdent("GE"))
    }

    // GENERIC_WRITE
    fn bits_0012_0116() -> Option<DebugIdent> {
        Some(DebugIdent("GW"))
    }

    // STANDARD_RIGHTS_ALL
    fn bits_001F_0000() -> Option<DebugIdent> {
        Some(DebugIdent("STDA"))
    }

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

macro_rules! fmt_tuple {
    ($mask:expr, $ident:expr) => {
        
    }
}

#[repr(transparent)]
pub struct DebugFileAccessRights<N: AccessMaskIdents>{ 
    pub access_mask: ACCESS_MASK,
    pub _ph: PhantomData<N>,
}

impl<N: AccessMaskIdents> DebugFileAccessRights<N> {
    pub fn new( access_mask: ACCESS_MASK ) -> Self {
        Self {
            access_mask,
            _ph: PhantomData, 
        }
    }

    fn fmt_tuple(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_tuple(N::NAME);

        if let Some(ident) = N::bit_0000_0001() {
            if self.access_mask.contains(ACCESS_MASK(0x_0000_0001)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0000_0002() {
            if self.access_mask.contains(ACCESS_MASK(0x_0000_0002)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0000_0004() {
            if self.access_mask.contains(ACCESS_MASK(0x_0000_0004)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0000_0008() {
            if self.access_mask.contains(ACCESS_MASK(0x_0000_0008)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0000_0010() {
            if self.access_mask.contains(ACCESS_MASK(0x_0000_0010)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0000_0020() {
            if self.access_mask.contains(ACCESS_MASK(0x_0000_0020)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0000_0040() {
            if self.access_mask.contains(ACCESS_MASK(0x_0000_0040)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0000_0080() {
            if self.access_mask.contains(ACCESS_MASK(0x_0000_0080)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = &N::bit_0000_0100() {
            if self.access_mask.contains(ACCESS_MASK(0x_0000_0100)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = &N::bit_0000_0200() {
            if self.access_mask.contains(ACCESS_MASK(0x_0000_0200)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0000_0400() {
            if self.access_mask.contains(ACCESS_MASK(0x_0000_0400)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0000_0800() {
            if self.access_mask.contains(ACCESS_MASK(0x_0000_0800)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0000_1000() {
            if self.access_mask.contains(ACCESS_MASK(0x_0000_1000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0000_2000() {
            if self.access_mask.contains(ACCESS_MASK(0x_0000_2000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0000_4000() {
            if self.access_mask.contains(ACCESS_MASK(0x_0000_4000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0000_8000() {
            if self.access_mask.contains(ACCESS_MASK(0x_0000_8000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0001_0000() {
            if self.access_mask.contains(ACCESS_MASK(0x_0001_0000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0002_0000() {
            if self.access_mask.contains(ACCESS_MASK(0x_0002_0000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0004_0000() {
            if self.access_mask.contains(ACCESS_MASK(0x_0004_0000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0008_0000() {
            if self.access_mask.contains(ACCESS_MASK(0x_0008_0000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0010_0000() {
            if self.access_mask.contains(ACCESS_MASK(0x_0010_0000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0020_0000() {
            if self.access_mask.contains(ACCESS_MASK(0x_0020_0000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0040_0000() {
            if self.access_mask.contains(ACCESS_MASK(0x_0040_0000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0080_0000() {
            if self.access_mask.contains(ACCESS_MASK(0x_0080_0000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0100_0000() {
            if self.access_mask.contains(ACCESS_MASK(0x_0100_0000)) {
                f.field(&ident);
            }
        }

        if self.access_mask.contains(ACCESS_MASK(0x_0200_0000)) {
            if let Some(ident) = N::bit_0200_0000() {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0400_0000() {
            if self.access_mask.contains(ACCESS_MASK(0x_0400_0000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0800_0000() {
            if self.access_mask.contains(ACCESS_MASK(0x_0800_0000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_1000_0000() {
            if self.access_mask.contains(ACCESS_MASK(0x_1000_0000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_2000_0000() {
            if self.access_mask.contains(ACCESS_MASK(0x_2000_0000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_4000_0000() {
            if self.access_mask.contains(ACCESS_MASK(0x_4000_0000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_8000_0000() {
            if self.access_mask.contains(ACCESS_MASK(0x_8000_0000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bits_0000_FFFF() {
            if self.access_mask.contains(ACCESS_MASK(0x_0000_FFFF)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bits_000F_0000() {
            if self.access_mask.contains(ACCESS_MASK(0x_000F_0000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bits_0012_0089() {
            if self.access_mask.contains(ACCESS_MASK(0x_0012_0089)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bits_0012_00A0() {
            if self.access_mask.contains(ACCESS_MASK(0x_0012_00A0)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bits_0012_0116() {
            if self.access_mask.contains(ACCESS_MASK(0x_0012_0116)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bits_001F_0000() {
            if self.access_mask.contains(ACCESS_MASK(0x_001F_0000)) {
                f.field(&ident);
            }
        }

        f.finish()
    }

    fn fmt_plain_list(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        let mut first_item = true;

        if let Some(ident) = N::bit_0000_0001() {
            if self.access_mask.contains(ACCESS_MASK(0x_0000_0001)) {
                if first_item {
                    first_item = false;
                } else {
                    write!( f, ", " );
                }

                write!( f, "{:?}", ident );
            }
        }

        if let Some(ident) = N::bit_0000_0002() {
            if self.access_mask.contains(ACCESS_MASK(0x_0000_0002)) {
                if first_item {
                    first_item = false;
                } else {
                    write!( f, ", " );
                }

                write!( f, "{:?}", ident );
            }
        }

        if let Some(ident) = N::bit_0000_0004() {
            if self.access_mask.contains(ACCESS_MASK(0x_0000_0004)) {
                if first_item {
                    first_item = false;
                } else {
                    write!( f, ", " );
                }

                write!( f, "{:?}", ident );
            }
        }

        if let Some(ident) = N::bit_0000_0008() {
            if self.access_mask.contains(ACCESS_MASK(0x_0000_0008)) {
                if first_item {
                    first_item = false;
                } else {
                    write!( f, ", " );
                }

                write!( f, "{:?}", ident );
            }
        }

        if let Some(ident) = N::bit_0000_0010() {
            if self.access_mask.contains(ACCESS_MASK(0x_0000_0010)) {
                if first_item {
                    first_item = false;
                } else {
                    write!( f, ", " );
                }

                write!( f, "{:?}", ident );
            }
        }

        if let Some(ident) = N::bit_0000_0020() {
            if self.access_mask.contains(ACCESS_MASK(0x_0000_0020)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0000_0040() {
            if self.access_mask.contains(ACCESS_MASK(0x_0000_0040)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0000_0080() {
            if self.access_mask.contains(ACCESS_MASK(0x_0000_0080)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = &N::bit_0000_0100() {
            if self.access_mask.contains(ACCESS_MASK(0x_0000_0100)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = &N::bit_0000_0200() {
            if self.access_mask.contains(ACCESS_MASK(0x_0000_0200)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0000_0400() {
            if self.access_mask.contains(ACCESS_MASK(0x_0000_0400)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0000_0800() {
            if self.access_mask.contains(ACCESS_MASK(0x_0000_0800)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0000_1000() {
            if self.access_mask.contains(ACCESS_MASK(0x_0000_1000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0000_2000() {
            if self.access_mask.contains(ACCESS_MASK(0x_0000_2000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0000_4000() {
            if self.access_mask.contains(ACCESS_MASK(0x_0000_4000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0000_8000() {
            if self.access_mask.contains(ACCESS_MASK(0x_0000_8000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0001_0000() {
            if self.access_mask.contains(ACCESS_MASK(0x_0001_0000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0002_0000() {
            if self.access_mask.contains(ACCESS_MASK(0x_0002_0000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0004_0000() {
            if self.access_mask.contains(ACCESS_MASK(0x_0004_0000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0008_0000() {
            if self.access_mask.contains(ACCESS_MASK(0x_0008_0000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0010_0000() {
            if self.access_mask.contains(ACCESS_MASK(0x_0010_0000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0020_0000() {
            if self.access_mask.contains(ACCESS_MASK(0x_0020_0000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0040_0000() {
            if self.access_mask.contains(ACCESS_MASK(0x_0040_0000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0080_0000() {
            if self.access_mask.contains(ACCESS_MASK(0x_0080_0000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0100_0000() {
            if self.access_mask.contains(ACCESS_MASK(0x_0100_0000)) {
                f.field(&ident);
            }
        }

        if self.access_mask.contains(ACCESS_MASK(0x_0200_0000)) {
            if let Some(ident) = N::bit_0200_0000() {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0400_0000() {
            if self.access_mask.contains(ACCESS_MASK(0x_0400_0000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_0800_0000() {
            if self.access_mask.contains(ACCESS_MASK(0x_0800_0000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_1000_0000() {
            if self.access_mask.contains(ACCESS_MASK(0x_1000_0000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_2000_0000() {
            if self.access_mask.contains(ACCESS_MASK(0x_2000_0000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_4000_0000() {
            if self.access_mask.contains(ACCESS_MASK(0x_4000_0000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bit_8000_0000() {
            if self.access_mask.contains(ACCESS_MASK(0x_8000_0000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bits_0000_FFFF() {
            if self.access_mask.contains(ACCESS_MASK(0x_0000_FFFF)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bits_000F_0000() {
            if self.access_mask.contains(ACCESS_MASK(0x_000F_0000)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bits_0012_0089() {
            if self.access_mask.contains(ACCESS_MASK(0x_0012_0089)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bits_0012_00A0() {
            if self.access_mask.contains(ACCESS_MASK(0x_0012_00A0)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bits_0012_0116() {
            if self.access_mask.contains(ACCESS_MASK(0x_0012_0116)) {
                f.field(&ident);
            }
        }

        if let Some(ident) = N::bits_001F_0000() {
            if self.access_mask.contains(ACCESS_MASK(0x_001F_0000)) {
                f.field(&ident);
            }
        }
    }
}

impl<N: AccessMaskIdents> fmt::Debug for DebugFileAccessRights<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        match N::MODE {
            AccessMaskDebugMode::Tuple => self.fmt_tuple(f),
            AccessMaskDebugMode::PlainList => self.fmt_plain_list(f),
        }
    }
}
