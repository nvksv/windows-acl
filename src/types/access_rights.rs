#![allow(non_snake_case)]

use core::{ops, default, fmt};
use std::marker::PhantomData;
use windows::{
    core::Result,
    Win32::{
        Security::Authorization::{
                SE_DS_OBJECT, SE_DS_OBJECT_ALL, SE_FILE_OBJECT, SE_KERNEL_OBJECT, SE_LMSHARE, SE_OBJECT_TYPE,
                SE_PRINTER, SE_PROVIDER_DEFINED_OBJECT, SE_REGISTRY_KEY, SE_REGISTRY_WOW64_32KEY, SE_SERVICE,
                SE_UNKNOWN_OBJECT_TYPE, SE_WINDOW_OBJECT, SE_WMIGUID_OBJECT,
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

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub trait AccessMaskIdents {
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

    fn bits_0012_00A0() -> Option<DebugIdent> {
        None
    }

    fn bits_0012_00A0() -> Option<DebugIdent> {
        None
    }

    fn bits_0012_00A0() -> Option<DebugIdent> {
        None
    }

}

pub struct FileAccessRightsFullIdents {}

impl AccessMaskIdents for FileAccessRightsFullIdents {
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

    fn bit_0004_0000() -> Option<DebugIdent> {
        Some(DebugIdent("WRITE_DAC"))
    }

    fn bit_0008_0000() -> Option<DebugIdent> {
        Some(DebugIdent("WRITE_OWNER"))
    }

    fn bit_0010_0000() -> Option<DebugIdent> {
        Some(DebugIdent("SYNCHRONIZE"))
    }

    fn bits_0012_00A0() -> Option<DebugIdent> {
        Some(DebugIdent("GENERIC_EXECUTE"))
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

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
}

impl<N: AccessMaskIdents> fmt::Debug for DebugFileAccessRights<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_tuple("ACCESS_RIGHTS");

        if self.access_mask.contains(ACCESS_MASK(0x_0000_0001)) {
            if let Some(ident) = N::bit_0000_0001() {
                f.field(&ident);
            }
        }

        if self.access_mask.contains(ACCESS_MASK(0x_0000_0002)) {
            if let Some(ident) = N::bit_0000_0002() {
                f.field(&ident);
            }
        }

        if self.access_mask.contains(ACCESS_MASK(0x_0000_0004)) {
            if let Some(ident) = N::bit_0000_0004() {
                f.field(&ident);
            }
        }

        if self.access_mask.contains(ACCESS_MASK(0x_0000_0008)) {
            if let Some(ident) = N::bit_0000_0008() {
                f.field(&ident);
            }
        }

        if self.access_mask.contains(ACCESS_MASK(0x_0000_0010)) {
            if let Some(ident) = N::bit_0000_0010() {
                f.field(&ident);
            }
        }

        if self.access_mask.contains(ACCESS_MASK(0x_0000_0020)) {
            if let Some(ident) = N::bit_0000_0020() {
                f.field(&ident);
            }
        }

        if self.access_mask.contains(ACCESS_MASK(0x_0000_0040)) {
            if let Some(ident) = N::bit_0000_0040() {
                f.field(&ident);
            }
        }

        if self.access_mask.contains(ACCESS_MASK(0x_0000_0080)) {
            if let Some(ident) = N::bit_0000_0080() {
                f.field(&ident);
            }
        }

        if self.access_mask.contains(ACCESS_MASK(0x_0000_0100)) {
            if let Some(ident) = &N::bit_0000_0100() {
                f.field(&ident);
            }
        }

        if self.access_mask.contains(ACCESS_MASK(0x_0000_0200)) {
            if let Some(ident) = &N::bit_0000_0200() {
                f.field(&ident);
            }
        }

        if self.access_mask.contains(ACCESS_MASK(0x_0000_0400)) {
            if let Some(ident) = N::bit_0000_0400() {
                f.field(&ident);
            }
        }

        if self.access_mask.contains(ACCESS_MASK(0x_0000_0800)) {
            if let Some(ident) = N::bit_0000_0800() {
                f.field(&ident);
            }
        }

        if self.access_mask.contains(ACCESS_MASK(0x_0000_1000)) {
            if let Some(ident) = N::bit_0000_1000() {
                f.field(&ident);
            }
        }

        if self.access_mask.contains(ACCESS_MASK(0x_0000_2000)) {
            if let Some(ident) = N::bit_0000_2000() {
                f.field(&ident);
            }
        }

        if self.access_mask.contains(ACCESS_MASK(0x_0000_4000)) {
            if let Some(ident) = N::bit_0000_4000() {
                f.field(&ident);
            }
        }

        if self.access_mask.contains(ACCESS_MASK(0x_0000_8000)) {
            if let Some(ident) = N::bit_0000_8000() {
                f.field(&ident);
            }
        }

        if self.access_mask.contains(ACCESS_MASK(0x_0001_0000)) {
            if let Some(ident) = N::bit_0001_0000() {
                f.field(&ident);
            }
        }

        if self.access_mask.contains(ACCESS_MASK(0x_0002_0000)) {
            if let Some(ident) = N::bit_0002_0000() {
                f.field(&ident);
            }
        }

        if self.access_mask.contains(ACCESS_MASK(0x_0004_0000)) {
            if let Some(ident) = N::bit_0004_0000() {
                f.field(&ident);
            }
        }

        if self.access_mask.contains(ACCESS_MASK(0x_0008_0000)) {
            if let Some(ident) = N::bit_0008_0000() {
                f.field(&ident);
            }
        }

        if self.access_mask.contains(ACCESS_MASK(0x_0010_0000)) {
           if let Some(ident) = N::bit_0010_0000() {
                f.field(&ident);
            }
        }

        if self.access_mask.contains(ACCESS_MASK(0x_0020_0000)) {
            if let Some(ident) = N::bit_0020_0000() {
                f.field(&ident);
            }
        }

        if self.access_mask.contains(ACCESS_MASK(0x_0040_0000)) {
            if let Some(ident) = N::bit_0040_0000() {
                f.field(&ident);
            }
        }

        if self.access_mask.contains(ACCESS_MASK(0x_0080_0000)) {
            if let Some(ident) = N::bit_0080_0000() {
                f.field(&ident);
            }
        }

        if self.access_mask.contains(ACCESS_MASK(0x_0100_0000)) {
            if let Some(ident) = N::bit_0100_0000() {
                f.field(&ident);
            }
        }

        if self.access_mask.contains(ACCESS_MASK(0x_0200_0000)) {
            if let Some(ident) = N::bit_0200_0000() {
                f.field(&ident);
            }
        }

        if self.access_mask.contains(ACCESS_MASK(0x_0400_0000)) {
            if let Some(ident) = N::bit_0400_0000() {
                f.field(&ident);
            }
        }

        if self.access_mask.contains(ACCESS_MASK(0x_0800_0000)) {
            if let Some(ident) = N::bit_0800_0000() {
                f.field(&ident);
            }
        }

        if self.access_mask.contains(ACCESS_MASK(0x_1000_0000)) {
            if let Some(ident) = N::bit_1000_0000() {
                f.field(&ident);
            }
        }

        if self.access_mask.contains(ACCESS_MASK(0x_2000_0000)) {
            if let Some(ident) = N::bit_2000_0000() {
                f.field(&ident);
            }
        }

        if self.access_mask.contains(ACCESS_MASK(0x_4000_0000)) {
            if let Some(ident) = N::bit_4000_0000() {
                f.field(&ident);
            }
        }

        if self.access_mask.contains(ACCESS_MASK(0x_8000_0000)) {
            if let Some(ident) = N::bit_8000_0000() {
                f.field(&ident);
            }
        }



        // 0x_0012_0089
        if FILE_ACCESS_RIGHTS(self.0.0).contains(FILE_GENERIC_READ) {
            f.field(&DebugIdent("ENERIC_READ"));
        }

        // 0x_0012_0116
        if FILE_ACCESS_RIGHTS(self.0.0).contains(FILE_GENERIC_WRITE) {
            f.field(&DebugIdent("ENERIC_WRITE"));
        }

        // 0x_0000_FFFF
        if FILE_ACCESS_RIGHTS(self.0.0).contains(SPECIFIC_RIGHTS_ALL) {
            f.field(&DebugIdent("SPECIFIC_RIGHTS_ALL"));
        }

        // 0x_0000_FFFF
        if FILE_ACCESS_RIGHTS(self.0.0).contains(STANDARD_RIGHTS_ALL) {
            f.field(&DebugIdent("STANDARD_RIGHTS_ALL"));
        }

        // 0x_0002_0000
        if FILE_ACCESS_RIGHTS(self.0.0).contains(STANDARD_RIGHTS_EXECUTE) {
            f.field(&DebugIdent("STANDARD_RIGHTS_EXECUTE"));
        }

        // 0x_0002_0000
        if FILE_ACCESS_RIGHTS(self.0.0).contains(STANDARD_RIGHTS_READ) {
            f.field(&DebugIdent("STANDARD_RIGHTS_READ"));
        }

        // 0x_0002_0000
        if FILE_ACCESS_RIGHTS(self.0.0).contains(STANDARD_RIGHTS_REQUIRED) {
            f.field(&DebugIdent("STANDARD_RIGHTS_REQUIRED"));
        }

        // 0x_0002_0000
        if FILE_ACCESS_RIGHTS(self.0.0).contains(STANDARD_RIGHTS_WRITE) {
            f.field(&DebugIdent("STANDARD_RIGHTS_WRITE"));
        }

        f.finish()
    }
}
