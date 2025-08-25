#![allow(non_snake_case)]

use core::{
    mem,
    hash,
    marker::PhantomData,
    fmt,
};
use windows::{
    core::{
        Error, Result,
    },
    Win32::{
        Security::{
            PSID, ACE_FLAGS, CONTAINER_INHERIT_ACE, FAILED_ACCESS_ACE_FLAG, INHERIT_ONLY_ACE, INHERITED_ACE, 
            NO_PROPAGATE_INHERIT_ACE, OBJECT_INHERIT_ACE, SUCCESSFUL_ACCESS_ACE_FLAG,
        },
    },
};

use crate::{
    utils::{acl_entry_size, DebugIdent},
    types::*,
    sid::{SIDRef, VSID, IntoVSID},
    acl_kind::{ACLKind, DACL, SACL, IsACLKind},
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub enum AceFlagsDebugMode {
    Tuple,
    PlainList
}

pub trait AceFlagsIdents {
    const DEBUG_MODE: AceFlagsDebugMode;
    const DEBUG_NAME: &'static str = "";
    const DISPLAY_MODE: AceFlagsDebugMode;
    const DISPLAY_NAME: &'static str = "";

    fn to_generic( _ace_flags: ACE_FLAGS, _is_container: Option<bool> ) -> Option<AceGenericFlags> {
        None
    }

    fn generic_inherited() -> Option<DebugIdent> {
        None
    }

    fn generic_kind( _kind: AceGenericKind ) -> Option<DebugIdent> {
        None
    }

    fn generic_this_container_only() -> Option<DebugIdent> {
        None
    }

    fn object_inherit() -> Option<DebugIdent> {
        None
    }

    fn container_inherit() -> Option<DebugIdent> {
        None
    }

    fn no_propagate_inherit() -> Option<DebugIdent> {
        None
    }

    fn inherit_only() -> Option<DebugIdent> {
        None
    }

    fn inherited() -> Option<DebugIdent> {
        None
    }

    fn successful_access_flag() -> Option<DebugIdent> {
        None
    }

    fn failed_access_flag() -> Option<DebugIdent> {
        None
    }

}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AceGenericKind {
    ThisFolderOnly,
    ThisFolderSubfoldersAndFiles,
    ThisFolderAndSubfolders,
    ThisFolderAndFiles,
    SubfoldersAndFiles,
    SubfoldersOnly,
    FilesOnly
}

pub struct AceGenericFlags {
    pub inherited: bool,
    pub kind: AceGenericKind,
    pub this_container_only: bool,
    pub other: ACE_FLAGS,
}

fn ace_flags_to_generic( ace_flags: ACE_FLAGS, is_container: bool ) -> Option<AceGenericFlags> {
    let inherited = ace_flags.contains(INHERITED_ACE);
    let this_container_only = ace_flags.contains(NO_PROPAGATE_INHERIT_ACE);

    let oi = ace_flags.contains(OBJECT_INHERIT_ACE);
    let ci = ace_flags.contains(CONTAINER_INHERIT_ACE);
    let io = ace_flags.contains(INHERIT_ONLY_ACE);

    if is_container && (this_container_only || oi || ci || io) {
        return None;
    }

    let kind = match (io, oi, ci) {
        (false, true, true) => AceGenericKind::ThisFolderSubfoldersAndFiles,
        (false, true, false) => AceGenericKind::ThisFolderAndSubfolders,
        (false, false, true) => AceGenericKind::ThisFolderAndFiles,
        (false, false, false) => AceGenericKind::ThisFolderOnly,
        (true, true, true) => AceGenericKind::SubfoldersAndFiles,
        (true, true, false) => AceGenericKind::FilesOnly,
        (true, false, true) => AceGenericKind::SubfoldersOnly,
        (true, false, false) => {
            return None;
        },
    };

    if this_container_only && kind == AceGenericKind::ThisFolderOnly {
        return None;
    }

    let other = ace_flags & !(INHERITED_ACE | NO_PROPAGATE_INHERIT_ACE| OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE);

    Some(AceGenericFlags {
        inherited,
        this_container_only,
        kind,
        other
    })
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct AceFlagsFullIdents {}

impl AceFlagsIdents for AceFlagsFullIdents {
    const DEBUG_MODE: AceFlagsDebugMode = AceFlagsDebugMode::Tuple;
    const DEBUG_NAME: &'static str = "AceFlags";
    const DISPLAY_MODE: AceFlagsDebugMode = AceFlagsDebugMode::PlainList;

    // fn to_generic(ace_flags: ACE_FLAGS, is_container: Option<bool>) -> Option<AceGenericFlags> {
    //     ace_flags_to_generic(ace_flags, is_container)
    // }

    fn generic_inherited() -> Option<DebugIdent> {
        Some(DebugIdent("INHERITED"))
    }

    fn generic_kind( kind: AceGenericKind ) -> Option<DebugIdent> {
        Some(match kind {
            AceGenericKind::ThisFolderSubfoldersAndFiles => DebugIdent("THIS_FOLDER_SUBFOLDERS_AND_FILES"),
            AceGenericKind::ThisFolderAndSubfolders => DebugIdent("THIS_FOLDER_AND_SUBFOLDERS"),
            AceGenericKind::ThisFolderAndFiles => DebugIdent("THIS_FOLDER_AND_FILES"),
            AceGenericKind::ThisFolderOnly => DebugIdent("THIS_FOLDER_ONLY"),
            AceGenericKind::SubfoldersAndFiles => DebugIdent("SUBFOLDERS_AND_FILES"),
            AceGenericKind::SubfoldersOnly => DebugIdent("SUBFOLDERS_ONLY"),
            AceGenericKind::FilesOnly => DebugIdent("FILES_ONLY"),
        })
    }

    fn generic_this_container_only() -> Option<DebugIdent> {
        Some(DebugIdent("THIS_CONTAINER_ONLY"))
    }

    fn object_inherit() -> Option<DebugIdent> {
        Some(DebugIdent("OBJECT_INHERIT"))
    }

    fn container_inherit() -> Option<DebugIdent> {
        Some(DebugIdent("CONTAINER_INHERIT"))
    }

    fn no_propagate_inherit() -> Option<DebugIdent> {
        Some(DebugIdent("NO_PROPAGATE_INHERIT"))
    }

    fn inherit_only() -> Option<DebugIdent> {
        Some(DebugIdent("INHERIT_ONLY"))
    }

    fn inherited() -> Option<DebugIdent> {
        Some(DebugIdent("INHERITED"))
    }

    fn successful_access_flag() -> Option<DebugIdent> {
        Some(DebugIdent("SUCCESSFUL_ACCESS_FLAG"))
    }

    fn failed_access_flag() -> Option<DebugIdent> {
        Some(DebugIdent("FAILED_ACCESS_FLAG"))
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct AceFlagsShortIdents {}

impl AceFlagsIdents for AceFlagsShortIdents {
    const DEBUG_MODE: AceFlagsDebugMode = AceFlagsDebugMode::Tuple;
    const DEBUG_NAME: &'static str = "AceFlags";
    const DISPLAY_MODE: AceFlagsDebugMode = AceFlagsDebugMode::PlainList;

    fn to_generic(ace_flags: ACE_FLAGS, is_container: Option<bool>) -> Option<AceGenericFlags> {
        ace_flags_to_generic(ace_flags, is_container.unwrap_or(true))
    }

    fn generic_inherited() -> Option<DebugIdent> {
        Some(DebugIdent("I"))
    }

    fn generic_kind( kind: AceGenericKind ) -> Option<DebugIdent> {
        Some(match kind {
            AceGenericKind::ThisFolderSubfoldersAndFiles => DebugIdent("TSF"),
            AceGenericKind::ThisFolderAndSubfolders => DebugIdent("TS"),
            AceGenericKind::ThisFolderAndFiles => DebugIdent("TF"),
            AceGenericKind::ThisFolderOnly => DebugIdent("TO"),
            AceGenericKind::SubfoldersAndFiles => DebugIdent("SF"),
            AceGenericKind::SubfoldersOnly => DebugIdent("SO"),
            AceGenericKind::FilesOnly => DebugIdent("FO"),
        })
    }

    fn generic_this_container_only() -> Option<DebugIdent> {
        Some(DebugIdent("TCO"))
    }

    fn object_inherit() -> Option<DebugIdent> {
        Some(DebugIdent("OI"))
    }

    fn container_inherit() -> Option<DebugIdent> {
        Some(DebugIdent("CI"))
    }

    fn no_propagate_inherit() -> Option<DebugIdent> {
        Some(DebugIdent("NPI"))
    }

    fn inherit_only() -> Option<DebugIdent> {
        Some(DebugIdent("IO"))
    }

    fn inherited() -> Option<DebugIdent> {
        Some(DebugIdent("I"))
    }

    fn successful_access_flag() -> Option<DebugIdent> {
        Some(DebugIdent("SAF"))
    }

    fn failed_access_flag() -> Option<DebugIdent> {
        Some(DebugIdent("FAF"))
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct AceFlagsRepresenter<N: AceFlagsIdents>{
    pub flags: ACE_FLAGS,
    pub is_container: Option<bool>,
    pub _ph: PhantomData<N>,
}

macro_rules! fmt_tuple {
    ($mask:expr, $ident:ident, $ace_flags:expr, $f:ident) => {
        if let Some(ident) = N::$ident() {
            if $ace_flags.contains($mask) {
                $f.field(&ident);
            }
        }
    };
    (g: $ident:ident, $f:ident) => {
        if let Some(ident) = N::$ident() {
            $f.field(&ident);
        }
    };
    (gk: $ident:ident, $kind:expr, $f:ident) => {
        if let Some(ident) = N::$ident($kind) {
            $f.field(&ident);
        }
    };
}
macro_rules! fmt_plain_list {
    ($mask:expr, $ident:ident, $ace_flags:expr, $f:ident, $first_item:ident) => {
        if let Some(ident) = N::$ident() {
            if $ace_flags.contains($mask) {
                if $first_item {
                    #[allow(unused_assignments)] {
                        $first_item = false;
                    }
                } else {
                    write!( $f, ", " )?;
                }

                write!( $f, "{:?}", ident )?;
            }
        }
    };
    (g: $ident:ident, $f:ident, $first_item:ident) => {
        if let Some(ident) = N::$ident() {
            if $first_item {
                #[allow(unused_assignments)] {
                    $first_item = false;
                }
            } else {
                write!( $f, ", " )?;
            }

            write!( $f, "{:?}", ident )?;
        }
    };
    (gk: $ident:ident, $kind:expr, $f:ident, $first_item:ident) => {
        if let Some(ident) = N::$ident($kind) {
            if $first_item {
                #[allow(unused_assignments)] {
                    $first_item = false;
                }
            } else {
                write!( $f, ", " )?;
            }

            write!( $f, "{:?}", ident )?;
        }
    };
}


impl<N: AceFlagsIdents> AceFlagsRepresenter<N> {
    pub fn new( flags: ACE_FLAGS, is_container: Option<bool> ) -> Self {
        Self { 
            flags,
            is_container,
            _ph: PhantomData
        }
    }

    fn fmt_tuple(&self, f: &mut std::fmt::Formatter<'_>, name: &'static str) -> fmt::Result {
        let mut f = f.debug_tuple(name);

        let mut ace_flags = self.flags;

        if let Some(generic) = N::to_generic(ace_flags, self.is_container) {
            if generic.inherited {
                fmt_tuple!(g: generic_inherited, f);
            }
            fmt_tuple!(gk: generic_kind, generic.kind, f);
            if generic.this_container_only {
                fmt_tuple!(g: generic_this_container_only, f);
            }

            ace_flags = generic.other;
        }

        fmt_tuple!(OBJECT_INHERIT_ACE,          object_inherit,         ace_flags, f);
        fmt_tuple!(CONTAINER_INHERIT_ACE,       container_inherit,      ace_flags, f);
        fmt_tuple!(NO_PROPAGATE_INHERIT_ACE,    no_propagate_inherit,   ace_flags, f);
        fmt_tuple!(INHERIT_ONLY_ACE,            inherit_only,           ace_flags, f);
        fmt_tuple!(INHERITED_ACE,               inherited,              ace_flags, f);
        fmt_tuple!(SUCCESSFUL_ACCESS_ACE_FLAG,  successful_access_flag, ace_flags, f);
        fmt_tuple!(FAILED_ACCESS_ACE_FLAG,      failed_access_flag,     ace_flags, f);

        f.finish()
    }

    fn fmt_plain_list(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        let mut first_item = true;

        let mut ace_flags = self.flags;

        if let Some(generic) = N::to_generic(ace_flags, self.is_container) {
            if generic.inherited {
                fmt_plain_list!(g: generic_inherited, f, first_item);
            }
            fmt_plain_list!(gk: generic_kind, generic.kind, f, first_item);
            if generic.this_container_only {
                fmt_plain_list!(g: generic_this_container_only, f, first_item);
            }

            ace_flags = generic.other;
        }

        fmt_plain_list!(OBJECT_INHERIT_ACE,          object_inherit,         ace_flags, f, first_item);
        fmt_plain_list!(CONTAINER_INHERIT_ACE,       container_inherit,      ace_flags, f, first_item);
        fmt_plain_list!(NO_PROPAGATE_INHERIT_ACE,    no_propagate_inherit,   ace_flags, f, first_item);
        fmt_plain_list!(INHERIT_ONLY_ACE,            inherit_only,           ace_flags, f, first_item);
        fmt_plain_list!(INHERITED_ACE,               inherited,              ace_flags, f, first_item);
        fmt_plain_list!(SUCCESSFUL_ACCESS_ACE_FLAG,  successful_access_flag, ace_flags, f, first_item);
        fmt_plain_list!(FAILED_ACCESS_ACE_FLAG,      failed_access_flag,     ace_flags, f, first_item);

        Ok(())
    }
}

impl<N: AceFlagsIdents> fmt::Debug for AceFlagsRepresenter<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        match N::DEBUG_MODE {
            AceFlagsDebugMode::Tuple => self.fmt_tuple(f, N::DEBUG_NAME),
            AceFlagsDebugMode::PlainList => self.fmt_plain_list(f),
        }
    }
}

impl<N: AceFlagsIdents> fmt::Display for AceFlagsRepresenter<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        match N::DISPLAY_MODE {
            AceFlagsDebugMode::Tuple => self.fmt_tuple(f, N::DISPLAY_NAME),
            AceFlagsDebugMode::PlainList => self.fmt_plain_list(f),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub trait IntoAceFlags {
    fn into_ace_flags( self ) -> ACE_FLAGS;
}

impl IntoAceFlags for ACE_FLAGS {
    #[inline]
    fn into_ace_flags( self ) -> ACE_FLAGS {
        self
    }
}

impl IntoAceFlags for u32 {
    #[inline]
    fn into_ace_flags( self ) -> ACE_FLAGS {
        ACE_FLAGS(self)
    }
}