//! Contains the ACL introspection and manipulation functionality

#![allow(non_snake_case)]

use core::{
    mem::offset_of,
    ffi::c_void,
    ptr::{null, null_mut},
    mem,
    marker::PhantomData,
};
use std::{
    collections::btree_map::Entry, os::windows::io::RawHandle
};
use windows::{
    core::{
        Error, Result,
    },
    Win32::{
        Foundation::{
            HANDLE,
        },
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
            ACL as _ACL, ACL_REVISION_DS, ACL_SIZE_INFORMATION, CONTAINER_INHERIT_ACE,
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
use fallible_iterator::FallibleIterator;

use crate::{
    acl_entry::{ACLEntry, ACLEntryMask},
    sd::{
        SDSource, SecurityDescriptor,
    }, 
    sid::{SIDRef, VSID}, 
    acl::{ACLKind},
    types::*, 
    utils::{as_ppvoid_mut, as_pvoid_mut, vec_as_pacl_mut, parse_dacl_ace, parse_sacl_ace, acl_size}
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
 
pub struct RawACL<'r, K: ACLKind> {
    raw: *const _ACL,
    _ph: PhantomData<&'r K>,
}
 
impl<'r, K: ACLKind> RawACL<'r, K> {
    pub fn from_ptr( raw: *const _ACL ) -> Self {
        Self {
            raw,
            _ph: PhantomData,
        }
    }

    pub fn iter_hdr( &self ) -> RawACLIterator<'r> {
        RawACLIterator::new(self.raw)
    }

    pub fn iter_entry_hdr( &self ) -> RawACLEntryHdrIterator<'r, K> {
        RawACLEntryHdrIterator::new(self.raw)
    }

    pub fn iter_entry( &self ) -> RawACLEntryIterator<'r, K> {
        RawACLEntryIterator::new(self.raw)
    }

    /// Returns a `Vec<ACLEntry>` of access control list entries for the specified named object path.
    pub fn all(&self) -> Result<Vec<ACLEntry<'r, K>>> {
        let entries = self.iter_entry()
            .collect()?;
            // .for_each(|entry| {
            //     entries.push(entry);
            //     Ok(())
            // });

        Ok(entries)
    }

    /// Retrieves a list of access control entries matching the target SID entity and optionally, a access control entry type.
    ///
    /// # Arguments
    /// * `sid` - The raw SID of the target entity.
    /// * `entry_type` - The access control entry type or `None`.
    ///
    /// # Errors
    /// On error, a Windows error code is wrapped in an `Err` type.
    pub fn all_filtered<'rr: 'r>(&self, sid: SIDRef<'rr>, mask: &ACLEntryMask ) -> Result<Vec<ACLEntry<'r, K>>> {
        let entries = self.iter_entry()
            .filter(|entry| {
                if !entry.is_match(mask) {
                    return Ok(false);
                }

                if !entry.sid.eq_to_ref(sid) {
                    return Ok(false);
                }

                Ok(true)
            })
            .collect()?;

        Ok(entries)
    }

    // pub fn add<'e: 'r>( &self, entry: ACLEntry<'e, K> ) -> impl FallibleIterator<Item = ACLEntry<'e, K>>

} 

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct RawVecACL<K: ACLKind> {
    inner: Vec<u8>,
    _ph: PhantomData<K>,
}

impl<K: ACLKind> RawVecACL<K> {
    pub fn new() -> Self {
        Self {
            inner: vec![],
            _ph: PhantomData,
        }
    }

    pub fn from_iter<'r>(iter: impl FallibleIterator<Item = ACLEntry<'r, K>>) -> Result<Self> {
        
    }

} 


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct RawACLIterator<'r> {
    acl: *const _ACL,
    idx: u16,
    ace_count: u16,
    _ph: PhantomData<&'r ()>,
}

impl<'r> RawACLIterator<'r> {
    pub fn new( acl: *const _ACL ) -> Self {
        if acl.is_null() {
            return Self {
                acl,
                idx: 1,
                ace_count: 0,
                _ph: PhantomData,
            };
        }

        Self {
            acl,
            idx: 0,
            ace_count: unsafe { (*acl).AceCount },
            _ph: PhantomData,
        }
    }
}

impl<'r> FallibleIterator for RawACLIterator<'r> {
    type Item = &'r ACE_HEADER;
    type Error = Error;

    fn next( &mut self ) -> Result<Option<Self::Item>> {
        if self.idx >= self.ace_count {
            return Ok(None);
        }

        let mut hdr: *mut ACE_HEADER = null_mut();
        unsafe { 
            GetAce(
                self.acl,
                self.idx as u32,
                as_ppvoid_mut(&mut hdr)
            )
        }?;

        if hdr.is_null() {
            return Err(Error::empty());
        }

        let hdr = unsafe { &* hdr };

        self.idx += 1;

        Ok(Some(hdr))
    }
} 

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct RawACLEntryHdrIterator<'r, K: ACLKind> {
    inner: RawACLIterator<'r>,
    _ph: PhantomData<K>,
}

impl<'r, K: ACLKind> RawACLEntryHdrIterator<'r, K> {
    pub fn new( acl: *const _ACL ) -> Self {
        Self {
            inner: RawACLIterator::new(acl),
            _ph: PhantomData,
        }
    }
}

impl<'r, K: ACLKind> FallibleIterator for RawACLEntryHdrIterator<'r, K> {
    type Item = (ACLEntry<'r, K>, &'r ACE_HEADER);
    type Error = Error;

    fn next(&mut self) -> Result<Option<Self::Item>> {
        Ok(
            match self.inner.next()? {
                Some(hdr) => {
                    let entry = K::parse_ace(hdr)?;
                    Some((entry, hdr))
                },
                None => None,
            }
        )
    }
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct RawACLEntryIterator<'r, K: ACLKind> {
    inner: RawACLIterator<'r>,
    _ph: PhantomData<K>,
}

impl<'r, K: ACLKind> RawACLEntryIterator<'r, K> {
    pub fn new( acl: *const _ACL ) -> Self {
        Self {
            inner: RawACLIterator::new(acl),
            _ph: PhantomData,
        }
    }
}

impl<'r, K: ACLKind> FallibleIterator for RawACLEntryIterator<'r, K> {
    type Item = ACLEntry<'r, K>;
    type Error = Error;

    fn next(&mut self) -> Result<Option<Self::Item>> {
        Ok(
            match self.inner.next()? {
                Some(hdr) => {
                    let entry = K::parse_ace(hdr)?;
                    Some(entry)
                },
                None => None,
            }
        )
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub enum RawACLEntryReplaceResult<'r, K: ACLKind + ?Sized> {
    Ignore,
    Remove,
    Replace(ACLEntry<'r, K>),
}

pub struct RawACLEntryReplacer<'r, I, K, F>
where
    I: FallibleIterator<Item = ACLEntry<'r, K>>,
    K: ACLKind + ?Sized,
    F: FnMut(&<I as FallibleIterator>::Item) -> Result<RawACLEntryReplaceResult<'r, K>>,
{
    inner: I,
    f: F,
}

impl<'r, I, K, F> RawACLEntryReplacer<'r, I, K, F>
where
    I: FallibleIterator<Item = ACLEntry<'r, K>>,
    K: ACLKind + ?Sized,
    F: FnMut(&<I as FallibleIterator>::Item) -> Result<RawACLEntryReplaceResult<'r, K>>,
{
    pub fn new( inner: I, f: F ) -> Self {
        Self {
            inner,
            f
        }
    }
}

impl<'r, I, K, F> FallibleIterator for RawACLEntryReplacer<'r, I, K, F>
where
    I: FallibleIterator<Item = ACLEntry<'r, K>>,
    K: ACLKind + ?Sized,
    F: FnMut(&<I as FallibleIterator>::Item) -> Result<RawACLEntryReplaceResult<'r, K>>,
{
    type Item = ACLEntry<'r, K>;
    type Error = Error;

    fn next(&mut self) -> Result<Option<Self::Item>> {
        while let Some(item) = self.inner.next()? {
            match (self.f)(&item)? {
                RawACLEntryReplaceResult::Ignore => { 
                    return Ok(Some(item)); 
                },
                RawACLEntryReplaceResult::Remove => { 
                    continue; 
                },
                RawACLEntryReplaceResult::Replace(item) => {
                    return Ok(Some(item)); 
                }
            };
        }
    }
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct RawACLEntryAdder<'r, I, K>
where
    I: FallibleIterator<Item = ACLEntry<'r, K>>,
    K: ACLKind + ?Sized,
{
    inner: I,
    entry: ACLEntry<'r, K>,
    processed: bool
}

impl<'r, I, K> RawACLEntryAdder<'r, I, K>
where
    I: FallibleIterator<Item = ACLEntry<'r, K>>,
    K: ACLKind + ?Sized,
{
    pub fn new( inner: I, entry: ACLEntry<'r, K> ) -> Self {
        Self {
            inner,
            entry,
            processed: false,
        }
    }
}

impl<'r, I, K> FallibleIterator for RawACLEntryAdder<'r, I, K>
where
    I: FallibleIterator<Item = ACLEntry<'r, K>>,
    K: ACLKind + ?Sized,
{
    type Item = ACLEntry<'r, K>;
    type Error = Error;

    fn next(&mut self) -> Result<Option<Self::Item>> {
        while let Some(item) = self.inner.next()? {
            match (self.f)(&item)? {
                RawACLEntryReplaceResult::Ignore => { 
                    return Ok(Some(item)); 
                },
                RawACLEntryReplaceResult::Remove => { 
                    continue; 
                },
                RawACLEntryReplaceResult::Replace(item) => {
                    return Ok(Some(item)); 
                }
            };
        }
    }
}
