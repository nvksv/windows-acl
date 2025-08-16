//! Contains the ACL introspection and manipulation functionality

#![allow(non_snake_case)]

use core::{
    mem::offset_of,
    ffi::c_void,
    ptr::{null, null_mut},
    mem,
    marker::PhantomData,
    cmp::min,
    iter::FromIterator,
};
use std::{
    collections::btree_map::Entry, os::windows::io::RawHandle
};
use windows::{
    core::{
        Error, Result, HRESULT,
    },
    Win32::{
        Foundation::{
            HANDLE, STATUS_ALLOTTED_SPACE_EXCEEDED, 
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
            FindFirstFreeAce,
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
    acl::ACLKind, acl_entry::{ACLEntry, ACLEntryMask, AVERAGE_ACE_SIZE, MAX_ACL_SIZE}, 
    sd::{
        SDSource, SecurityDescriptor,
    }, 
    sid::{SIDRef, VSID}, types::*, utils::{acl_size, as_ppvoid_mut, as_pvoid_mut, parse_dacl_ace, parse_sacl_ace, vec_as_pacl_mut, MaybePtr}
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub trait MaxCountPredictor {
    fn predict_max_count( &self ) -> Result<u16>;
}

pub trait FromACLEntryIterator<'r, I: ACLEntryIterator<'r, K>, K: ACLKind>: Sized {
    fn from_iter(iter: I) -> Result<Self>;
}
 
pub trait ACLEntryIterator<'r, K: ACLKind>: FallibleIterator<Item = ACLEntry<'r, K>, Error = Error> + MaxCountPredictor {
    
    fn try_collect<T: FromACLEntryIterator<'r, Self, K>>( self ) -> Result<T> where Self: Sized {
        T::from_iter(self)
    }

    /// Adds a custom entry into the access control list.
    ///
    /// # Arguments
    /// * `sid` - The target entity's raw SID.
    /// * `entry_type` - The entry's type. Currently, only `AccessAllow`, `AccessDeny`, `SystemAudit`, and `SystemMandatoryLabel` are supported.
    /// * `flags` - See [ACE_HEADER](https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_ace_header) documentation.
    /// * `mask` - The permissions allotted for the target entity.
    ///
    /// # Remarks
    /// We only support (for now) adding access allow, access deny, system audit, and system mandatory label entries. After adding the entry,
    /// the security descriptor is automatically reloaded to reflect changes.
    ///
    /// # Errors
    /// On error, a Windows error code is wrapped in an `Err` type. If the error code is 0, the provided `entry_type` is invalid.    
    #[inline]
    fn add<'e: 'r, 's>( self, entry: ACLEntry<'e, K>, filter: Option<ACLEntryMask> ) -> Result<impl ACLEntryIterator<'r, K>> where Self: Sized {
        ACLListEntryAdder::new(
            self, 
            entry, 
            filter
        )
    }

    #[inline]
    fn add_allow<'s: 'r>( self, sid: VSID<'s>, flags: ACE_FLAGS, access_mask: ACCESS_MASK, filter: Option<ACLEntryMask> ) -> Result<impl ACLEntryIterator<'r, K>> where Self: Sized {
        self.add(
            ACLEntry::new_allow(flags, access_mask, sid), 
            filter
        )
    }

    #[inline]
    fn add_deny<'s: 'r>( self, sid: VSID<'s>, flags: ACE_FLAGS, access_mask: ACCESS_MASK, filter: Option<ACLEntryMask> ) -> Result<impl ACLEntryIterator<'r, K>> where Self: Sized {
        self.add(
            ACLEntry::new_deny(flags, access_mask, sid), 
            filter
        )
    }

    /// Removes access control list entries that match the specified parameters.
    ///
    /// # Arguments
    /// * `sid` - The target entry's raw SID.
    /// * `entry_type` - The entry's type.
    /// * `flags` - See [ACE_HEADER](https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_ace_header) documentation.
    ///
    /// # Remarks
    /// After removing the entry, the security descriptor is reloaded automatically to reflect changes.
    ///
    /// # Errors
    /// On error, a Windows error code wrapped in a `Err` type.
    fn remove<'s>( self, sid: SIDRef<'s>, filter: Option<ACLEntryMask> ) -> Result<impl ACLEntryIterator<'r, K>> where Self: Sized {
        ACLListEntryRemover::new(
            self, 
            sid,
            filter
        )
    }

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct ACLList<'r, K: ACLKind> {
    pacl: *const _ACL,
    _ph: PhantomData<&'r K>,
}
 
impl<'r, K: ACLKind> ACLList<'r, K> {
    pub fn from_pacl( pacl: *const _ACL ) -> Self {
        Self {
            pacl,
            _ph: PhantomData,
        }
    }

    pub fn pacl(&self) -> *const _ACL {
        self.pacl
    }

    pub fn iter_hdr( &self ) -> ACLListIterator<'r> {
        ACLListIterator::new(self.pacl)
    }

    pub fn iter_entry_hdr( &self ) -> ACLListEntryHdrIterator<'r, K> {
        ACLListEntryHdrIterator::new(self.pacl)
    }

    pub fn iter( &self ) -> ACLListEntryIterator<'r, K> {
        ACLListEntryIterator::new(self.pacl)
    }

    /// Returns a `Vec<ACLEntry>` of access control list entries for the specified named object path.
    pub fn all(&self) -> Result<Vec<ACLEntry<'r, K>>> {
        self.iter()
            .try_collect()
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
        self.iter()
            .filter(|entry| {
                if !entry.is_match_any_sid(mask) {
                    return Ok(false);
                }

                if !entry.sid.eq_to_ref(sid) {
                    return Ok(false);
                }

                Ok(true)
            })
            .collect()
    }
} 

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct ACLVecList<K: ACLKind> {
    inner: Vec<u8>,
    _ph: PhantomData<K>,
}

impl<K: ACLKind> ACLVecList<K> {
    pub fn new() -> Self {
        Self {
            inner: vec![],
            _ph: PhantomData,
        }
    }

    pub fn as_vec( &self ) -> &Vec<u8> {
        &self.inner
    }

    pub fn into_vec( self ) -> Vec<u8> {
        self.inner
    }

    pub fn pacl( &self ) -> Result<*const _ACL> {
        if self.inner.is_empty() {
            return Err(Error::empty());
        }

        Ok(self.inner.as_ptr() as *const _ACL)
    }

    pub fn as_list<'s>( &'s self ) -> Result<ACLList<'s, K>> {
        let pacl = self.pacl()?;
        Ok(ACLList::from_pacl(pacl))
    }

    pub fn from_iter<'r, I>(mut iter: I) -> Result<Self> where I: ACLEntryIterator<'r, K> {
        let max_count = iter.predict_max_count()?;
        let max_size = min( 
            max_count.saturating_mul(AVERAGE_ACE_SIZE).saturating_add(size_of::<_ACL>() as u16), 
            MAX_ACL_SIZE 
        );

        let mut buffer = Vec::with_capacity( max_size as usize );
        unsafe { buffer.set_len(max_size as usize) };

        //

        let mut pacl = vec_as_pacl_mut(&mut buffer);
        unsafe {
            InitializeAcl(
                pacl,
                max_size as u32,
                ACL_REVISION_DS,
            )
        }?;

        while let Some(entry) = iter.next()? {
            match K::write_ace( pacl, &entry ) {
                Ok(()) => {},
                Err(err) if err.code() != HRESULT::from_nt(STATUS_ALLOTTED_SPACE_EXCEEDED.0) => {
                    let additional = MAX_ACL_SIZE.saturating_sub(buffer.len() as u16);
                    if additional == 0 {
                        return Err(err);
                    };
                    buffer.try_reserve(additional as usize).map_err(|_| Error::empty())?;

                    pacl = vec_as_pacl_mut(&mut buffer);
                    K::write_ace( pacl, &entry )?;
                },
                Err(err) => { 
                    return Err(err);
                },
            }
        }

        //

        let mut pfreeace: *mut c_void = null_mut();
        unsafe {
            FindFirstFreeAce(
                pacl,
                &mut pfreeace
            )?
        };

        let buffer_range = &buffer[..].as_ptr_range();

        let buffer_start = buffer_range.start as *const u8;
        let acl_start = pacl as *const u8;
        let acl_end = pfreeace as *const u8;
        let buffer_end = buffer_range.end as *const u8;

        if !(buffer_start == acl_start && acl_start <= acl_end && acl_end <= buffer_end) {
            return Err(Error::empty());
        }

        let acl_size =  unsafe { acl_end.offset_from_unsigned(acl_start) }.try_into().map_err(|_| Error::empty())?;
        unsafe { buffer.set_len(acl_size as usize) };

        //

        unsafe { (*pacl).AclSize = acl_size };
        buffer.truncate( acl_size as usize );

        if !unsafe { IsValidAcl(pacl) }.as_bool() {
            return Err(Error::empty());
        }

        //

        Ok(Self {
            inner: buffer,
            _ph: PhantomData,
        })
    }

} 

impl<'r, I: ACLEntryIterator<'r, K>, K: ACLKind> FromACLEntryIterator<'r, I, K> for ACLVecList<K> {
    fn from_iter(iter: I) -> Result<Self> {
        Self::from_iter(iter)
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct ACLListIterator<'r> {
    acl: *const _ACL,
    idx: u16,
    ace_count: u16,
    _ph: PhantomData<&'r ()>,
}

impl<'r> ACLListIterator<'r> {
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

impl<'r> FallibleIterator for ACLListIterator<'r> {
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

impl<'r> MaxCountPredictor for ACLListIterator<'r> {
    fn predict_max_count( &self ) -> Result<u16> {
        Ok(self.ace_count)
    }
}
   

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct ACLListEntryHdrIterator<'r, K: ACLKind> {
    inner: ACLListIterator<'r>,
    _ph: PhantomData<K>,
}

impl<'r, K: ACLKind> ACLListEntryHdrIterator<'r, K> {
    pub fn new( acl: *const _ACL ) -> Self {
        Self {
            inner: ACLListIterator::new(acl),
            _ph: PhantomData,
        }
    }
}

impl<'r, K: ACLKind> FallibleIterator for ACLListEntryHdrIterator<'r, K> {
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

impl<'r, K: ACLKind> MaxCountPredictor for ACLListEntryHdrIterator<'r, K> {
    fn predict_max_count( &self ) -> Result<u16> {
        self.inner.predict_max_count()
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct ACLListEntryIterator<'r, K: ACLKind> {
    inner: ACLListIterator<'r>,
    _ph: PhantomData<K>,
}

impl<'r, K: ACLKind> ACLListEntryIterator<'r, K> {
    pub fn new( acl: *const _ACL ) -> Self {
        Self {
            inner: ACLListIterator::new(acl),
            _ph: PhantomData,
        }
    }
}

impl<'r, K: ACLKind> FallibleIterator for ACLListEntryIterator<'r, K> {
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

impl<'r, K: ACLKind> MaxCountPredictor for ACLListEntryIterator<'r, K> {
    fn predict_max_count( &self ) -> Result<u16> {
        self.inner.predict_max_count()
    }
}

impl<'r, K: ACLKind> ACLEntryIterator<'r, K> for ACLListEntryIterator<'r, K> {}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub enum ACLListEntryReplaceResult<'r, K: ACLKind> {
    Ignore,
    Remove,
    Replace(ACLEntry<'r, K>),
}

pub struct ACLListEntryReplacer<'r, I, K, F>
where
    I: ACLEntryIterator<'r, K>,
    K: ACLKind,
    F: FnMut(&ACLEntry<'r, K>) -> Result<ACLListEntryReplaceResult<'r, K>>,
{
    inner: I,
    f: F,
    _ph: PhantomData<&'r K>,
}

impl<'r, I, K, F> ACLListEntryReplacer<'r, I, K, F>
where
    I: ACLEntryIterator<'r, K>,
    K: ACLKind,
    F: FnMut(&ACLEntry<'r, K>) -> Result<ACLListEntryReplaceResult<'r, K>>,
{
    pub fn new( inner: I, f: F ) -> Self {
        Self {
            inner,
            f,
            _ph: PhantomData,
        }
    }
}

impl<'r, I, K, F> FallibleIterator for ACLListEntryReplacer<'r, I, K, F>
where
    I: ACLEntryIterator<'r, K>,
    K: ACLKind,
    F: FnMut(&ACLEntry<'r, K>) -> Result<ACLListEntryReplaceResult<'r, K>>,
{
    type Item = ACLEntry<'r, K>;
    type Error = Error;

    fn next(&mut self) -> Result<Option<Self::Item>> {
        while let Some(item) = self.inner.next()? {
            match (self.f)(&item)? {
                ACLListEntryReplaceResult::Ignore => { 
                    return Ok(Some(item)); 
                },
                ACLListEntryReplaceResult::Remove => { 
                    continue; 
                },
                ACLListEntryReplaceResult::Replace(item) => {
                    return Ok(Some(item)); 
                }
            };
        }

        Ok(None)
    }
}

impl<'r, I, K, F> MaxCountPredictor for ACLListEntryReplacer<'r, I, K, F> 
where
    I: ACLEntryIterator<'r, K>,
    K: ACLKind,
    F: FnMut(&ACLEntry<'r, K>) -> Result<ACLListEntryReplaceResult<'r, K>>,
{
    fn predict_max_count( &self ) -> Result<u16> {
        self.inner.predict_max_count()
    }
}

impl<'r, I, K, F> ACLEntryIterator<'r, K> for ACLListEntryReplacer<'r, I, K, F>
where
    I: ACLEntryIterator<'r, K>,
    K: ACLKind,
    F: FnMut(&ACLEntry<'r, K>) -> Result<ACLListEntryReplaceResult<'r, K>>,
{}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct ACLListEntryAdder<'r, I: ACLEntryIterator<'r, K>, K: ACLKind> {
    inner: I,
    entry: Option<ACLEntry<'r, K>>,
    filter: Option<ACLEntryMask>,
}

impl<'r, I: ACLEntryIterator<'r, K>, K: ACLKind> ACLListEntryAdder<'r, I, K> {
    pub fn new( inner: I, entry: ACLEntry<'r, K>, filter: Option<ACLEntryMask> ) -> Result<Self> {
        let _ = entry.sid.as_ref().ok_or_else(|| Error::empty())?;
        Ok(Self {
            inner,
            entry: Some(entry),
            filter,
        })
    }
}

impl<'r, I: ACLEntryIterator<'r, K>, K: ACLKind> FallibleIterator for ACLListEntryAdder<'r, I, K> {
    type Item = ACLEntry<'r, K>;
    type Error = Error;

    fn next(&mut self) -> Result<Option<Self::Item>> {
        if let Some(entry) = &self.entry {
            let sid = entry.sid.as_ref().unwrap();
            while let Some(item) = self.inner.next()? {
                if item.is_match( sid, &self.filter ) {
                    continue;
                }
                return Ok(Some(item));
            }
        } else {
            return self.inner.next();
        }

        if let Some(entry) = self.entry.take() {
            return Ok(Some(entry));
        }

        Ok(None)
    }
}

impl<'r, I: ACLEntryIterator<'r, K>, K: ACLKind> MaxCountPredictor for ACLListEntryAdder<'r, I, K> {
    fn predict_max_count( &self ) -> Result<u16> {
        let inner_count = self.inner.predict_max_count()?;
        Ok(inner_count.saturating_add(1))
    }
}

impl<'r, I: ACLEntryIterator<'r, K>, K: ACLKind> ACLEntryIterator<'r, K> for ACLListEntryAdder<'r, I, K> {}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct ACLListEntryRemover<'r, 's, I: ACLEntryIterator<'r, K>, K: ACLKind> {
    inner: I,
    sid: SIDRef<'s>,
    filter: Option<ACLEntryMask>,
    _ph_r: PhantomData<&'r ()>,
    _ph_k: PhantomData<K>,
}

impl<'r, 's, I: ACLEntryIterator<'r, K>, K: ACLKind> ACLListEntryRemover<'r, 's, I, K> {
    pub fn new( inner: I, sid: SIDRef<'s>, filter: Option<ACLEntryMask> ) -> Result<Self> {
        Ok(Self {
            inner,
            sid,
            filter,
            _ph_r: PhantomData,
            _ph_k: PhantomData,
        })
    }
}

impl<'r, 's, I: ACLEntryIterator<'r, K>, K: ACLKind> FallibleIterator for ACLListEntryRemover<'r, 's, I, K> {
    type Item = ACLEntry<'r, K>;
    type Error = Error;

    fn next(&mut self) -> Result<Option<Self::Item>> {
        while let Some(item) = self.inner.next()? {
            if item.is_match( self.sid, &self.filter ) {
                continue;
            }
            return Ok(Some(item));
        }

        Ok(None)
    }
}

impl<'r, 's, I: ACLEntryIterator<'r, K>, K: ACLKind> MaxCountPredictor for ACLListEntryRemover<'r, 's, I, K> {
    fn predict_max_count( &self ) -> Result<u16> {
        self.inner.predict_max_count()
    }
}

impl<'r, 's, I: ACLEntryIterator<'r, K>, K: ACLKind> ACLEntryIterator<'r, K> for ACLListEntryRemover<'r, 's, I, K> {}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

impl<'r, I: ACLEntryIterator<'r, K>, K: ACLKind> FromACLEntryIterator<'r, I, K> for Vec<ACLEntry<'r, K>> {
    fn from_iter(mut iter: I) -> Result<Self> {
        let mut result = vec![];

        while let Some(entry) = iter.next()? {
            result.push(entry);
        }
        
        Ok(result)
    }
}
