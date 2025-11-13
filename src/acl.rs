//! Contains the ACL introspection and manipulation functionality

#![allow(non_snake_case)]

use core::{
    ffi::c_void,
    ptr::{null_mut},
    marker::PhantomData,
    cmp::min,
};
use std::{
    ptr::null,
    ffi::OsString,
};
use windows::{
    core::{
        Error, Result, HRESULT,
    },
    Win32::{
        Foundation::{
            STATUS_ALLOTTED_SPACE_EXCEEDED, 
        },
        Security::{
            Authorization::INHERITED_FROMW,
            GetAce, InitializeAcl, IsValidAcl,
            ACL as _ACL, ACL_REVISION_DS, ACE_HEADER, ACE_FLAGS,
            FindFirstFreeAce, 
        },
    },
};
use fallible_iterator::FallibleIterator;

use crate::{
    ace::{ACE, ACEFilter, AVERAGE_ACE_SIZE, IntoOptionalACEFilter, MAX_ACL_SIZE}, acl_kind::{ACLKind, DACL, IsACLKind, SACL}, types::*, utils::{as_ppvoid_mut, vec_as_pacl_mut}, winapi::{
        security_descriptor::{WindowsInheritedFrom, WindowsSecurityDescriptor},
        sid::{IntoVSID, SIDRef}, 
    }
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub trait MaxCountPredictor {
    fn predict_max_count( &self ) -> Result<u16>;
}

pub trait FromACLEntryIterator<'r, I: ACLEntryIterator<'r, K>, K: ACLKind>: Sized {
    fn from_iter(iter: I) -> Result<Self>;
}
 
pub trait ACLEntryIterator<'r, K: ACLKind>: FallibleIterator<Item = ACE<'r, K>, Error = Error> + MaxCountPredictor {
    
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
    fn add<'e: 'r, 's>( self, entry: ACE<'e, K>, filter: impl IntoOptionalACEFilter ) -> Result<impl ACLEntryIterator<'r, K>> where Self: Sized {
        ACLListEntryAdder::new(
            self, 
            entry, 
            filter.into_optional_mask()
        )
    }

    #[inline]
    fn add_allow<'s: 'r>( self, sid: impl IntoVSID<'s>, flags: impl IntoAceFlags, access_mask: impl IntoAccessMask, filter: impl IntoOptionalACEFilter ) -> Result<impl ACLEntryIterator<'r, K>> where Self: Sized, K: IsACLKind<DACL> {
        self.add(
            ACE::new_allow( sid, flags, access_mask ), 
            filter.into_optional_mask()
        )
    }

    #[inline]
    fn add_deny<'s: 'r>( self, sid: impl IntoVSID<'s>, flags: impl IntoAceFlags, access_mask: impl IntoAccessMask, filter: impl IntoOptionalACEFilter ) -> Result<impl ACLEntryIterator<'r, K>> where Self: Sized, K: IsACLKind<DACL> {
        self.add(
            ACE::new_deny( sid, flags, access_mask ), 
            filter.into_optional_mask()
        )
    }

    #[inline]
    fn add_audit<'s: 'r>( self, sid: impl IntoVSID<'s>, flags: impl IntoAceFlags, access_mask: impl IntoAccessMask, filter: impl IntoOptionalACEFilter ) -> Result<impl ACLEntryIterator<'r, K>> where Self: Sized, K: IsACLKind<SACL> {
        self.add(
            ACE::new_audit( sid, flags, access_mask ), 
            filter.into_optional_mask()
        )
    }

    #[inline]
    fn add_mandatory_label<'s: 'r>( self, label_sid: impl IntoVSID<'s>, flags: impl IntoAceFlags, access_mask: impl IntoAccessMask, filter: impl IntoOptionalACEFilter ) -> Result<impl ACLEntryIterator<'r, K>> where Self: Sized, K: IsACLKind<SACL> {
        self.add(
            ACE::new_mandatory_label( label_sid, flags, access_mask ), 
            filter.into_optional_mask()
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
    fn remove<'s: 'r>( self, sid: &'s SIDRef, filter: impl IntoOptionalACEFilter ) -> Result<impl ACLEntryIterator<'r, K>> where Self: Sized {
        ACLListEntryRemover::new(
            self, 
            sid,
            filter.into_optional_mask()
        )
    }

    fn remove_any_sid<'s>( self, filter: ACEFilter ) -> Result<impl ACLEntryIterator<'r, K>> where Self: Sized {
        ACLListEntryRemover::new_any_sid(
            self, 
            filter
        )
    }

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct ACL<'r, K: ACLKind> {
    pacl: *const _ACL,
    _ph_r: PhantomData<&'r ()>,
    _ph_k: PhantomData<K>,
}
 
impl<'r, K: ACLKind> ACL<'r, K> {
    /// Warning: pacl may be NULL
    pub unsafe fn from_pacl( pacl: *const _ACL ) -> ACL<'static, K> {
        ACL {
            pacl,
            _ph_r: PhantomData,
            _ph_k: PhantomData,
        }
    }

    pub fn from_null() -> ACL<'static, K> {
        ACL {
            pacl: null(),
            _ph_r: PhantomData,
            _ph_k: PhantomData,
        }
    }

    pub(crate) unsafe fn from_descriptor<'d>( _descriptor: &'d WindowsSecurityDescriptor, pacl: Option<*const _ACL> ) -> ACL<'d, K> {
        let pacl = pacl.unwrap_or(null());
        ACL {
            pacl,
            _ph_r: PhantomData,
            _ph_k: PhantomData,
        }
    }

    pub fn ace_count( &self ) -> u16 {
        if !self.pacl.is_null() {
            unsafe { (*self.pacl).AceCount }
        } else {
            0
        }
    }

    /// Warning: may return NULL
    pub fn pacl(&self) -> *const _ACL {
        self.pacl
    }

    pub fn iter_hdr( &self ) -> AceHdrIterator<'r> {
        AceHdrIterator::new(self.pacl)
    }

    pub fn iter_entry_hdr( &self ) -> AceEntryHdrIterator<'r, K> {
        AceEntryHdrIterator::new(self.pacl)
    }

    pub fn iter<'s>( &'s self ) -> AceEntryIterator<'s, K> where 'r: 's {
        AceEntryIterator::new(self.pacl)
    }

    /// Returns a `Vec<ACLEntry>` of access control list entries for the specified named object path.
    pub fn all(&self) -> Result<Vec<ACE<'_, K>>> {
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
    pub fn all_filtered<'s>(&'s self, sid: &SIDRef, mask: impl IntoOptionalACEFilter ) -> Result<Vec<ACE<'s, K>>> {
        let mask = mask.into_optional_mask();

        self.iter()
            .filter(|entry| {
                if let Some(mask) = mask.as_ref() {
                    if !entry.is_match_any_sid(mask) {
                        return Ok(false);
                    }
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

    pub fn as_list<'s>( &'s self ) -> Result<ACL<'s, K>> {
        let pacl = self.pacl()?;
        let acl = unsafe { ACL::from_pacl(pacl) };
        Ok(acl)
    }

    pub fn from_iter<'r, I>(mut iter: I) -> Result<Self> where I: ACLEntryIterator<'r, K> {
        let max_count = iter.predict_max_count()?;
        let max_size = min( 
            max_count.saturating_mul(AVERAGE_ACE_SIZE).saturating_add(size_of::<_ACL>() as u16), 
            MAX_ACL_SIZE 
        );

        let mut buffer = [0u8].repeat(max_size as usize );

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
                Err(err) if err.code() == HRESULT::from_nt(STATUS_ALLOTTED_SPACE_EXCEEDED.0) => {
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

        let buffer_range = buffer[..].as_ptr_range();

        let buffer_start = buffer_range.start as *const u8;
        let acl_start = pacl as *const u8;
        let acl_end = pfreeace as *const u8;
        let buffer_end = buffer_range.end as *const u8;

        if !(buffer_start == acl_start && acl_start <= acl_end && acl_end <= buffer_end) {
            return Err(Error::empty());
        }

        let acl_size =  unsafe { acl_end.offset_from_unsigned(acl_start) }
            .try_into().map_err(|_| Error::empty())?;

        debug_assert!( acl_size as usize <= buffer.capacity() );
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

pub struct AceHdrIterator<'r> {
    acl: *const _ACL,
    idx: u16,
    ace_count: u16,
    _ph: PhantomData<&'r ()>,
}

impl<'r> AceHdrIterator<'r> {
    fn new( acl: *const _ACL ) -> Self {
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

    #[inline]
    fn current_item_idx( &self ) -> Option<u16> {
        if self.idx > 0 {
            Some(self.idx - 1)
        } else {
            None
        }
    }
}

impl<'r> FallibleIterator for AceHdrIterator<'r> {
    type Item = &'r ACE_HEADER;
    type Error = Error;

    fn next( &mut self ) -> Result<Option<Self::Item>> {
        if self.idx >= self.ace_count {
            return Ok(None);
        }

        debug_assert!( !self.acl.is_null() );

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

impl<'r> MaxCountPredictor for AceHdrIterator<'r> {
    fn predict_max_count( &self ) -> Result<u16> {
        Ok(self.ace_count)
    }
}
   

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct AceEntryHdrIterator<'r, K: ACLKind> {
    inner: AceHdrIterator<'r>,
    _ph: PhantomData<K>,
}

impl<'r, K: ACLKind> AceEntryHdrIterator<'r, K> {
    fn new( acl: *const _ACL ) -> Self {
        Self {
            inner: AceHdrIterator::new(acl),
            _ph: PhantomData,
        }
    }

    #[inline]
    fn current_item_idx( &self ) -> Option<u16> {
        self.inner.current_item_idx()
    }
}

impl<'r, K: ACLKind> FallibleIterator for AceEntryHdrIterator<'r, K> {
    type Item = (ACE<'r, K>, &'r ACE_HEADER);
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

impl<'r, K: ACLKind> MaxCountPredictor for AceEntryHdrIterator<'r, K> {
    fn predict_max_count( &self ) -> Result<u16> {
        self.inner.predict_max_count()
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct AceEntryIterator<'r, K: ACLKind> {
    inner: AceHdrIterator<'r>,
    _ph: PhantomData<K>,
}

impl<'r, K: ACLKind> AceEntryIterator<'r, K> {
    fn new( acl: *const _ACL ) -> Self {
        Self {
            inner: AceHdrIterator::new(acl),
            _ph: PhantomData,
        }
    }

    #[inline]
    fn current_item_idx( &self ) -> Option<u16> {
        self.inner.current_item_idx()
    }
}

impl<'r, K: ACLKind> FallibleIterator for AceEntryIterator<'r, K> {
    type Item = ACE<'r, K>;
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

impl<'r, K: ACLKind> MaxCountPredictor for AceEntryIterator<'r, K> {
    fn predict_max_count( &self ) -> Result<u16> {
        self.inner.predict_max_count()
    }
}

impl<'r, K: ACLKind> ACLEntryIterator<'r, K> for AceEntryIterator<'r, K> {}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub enum ACLListEntryReplaceResult<'r, K: ACLKind> {
    Ignore,
    Remove,
    Replace(ACE<'r, K>),
}

pub struct ACLListEntryReplacer<'r, I, K, F>
where
    I: ACLEntryIterator<'r, K>,
    K: ACLKind,
    F: FnMut(&ACE<'r, K>) -> Result<ACLListEntryReplaceResult<'r, K>>,
{
    inner: I,
    f: F,
    _ph: PhantomData<&'r K>,
}

impl<'r, I, K, F> ACLListEntryReplacer<'r, I, K, F>
where
    I: ACLEntryIterator<'r, K>,
    K: ACLKind,
    F: FnMut(&ACE<'r, K>) -> Result<ACLListEntryReplaceResult<'r, K>>,
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
    F: FnMut(&ACE<'r, K>) -> Result<ACLListEntryReplaceResult<'r, K>>,
{
    type Item = ACE<'r, K>;
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
    F: FnMut(&ACE<'r, K>) -> Result<ACLListEntryReplaceResult<'r, K>>,
{
    fn predict_max_count( &self ) -> Result<u16> {
        self.inner.predict_max_count()
    }
}

impl<'r, I, K, F> ACLEntryIterator<'r, K> for ACLListEntryReplacer<'r, I, K, F>
where
    I: ACLEntryIterator<'r, K>,
    K: ACLKind,
    F: FnMut(&ACE<'r, K>) -> Result<ACLListEntryReplaceResult<'r, K>>,
{}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct ACLListEntryAdder<'r, I: ACLEntryIterator<'r, K>, K: ACLKind> {
    inner: I,
    entry: Option<ACE<'r, K>>,
    filter: Option<ACEFilter>,
}

impl<'r, I: ACLEntryIterator<'r, K>, K: ACLKind> ACLListEntryAdder<'r, I, K> {
    pub fn new( inner: I, entry: ACE<'r, K>, filter: Option<ACEFilter> ) -> Result<Self> {
        let _ = entry.sid.as_ref().ok_or_else(|| Error::empty())?;
        Ok(Self {
            inner,
            entry: Some(entry),
            filter,
        })
    }
}

impl<'r, I: ACLEntryIterator<'r, K>, K: ACLKind> FallibleIterator for ACLListEntryAdder<'r, I, K> {
    type Item = ACE<'r, K>;
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

            if let Some(entry) = self.entry.take() {
                return Ok(Some(entry));
            }

            Ok(None)
        } else {
            self.inner.next()
        }
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
    sid: Option<&'s SIDRef>,
    filter: Option<ACEFilter>,
    _ph_r: PhantomData<&'r ()>,
    _ph_k: PhantomData<K>,
}

impl<'r, 's, I: ACLEntryIterator<'r, K>, K: ACLKind> ACLListEntryRemover<'r, 's, I, K> {
    pub fn new( inner: I, sid: &'s SIDRef, filter: Option<ACEFilter> ) -> Result<Self> {
        Ok(Self {
            inner,
            sid: Some(sid),
            filter,
            _ph_r: PhantomData,
            _ph_k: PhantomData,
        })
    }

    pub fn new_any_sid( inner: I, filter: ACEFilter ) -> Result<Self> {
        Ok(Self {
            inner,
            sid: None,
            filter: Some(filter),
            _ph_r: PhantomData,
            _ph_k: PhantomData,
        })
    }
}

impl<'r, 's, I: ACLEntryIterator<'r, K>, K: ACLKind> FallibleIterator for ACLListEntryRemover<'r, 's, I, K> {
    type Item = ACE<'r, K>;
    type Error = Error;

    fn next(&mut self) -> Result<Option<Self::Item>> {
        if let Some(sid) = self.sid {
            while let Some(item) = self.inner.next()? {
                if item.is_match( sid, &self.filter ) {
                    continue;
                }
                return Ok(Some(item));
            }
        } else if let Some(filter) = &self.filter {
            while let Some(item) = self.inner.next()? {
                if item.is_match_any_sid( filter ) {
                    continue;
                }
                return Ok(Some(item));
            }
        } else {
            if let Some(item) = self.inner.next()? {
                return Ok(Some(item));
            }
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

impl<'r, I: ACLEntryIterator<'r, K>, K: ACLKind> FromACLEntryIterator<'r, I, K> for Vec<ACE<'r, K>> {
    fn from_iter(mut iter: I) -> Result<Self> {
        let mut result = vec![];

        while let Some(entry) = iter.next()? {
            result.push(entry);
        }
        
        Ok(result)
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct ACEWithInheritedFromIterator<'r, K: ACLKind> {
    inner: AceEntryIterator<'r, K>,
    inherited_from: WindowsInheritedFrom,    
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct ACEWithInheritedFrom<'r, K: ACLKind> {
    pub ace: ACE<'r, K>,
    pub generation_gap: i32,
    pub ancestor_name: Option<OsString>,
}

impl<'r, K: ACLKind> ACEWithInheritedFromIterator<'r, K> {
    pub(crate) fn new( acl: *const _ACL, inherited_from: WindowsInheritedFrom ) -> Self {
        Self {
            inner: AceEntryIterator::new(acl),
            inherited_from,
        }
    }
}

impl<'r, K: ACLKind> FallibleIterator for ACEWithInheritedFromIterator<'r, K> {
    type Item = ACEWithInheritedFrom<'r, K>;
    type Error = Error;

    fn next(&mut self) -> Result<Option<Self::Item>> {
        while let Some(ace) = self.inner.next()? {
            let idx = self.inner.current_item_idx().ok_or_else(|| Error::empty())?;
            let if_item = self.inherited_from.get(idx).ok_or_else(|| Error::empty())?;

            let item = ACEWithInheritedFrom {
                ace,
                generation_gap: WindowsInheritedFrom::generation_gap(if_item),
                ancestor_name: WindowsInheritedFrom::ancestor_name(if_item)?,
            };

            return Ok(Some(item));
        }

        Ok(None)
    }
}
