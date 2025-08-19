#![allow(non_snake_case)]

use core::{
    ffi::c_void, fmt, mem, ptr::null_mut, slice, cmp, hash
};
use std::fmt::Debug;
use crate::utils::{str_to_wstr, DebugUnpretty, MaybePtr};
use windows::{
    core::{
        Error, Result, HRESULT, PWSTR  
    },
    Win32::{
        Foundation::{
            CloseHandle, LocalFree, ERROR_INSUFFICIENT_BUFFER, HANDLE, HLOCAL
        },
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSidToSidW,
            }, 
            CopySid, CreateWellKnownSid, EqualSid, GetLengthSid, GetTokenInformation, 
            GetWindowsAccountDomainSid, IsValidSid, LookupAccountNameW, TokenUser, PSID, 
            SID_NAME_USE, TOKEN_QUERY, WELL_KNOWN_SID_TYPE, SID_AND_ATTRIBUTES, 
            SECURITY_MAX_SID_SIZE, LookupAccountSidW,
        },
        System::Threading::{
                GetCurrentProcess, OpenProcessToken,
            },
    },
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/// Reference to SID bytes.
/// Guaranted to be non-null and valid. Size is precalculated.
#[derive(Clone, Copy, Hash)]
pub struct SIDRef<'r>( &'r [u8] );

impl<'r> SIDRef<'r> {
    pub fn from_psid( psid: PSID ) -> Result<Option<Self>> {
        if psid.is_invalid() || !unsafe { IsValidSid(psid) }.as_bool() {
            return Ok(None);
        }

        let sid = unsafe { Self::from_psid_unchecked(psid) }?;
        Ok(Some(sid))
    }

    pub unsafe fn from_psid_unchecked( psid: PSID ) -> Result<Self> {
        let sid_size = unsafe { GetLengthSid(psid) };

        let sid = unsafe { slice::from_raw_parts( psid.0 as *const u8, sid_size as usize ) };

        Ok(Self(sid))
    }

    pub fn to_sid( &self ) -> Result<SID> {
        let psid = self.psid();
        let sid_size = self.len();

        let mut sid: Vec<u8> = Vec::with_capacity(sid_size as usize);
        unsafe { sid.set_len(sid_size as usize) };

        unsafe { 
            CopySid(
                sid_size, 
                PSID(sid.as_mut_ptr() as *mut c_void), 
                psid
            )
        }?;

        Ok(SID { 
            sid
        })
    }

    pub fn into_vsid( self ) -> VSID<'r> {
        VSID::Ptr(self)
    }

    pub fn to_vsid<'s: 'r>( &'s self ) -> VSID<'s> {
        VSID::Ptr(*self)
    }

    pub fn to_owned_vsid( &self ) -> Result<VSID<'static>> {
        let sid = self.to_sid()?;
        Ok(VSID::Value(sid))
    }

    pub fn lookup_account_name( &self, domain_name: Option<&str> ) -> Result<(String, String)> {
        let mut domain_name: Option<Vec<u16>> = domain_name.map(|domain_name| str_to_wstr(domain_name));
        let domain_name = domain_name.as_mut()
            .map(|domain_name| PWSTR::from_raw(domain_name.as_mut_ptr()))
            .unwrap_or(PWSTR::null());

        let mut name_len: u32 = 0;
        let mut referenced_domain_name_len: u32 = 0;
        let mut sid_type: SID_NAME_USE = SID_NAME_USE(0);

        match unsafe {
            LookupAccountSidW(
                domain_name,
                self.psid(),
                None,
                &mut name_len,
                None,
                &mut referenced_domain_name_len,
                &mut sid_type
            )
        } {
            Ok(()) => {
                return Err(Error::empty());
            },
            Err(e) if e.code() != HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0) => {
                return Err(e);
            },
            Err(_) => {}

        };

        let mut name = [0_u16].repeat( (name_len as usize) + 1 );
        let mut referenced_domain_name = [0_u16].repeat( (referenced_domain_name_len as usize) + 1 );

        let name = PWSTR::from_raw(name.as_mut_ptr());
        let referenced_domain_name = PWSTR::from_raw(referenced_domain_name.as_mut_ptr());

        unsafe {
            LookupAccountSidW(
                domain_name,
                self.psid(),
                Some(name),
                &mut name_len,
                Some(referenced_domain_name),
                &mut referenced_domain_name_len,
                &mut sid_type
            )
        }?;

        let name = unsafe { name.to_string() }
            .map_err(|_| Error::empty())?;
        let referenced_domain_name = unsafe { referenced_domain_name.to_string() }
            .map_err(|_| Error::empty())?;

        Ok((name, referenced_domain_name))
    }

    /// Converts a raw SID into a SID string representation.
    ///
    /// # Arguments
    /// * `sid` - A pointer to a raw SID buffer. In native Windows, this is would be a `PSID` type.
    ///
    /// # Errors
    /// On error, a Windows error code is returned with the `Err` type.
    pub fn to_string( &self ) -> Result<String> {
        let mut raw_string_sid: PWSTR = PWSTR::null();
        unsafe { ConvertSidToStringSidW( self.psid(), &mut raw_string_sid) }?;
        if raw_string_sid.is_null() {
            return Err(Error::empty());
        }

        let string_sid = unsafe { raw_string_sid.to_string() }
            .map_err(|_| Error::empty())?;

        unsafe { LocalFree(Some(HLOCAL(raw_string_sid.as_ptr() as *mut c_void))) };

        Ok(string_sid)
    }

    pub fn get_domain_of( &self ) -> Result<SID> {
        let psid = self.psid();
        let mut domain_sid_size: u32 = 0;

        match unsafe {
            GetWindowsAccountDomainSid(
                psid, 
                None, 
                &mut domain_sid_size,
            )        
        } {
            Ok(()) => {
                return Err(Error::empty());
            },
            Err(e) if e.code() != HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0) => {
                return Err(e);
            },
            Err(_) => {}
        };

        if domain_sid_size == 0 {
            return Err(Error::empty());
        }

        let mut domain_sid = Vec::with_capacity(domain_sid_size as usize);

        unsafe {
            GetWindowsAccountDomainSid(
                psid, 
                Some(PSID(domain_sid.as_mut_ptr() as *mut c_void)),
                &mut domain_sid_size
            )        
        }?;

        unsafe { domain_sid.set_len(domain_sid_size as usize) };

        Ok(SID {
            sid: domain_sid,
        })

    }

    //

    #[inline]
    pub fn len( &self ) -> u32 {
        self.0.len() as u32
    }
    
    //

    pub fn eq_to_psid( &self, other: PSID ) -> bool {
        if other.is_invalid() || !unsafe { IsValidSid(other) }.as_bool() {
            return false;
        }

        unsafe { EqualSid( self.psid(), other) }.is_ok()
    }

    #[inline]
    pub fn eq( &self, other: &Self ) -> bool {
        unsafe { EqualSid( self.psid(), other.psid() ) }.is_ok()
    }

    pub fn cmp_to_psid( &self, other: PSID ) -> Option<cmp::Ordering> {
        let Some(other_sidref) = Self::from_psid(other).ok()? else {
            return Some(cmp::Ordering::Greater);
        };

        if self.eq( &other_sidref ) {
            return Some(cmp::Ordering::Equal);
        }

        self.cmp(&other_sidref)
    }

    #[inline]
    pub fn cmp( &self, other: &Self ) -> Option<cmp::Ordering> {
        PartialOrd::partial_cmp( &self.0, &other.0 )
    }

    //

    #[inline(always)]
    pub fn psid( &self ) -> PSID {
        PSID(self.0.as_ptr() as *mut c_void)
    }
}

impl<'r> fmt::Debug for SIDRef<'r> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sid_str = match self.lookup_account_name(None) {
            Ok((name, mut domain_name)) => {
                if !domain_name.is_empty() {
                    domain_name.push('\\');   
                    domain_name.push_str(&name);   
                    domain_name
                } else {
                    name
                }
            },
            Err(_) => {
                match self.to_string() {
                    Ok(s) => {
                        s
                    },
                    Err(_) => {
                        format!( "{:?}", &self.0 )
                    }
                }
            }
        };

        f.write_fmt(format_args!("SIDRef({:?})", &sid_str))
    }
}

impl<'r> cmp::PartialEq for SIDRef<'r> {
    fn eq(&self, other: &Self) -> bool {
        self.eq(other)
    }
}

impl<'r> cmp::Eq for SIDRef<'r> {}

impl<'r> cmp::PartialOrd for SIDRef<'r> {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        self.cmp(other)
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#[derive(Clone, Hash)]
pub struct SID {
    sid: Vec<u8>,
}

impl SID {
    pub fn from_ref( r: SIDRef ) -> Result<Self> {
        r.to_sid()
    }

    pub fn from_psid( psid: PSID ) -> Result<Self> {
        if !unsafe { IsValidSid(psid) }.as_bool() {
            return Err(Error::empty());
        }

        let sid_size = unsafe { GetLengthSid(psid) };
        let mut sid: Vec<u8> = Vec::with_capacity(sid_size as usize);

        unsafe { 
            CopySid(
                sid_size, 
                PSID(sid.as_mut_ptr() as *mut c_void), 
                psid
            )
        }?;

        unsafe { sid.set_len(sid_size as usize) };

        let this = Self { 
            sid
        };

        Ok(this)
    }

    pub fn well_known( well_known_sid_type: WELL_KNOWN_SID_TYPE, domain_sid: Option<&SID> ) -> Result<Self> {
        let mut sid_size: u32 = 0;

        match unsafe {
            CreateWellKnownSid(
                well_known_sid_type, 
                domain_sid.map(|sid| sid.psid()), 
                None,
                &mut sid_size
            )        
        } {
            Ok(()) => {
                return Err(Error::empty());
            },
            Err(e) if e.code() != HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0) => {
                return Err(e);
            },
            Err(_) => {}
        };

        if sid_size == 0 {
            return Err(Error::empty());
        }

        let mut sid = Vec::with_capacity(sid_size as usize);

        unsafe {
            CreateWellKnownSid(
                well_known_sid_type, 
                domain_sid.map(|sid| sid.psid()), 
                Some(PSID(sid.as_mut_ptr() as *mut c_void)),
                &mut sid_size
            )        
        }?;

        unsafe { sid.set_len(sid_size as usize) };

        Ok(Self {
            sid
        })
    }

    pub fn current_user() -> Result<Self> {
        let hProcess = unsafe { GetCurrentProcess() };
        
        let mut hToken: HANDLE = HANDLE(null_mut());
        unsafe {
            OpenProcessToken( 
                hProcess, 
                TOKEN_QUERY, 
                &mut hToken
            )
        }?;

        //

        let mut sid_and_attributes_size: u32 = 0;

        match unsafe {
            GetTokenInformation(
                hToken, 
                TokenUser, 
                None,
                0, 
                &mut sid_and_attributes_size
            )        
        } {
            Ok(()) => {
                unsafe { CloseHandle( hProcess ) }?;
                return Err(Error::empty());
            },
            Err(e) if e.code() != HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0) => {
                let _ = unsafe { CloseHandle( hProcess ) };
                return Err(e);
            },
            Err(_) => {}
        };

        if sid_and_attributes_size == 0 {
            unsafe { CloseHandle( hProcess ) }?;
            return Err(Error::empty());
        }

        let mut sid_and_attributes_buf = Vec::with_capacity(sid_and_attributes_size as usize);

        match unsafe {
            GetTokenInformation(
                hToken, 
                TokenUser, 
                Some(sid_and_attributes_buf.as_mut_ptr() as *mut c_void),
                sid_and_attributes_size, 
                &mut sid_and_attributes_size
            )        
        } {
            Ok(()) => {},
            Err(e) => {
                let _ = unsafe { CloseHandle( hProcess ) };
                return Err(e);
            }
        };

        unsafe { CloseHandle( hProcess ) }?;

        unsafe { sid_and_attributes_buf.set_len(sid_and_attributes_size as usize) };

        //

        let sid_and_attributes = sid_and_attributes_buf.as_ptr() as *const SID_AND_ATTRIBUTES;
        let psid = unsafe{ (*sid_and_attributes).Sid };

        //

        Self::from_psid(psid)
    }

    /// Resolves a system username (either in the format of "user" or "DOMAIN\user") into a raw SID. The raw SID
    /// is represented by a `Vec<u8>` object.
    ///
    /// # Arguments
    /// * `name` - The user name to be resolved into a raw SID.
    /// * `system` - An optional string denoting the scope of the user name (such as a machine or domain name). If not required, use `None`.
    ///
    /// # Errors
    /// On error, a Windows error code is returned with the `Err` type.
    ///
    /// **Note**: If the error code is 0, `GetLastError()` returned `ERROR_INSUFFICIENT_BUFFER` after invoking `LookupAccountNameW` or
    ///         the `sid_size` is 0.
    pub fn from_account_name(name: &str, system: Option<&str>) -> Result<Self> {
        let mut name: Vec<u16> = str_to_wstr(name);
        let name = PWSTR::from_raw(name.as_mut_ptr());

        let mut system: Option<Vec<u16>> = system.map(|name| str_to_wstr(name));
        let system: PWSTR = system.as_mut()
            .map(|system| PWSTR::from_raw(system.as_mut_ptr()))
            .unwrap_or_else(|| PWSTR::null());

        let mut sid_size: u32 = 0;
        let mut sid_type: SID_NAME_USE = SID_NAME_USE(0);

        let mut domain_name_size: u32 = 0;

        match unsafe { 
            LookupAccountNameW(
                system,
                name,
                None,
                &mut sid_size,
                None,
                &mut domain_name_size,
                &mut sid_type,
            )
        } {
            Ok(()) => {
                return Err(Error::empty());
            },
            Err(e) if e.code() != HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0) => {
                return Err(e);
            },
            Err(_) => {}
        };

        if sid_size == 0 {
            return Err(Error::empty());
        }

        let mut sid: Vec<u8> = Vec::with_capacity(sid_size as usize);
        let mut domain_name: Vec<u8> = Vec::with_capacity((domain_name_size as usize) * mem::size_of::<u16>());

        unsafe {
            LookupAccountNameW(
                system,
                name,
                Some(PSID(sid.as_mut_ptr() as *mut c_void)),
                &mut sid_size,
                Some(PWSTR::from_raw(domain_name.as_mut_ptr() as *mut u16)),
                &mut domain_name_size,
                &mut sid_type,
            )
        }?;

        unsafe { sid.set_len(sid_size as usize) };

        Ok(Self {
            sid
        })
    }

    /// Converts a string representation of a SID into a raw SID. The returned raw SID is contained in a `Vec<u8>` object.
    ///
    /// # Arguments
    /// * `string_sid` - The SID to converted into raw form as a string.
    ///
    /// # Errors
    /// On error, a Windows error code is wrapped in an `Err` type.
    pub fn from_str(string_sid: &str) -> Result<Self> {
        let mut raw_string_sid: Vec<u16> = str_to_wstr(string_sid);
        let raw_string_sid = PWSTR::from_raw(raw_string_sid.as_mut_ptr());

        let mut psid: PSID = PSID(null_mut());
        unsafe { ConvertStringSidToSidW(raw_string_sid, &mut psid) }?;

        let size = unsafe { GetLengthSid(psid) };
        let mut sid: Vec<u8> = Vec::with_capacity(size as usize);

        unsafe { 
            CopySid(
                size, 
                PSID(sid.as_mut_ptr() as *mut c_void), 
                psid
            )
        }?;

        unsafe { LocalFree(Some(HLOCAL(psid.0))) };

        unsafe { sid.set_len(size as usize) };

        Ok(Self {
            sid,
        })
    }

    //

    pub fn as_ref<'r>( &'r self ) -> SIDRef<'r> {
        SIDRef( self.sid.as_slice() )
    }

    pub fn into_vsid( self ) -> VSID<'static> {
        VSID::Value(self)
    }

    pub fn to_vsid<'s>( &'s self ) -> VSID<'s> {
        let r = self.as_ref();
        VSID::Ptr(r)
    }

    pub fn to_owned_vsid( &self ) -> VSID<'static> {
        VSID::Value(self.clone())
    }

    /// Converts a raw SID into a SID string representation.
    ///
    /// # Arguments
    /// * `sid` - A pointer to a raw SID buffer. In native Windows, this is would be a `PSID` type.
    ///
    /// # Errors
    /// On error, a Windows error code is returned with the `Err` type.
    pub fn to_string( &self ) -> Result<String> {
        self.as_ref().to_string()
    }

    pub fn get_domain_of( &self ) -> Result<Self> {
        self.as_ref().get_domain_of()
    }

    //

    #[inline]
    pub fn len( &self ) -> u32 {
        self.sid.len() as u32
    }

    //

    pub fn eq_to_psid( &self, other: PSID ) -> bool {
        if !other.is_invalid() || !unsafe { IsValidSid(other) }.as_bool() {
            return false;
        }

        unsafe { EqualSid(self.psid(), other) }.is_ok()
    }

    pub fn eq_to_ref<'rr>( &self, other: SIDRef<'rr>) -> bool {
        self.as_ref().eq(&other)
    }

    pub fn eq( &self, other: &Self ) -> bool {
        unsafe { EqualSid( self.psid(), other.psid() ) }.is_ok()
    }

    pub fn cmp_to_psid( &self, other: PSID ) -> Option<cmp::Ordering> {
        // Invalid, null or empty SIDs are always less then valid

        let Some(other_sidref) = SIDRef::from_psid(other).ok()? else {
            return Some(cmp::Ordering::Greater);
        };

        let self_sidref = self.as_ref();

        self_sidref.cmp(&other_sidref)
    }

    pub fn cmp( &self, other: &Self ) -> Option<cmp::Ordering> {
        // Invalid, null or empty SIDs are always less then valid

        let self_sidref = self.as_ref();
        let other_sidref = other.as_ref();

        self_sidref.cmp(&other_sidref)
    }

    //

    #[inline(always)]
    pub fn psid( &self ) -> PSID {
        PSID(self.sid.as_ptr() as *mut c_void)
    }
}

impl fmt::Debug for SID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_tuple("SID");
        let f = match self.to_string() {
            Ok(s) => {
                f.field(&s)
            },
            Err(_) => {
                f.field(&self.sid)
            }
        };
        f.finish()
    }
}

impl cmp::PartialEq for SID {
    fn eq(&self, other: &Self) -> bool {
        self.eq(other)
    }
}

impl cmp::Eq for SID {}

impl cmp::PartialOrd for SID {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        self.cmp(other)
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub type VSID<'r> = MaybePtr<SIDRef<'r>, SID>;

impl<'r> VSID<'r> {
    pub fn empty() -> VSID<'static>{
        MaybePtr::None
    }

    pub unsafe fn from_psid( psid: PSID ) -> Result<Self> {
        let Some(sidref) = SIDRef::from_psid(psid)? else {
            return Ok(MaybePtr::None);
        };

        Ok(MaybePtr::Ptr(sidref))
    }

    pub unsafe fn from_psid_or_empty( psid: PSID ) -> Self {
        Self::from_psid(psid).unwrap_or(Self::None)
    }

    pub fn from_str(string_sid: &str) -> Result<VSID<'static>> {
        let sid = SID::from_str(string_sid)?;
        Ok(MaybePtr::Value(sid))
    }

    pub fn from_account_name(name: &str, system: Option<&str>) -> Result<VSID<'static>> {
        let sid = SID::from_account_name(name, system)?;
        Ok(MaybePtr::Value(sid))
    }

    pub fn to_string(&self) -> Result<String> {
        match self {
            Self::None => {
                Ok(String::new())
            },
            Self::Ptr(p) => {
                p.to_string()
            },
            Self::Value(v) => {
                v.to_string()
            }
        }
    }

    pub fn get_domain_of( &self ) -> Result<SID> {
        match self {
            Self::None => {
                Err(Error::empty())
            },
            Self::Ptr(p) => {
                p.get_domain_of()
            },
            Self::Value(v) => {
                v.get_domain_of()
            }
        }
    }

    //

    pub fn to_owned( &self ) -> Result<VSID<'static>> {
        Ok(
            match self {
                MaybePtr::None => {
                    MaybePtr::None
                },
                MaybePtr::Ptr(p) => {
                    MaybePtr::Value(p.to_sid()?)
                },
                MaybePtr::Value(v) => {
                    MaybePtr::Value(v.clone())
                }
            }
        )
    }

    pub fn into_owned_inplace( &mut self ) -> Result<&mut VSID<'static>> {
        match self {
            MaybePtr::Ptr(p) => {
                *self = MaybePtr::Value(p.to_sid()?);
            },
            MaybePtr::None | MaybePtr::Value(_) => {},
        }

        debug_assert!( matches!(self, MaybePtr::None | MaybePtr::Value(_)) );

        // No more referential data, only static types -- so converting to 'static is safe
        let static_self = unsafe { core::mem::transmute::<&mut VSID<'r>, &mut VSID<'static>>(self) };

        Ok(static_self)
    }

    pub fn as_ref<'s: 'r>( &'s self ) -> Option<SIDRef<'s>> {
        match self {
            Self::None => {
                None
            },
            Self::Ptr(p) => {
                Some(p.clone())
            },
            Self::Value(v) => {
                Some(v.as_ref())
            }
        }
    }

    //

    pub fn len( &self ) -> u32 {
        match self {
            Self::None => {
                0
            },
            Self::Ptr(p) => {
                p.len()
            },
            Self::Value(v) => {
                v.len()
            }
        }
    }

    pub fn is_valid( &self ) -> bool {
        match self {
            Self::None => {
                false
            },
            Self::Ptr(_) | Self::Value(_)=> {
                true
            },
        }
    }

    //

    pub fn eq_to_psid( &self, other: PSID) -> bool {
        let self_ref = self.as_ref();
        let other_ref = SIDRef::from_psid(other).ok().flatten();
        
        match (self_ref, other_ref) {
            (None, None) => { true },
            (None, Some(_)) => { false },
            (Some(_), None) => { false },
            (Some(s), Some(o)) => { s.eq(&o) }
        }        
    }

    pub fn eq_to_ref<'rr>( &self, other: SIDRef<'rr>) -> bool {
        let self_ref = self.as_ref();
        
        match self_ref {
            None => { false },
            Some(s) => { s.eq(&other) }
        }        
    }

    pub fn eq<'rr>( &self, other: &VSID<'rr>) -> bool {
        let self_ref = self.as_ref();
        let other_ref = other.as_ref();

        match (self_ref, other_ref) {
            (None, None) => { true },
            (None, Some(_)) => { false },
            (Some(_), None) => { false },
            (Some(s), Some(o)) => { s.eq(&o) }
        }        
    }

    pub fn cmp_to_psid( &self, other: PSID ) -> Option<cmp::Ordering> {
        // Invalid, null or empty SIDs are always less then valid

        let self_ref = self.as_ref();
        let other_ref = SIDRef::from_psid(other).ok().flatten();
        
        match (self_ref, other_ref) {
            (None, None) => { None },
            (None, Some(_)) => { Some(cmp::Ordering::Less) },
            (Some(_), None) => { Some(cmp::Ordering::Greater) },
            (Some(s), Some(o)) => { s.cmp(&o) }
        }        
    }

    pub fn cmp( &self, other: &Self ) -> Option<cmp::Ordering> {
        // Invalid, null or empty SIDs are always less then valid

        let self_ref = self.as_ref();
        let other_ref = other.as_ref();

        match (self_ref, other_ref) {
            (None, None) => { None },
            (None, Some(_)) => { Some(cmp::Ordering::Less) },
            (Some(_), None) => { Some(cmp::Ordering::Greater) },
            (Some(s), Some(o)) => { s.cmp(&o) }
        }        
    }

    //

    pub fn psid(&self) -> Option<PSID> {
        match self {
            Self::None => {
                None
            },
            Self::Ptr(p) => {
                Some(p.psid())
            },
            Self::Value(v) => {
                Some(v.psid())
            }
        }
    }

}

impl<'r> Clone for VSID<'r> {
    fn clone(&self) -> Self {
        match self {
            Self::None => Self::None,
            Self::Ptr(r) => Self::Ptr(*r),
            Self::Value(v) => Self::Value(v.clone()),
        }
    }
}

impl<'r> Debug for VSID<'r> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => {
                f.debug_tuple("VSID(None)").finish()
            },
            Self::Ptr(p) => {
                Debug::fmt(p, f)
            },
            Self::Value(v) => {
                Debug::fmt(v, f)
            },            
        }
    }
}

impl<'r> cmp::PartialEq for VSID<'r> {
    fn eq(&self, other: &Self) -> bool {
        self.eq(other)
    }
}

impl<'r> cmp::Eq for VSID<'r> {}

impl<'r> cmp::PartialOrd for VSID<'r> {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        self.cmp(other)
    }
}

impl<'r> hash::Hash for VSID<'r> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            Self::None => {
                // do nothing
            },
            Self::Ptr(p) => {
                hash::Hash::hash(p, state);
            },
            Self::Value(v) => {
                hash::Hash::hash(v, state);
            },            
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

pub trait IntoVSID<'s> {
    fn into_vsid( self ) -> VSID<'s>;
}

impl<'s, 'r: 's> IntoVSID<'s> for SIDRef<'r> {
    fn into_vsid( self ) -> VSID<'s> {
        self.into_vsid()
    }
}

impl<'s> IntoVSID<'s> for SID {
    fn into_vsid( self ) -> VSID<'s> {
        self.into_vsid()
    }
}

impl<'s> IntoVSID<'s> for VSID<'s> {
    fn into_vsid( self ) -> VSID<'s> {
        self
    }
}

impl<'s, 'r: 's> IntoVSID<'s> for &'r SID {
    fn into_vsid( self ) -> VSID<'s> {
        self.to_vsid()
    }
}

