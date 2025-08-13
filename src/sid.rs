#![allow(non_snake_case)]

use core::{
    ffi::c_void,
    ptr::{null_mut},
    fmt,
    mem,
};
use crate::{
    utils::{str_to_wstr},
};
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
            }, CopySid, CreateWellKnownSid, EqualSid, GetLengthSid, GetTokenInformation, GetWindowsAccountDomainSid, IsValidSid, LookupAccountNameW, TokenUser, PSID, SID_NAME_USE, TOKEN_QUERY, WELL_KNOWN_SID_TYPE, SID_AND_ATTRIBUTES, SECURITY_MAX_SID_SIZE,
        },
        System::Threading::{
                GetCurrentThread, GetCurrentProcess, OpenThreadToken, OpenProcessToken,
            },
    },
};

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SID {
    sid: Vec<u8>,
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

impl SID {
    #[inline]
    pub fn empty() -> Self {
        Self {
            sid: vec![],
        }
    }

    pub fn well_known( well_known_sid_type: WELL_KNOWN_SID_TYPE, domain_sid: Option<&SID> ) -> Result<Self> {
        let mut sid_size: u32 = 0;

        match unsafe {
            CreateWellKnownSid(
                well_known_sid_type, 
                domain_sid.and_then(|sid| sid.psid()), 
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
                domain_sid.and_then(|sid| sid.psid()), 
                Some(PSID(sid.as_mut_ptr() as *mut c_void)),
                &mut sid_size
            )        
        }?;

        unsafe { sid.set_len(sid_size as usize) };

        Ok(Self {
            sid
        })
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

    /// Converts a raw SID into a SID string representation.
    ///
    /// # Arguments
    /// * `sid` - A pointer to a raw SID buffer. In native Windows, this is would be a `PSID` type.
    ///
    /// # Errors
    /// On error, a Windows error code is returned with the `Err` type.
    pub fn to_string( &self ) -> Result<String> {
        if self.is_empty() {
            return Ok(String::new());
        }

        let mut raw_string_sid: PWSTR = PWSTR::null();
        unsafe { ConvertSidToStringSidW( self.psid_unchecked(), &mut raw_string_sid) }?;
        if raw_string_sid.is_null() {
            return Err(Error::empty());
        }

        let string_sid = unsafe { raw_string_sid.to_string() }
            .map_err(|_| Error::empty())?;

        unsafe { LocalFree(Some(HLOCAL(raw_string_sid.as_ptr() as *mut c_void))) };

        Ok(string_sid)
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

        unsafe { sid.set_len(size as usize) };

        Ok(Self {
            sid,
        })
    }

    pub fn get_domain_of( &self ) -> Result<Self> {
        let Some(psid) = self.psid() else {
            return Err(Error::empty());
        };

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

        Ok(Self {
            sid: domain_sid,
        })

    }

    #[inline]
    pub fn is_empty( &self ) -> bool {
        self.sid.is_empty()
    }

    #[inline]
    pub fn len( &self ) -> u32 {
        self.sid.len() as u32
    }

    pub fn is_valid( &self ) -> bool {
        if self.is_empty() {
            return false;
        }

        unsafe { IsValidSid(self.psid_unchecked()) }.as_bool()
    }

    pub fn is_equal_to_psid( &self, other: PSID ) -> bool {
        unsafe { EqualSid(PSID(self.sid.as_ptr() as *mut _), other) }.is_ok()
    }

    #[inline(always)]
    fn psid_unchecked( &self ) -> PSID {
        PSID(self.sid.as_ptr() as *mut c_void)
    }

    #[inline(always)]
    pub fn psid( &self ) -> Option<PSID> {
        if self.is_empty() {
            return None;
        }

        Some(self.psid_unchecked())
    }
}