use windows::{
    core::{
        Error, HRESULT,
    },
    Win32::{
            Foundation::{
                ERROR_INSUFFICIENT_BUFFER, ERROR_ACCESS_DENIED, ERROR_NOT_ALL_ASSIGNED,
            },
    },
};

pub trait ErrorExt {
    fn is_access_denied( &self ) -> bool;
    fn is_insufficient_buffer( &self ) -> bool;
    fn is_not_all_assigned( &self ) -> bool;
}

impl ErrorExt for Error {
    fn is_access_denied( &self ) -> bool {
        self.code() == HRESULT::from_win32(ERROR_ACCESS_DENIED.0)
    }

    fn is_insufficient_buffer( &self ) -> bool {
        self.code() == HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0)
    }

    fn is_not_all_assigned( &self ) -> bool {
        self.code() == HRESULT::from_win32(ERROR_NOT_ALL_ASSIGNED.0)
    }
}
