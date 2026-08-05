//! Low-level IPP (Internet Printing Protocol) request and response handling
//!
//! This module provides type-safe wrappers around CUPS IPP functions for building
//! and sending custom IPP requests. It's useful for advanced use cases that aren't
//! covered by the higher-level destination and job APIs.
//!
//! # Examples
//!
//! ## Creating and Sending an IPP Request
//!
//! ```no_run
//! use cups_rs::{IppRequest, IppOperation, IppTag, IppValueTag, ConnectionFlags, get_default_destination};
//!
//! let printer = get_default_destination().expect("No default printer");
//! let connection = printer.connect(ConnectionFlags::Scheduler, Some(5000), None)
//!     .expect("Failed to connect");
//!
//! let mut request = IppRequest::new(IppOperation::GetPrinterAttributes)
//!     .expect("Failed to create request");
//!
//! request.add_string(IppTag::Operation, IppValueTag::Uri,
//!                   "printer-uri", "ipp://localhost/printers/default")
//!     .expect("Failed to add attribute");
//!
//! let response = request.send(&connection, connection.resource_path())
//!     .expect("Failed to send request");
//!
//! if response.is_successful() {
//!     println!("Request successful!");
//! }
//! ```

use crate::bindings;
use crate::connection::HttpConnection;
use crate::error::{Error, Result};
use std::ffi::{CStr, CString};
use std::marker::PhantomData;
use std::ptr;

/// IPP attribute group tags
///
/// These tags define which group an IPP attribute belongs to in an IPP message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IppTag {
    Zero,
    Operation,
    Job,
    Printer,
    Subscription,
    EventNotification,
    Resource,
    Document,
    /// System group, used by the IPP System Service (`/ipp/system`).
    System,
    UnsupportedGroup,
}

impl From<IppTag> for bindings::ipp_tag_t {
    fn from(tag: IppTag) -> bindings::ipp_tag_t {
        match tag {
            IppTag::Zero => bindings::ipp_tag_e_IPP_TAG_ZERO,
            IppTag::Operation => bindings::ipp_tag_e_IPP_TAG_OPERATION,
            IppTag::Job => bindings::ipp_tag_e_IPP_TAG_JOB,
            IppTag::Printer => bindings::ipp_tag_e_IPP_TAG_PRINTER,
            IppTag::Subscription => bindings::ipp_tag_e_IPP_TAG_SUBSCRIPTION,
            IppTag::EventNotification => bindings::ipp_tag_e_IPP_TAG_EVENT_NOTIFICATION,
            IppTag::Resource => bindings::ipp_tag_e_IPP_TAG_RESOURCE,
            IppTag::Document => bindings::ipp_tag_e_IPP_TAG_DOCUMENT,
            IppTag::System => bindings::ipp_tag_e_IPP_TAG_SYSTEM,
            IppTag::UnsupportedGroup => bindings::ipp_tag_e_IPP_TAG_UNSUPPORTED_GROUP,
        }
    }
}

impl IppTag {
    /// Converts a raw group tag reported by libcups back into a known group.
    ///
    /// Returns `None` for values that are not group tags, so callers can reject
    /// an attribute that arrived in an unexpected part of a message instead of
    /// guessing.
    pub(crate) fn from_code(code: bindings::ipp_tag_t) -> Option<Self> {
        Some(match code {
            bindings::ipp_tag_e_IPP_TAG_ZERO => Self::Zero,
            bindings::ipp_tag_e_IPP_TAG_OPERATION => Self::Operation,
            bindings::ipp_tag_e_IPP_TAG_JOB => Self::Job,
            bindings::ipp_tag_e_IPP_TAG_PRINTER => Self::Printer,
            bindings::ipp_tag_e_IPP_TAG_SUBSCRIPTION => Self::Subscription,
            bindings::ipp_tag_e_IPP_TAG_EVENT_NOTIFICATION => Self::EventNotification,
            bindings::ipp_tag_e_IPP_TAG_RESOURCE => Self::Resource,
            bindings::ipp_tag_e_IPP_TAG_DOCUMENT => Self::Document,
            bindings::ipp_tag_e_IPP_TAG_SYSTEM => Self::System,
            bindings::ipp_tag_e_IPP_TAG_UNSUPPORTED_GROUP => Self::UnsupportedGroup,
            _ => return None,
        })
    }
}

/// IPP value tags
///
/// These tags define the type of value an IPP attribute contains. The set covers
/// both the types that can be written into a request and the out-of-band and
/// structured types that only ever arrive in a response, so
/// [`IppAttribute::value_tag`] can report what a peer actually sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IppValueTag {
    Integer,
    Boolean,
    Enum,
    String,
    Text,
    Name,
    Keyword,
    Uri,
    Charset,
    Language,
    MimeType,
    /// `textWithLanguage`, the localized form of [`IppValueTag::Text`].
    TextLang,
    /// `nameWithLanguage`, the localized form of [`IppValueTag::Name`].
    NameLang,
    UriScheme,
    Date,
    Resolution,
    Range,
    /// Start of a collection value; read the members with
    /// [`IppAttribute::get_collection`].
    BeginCollection,
    EndCollection,
    MemberName,
    UnsupportedValue,
    Default,
    Unknown,
    NoValue,
    NotSettable,
    DeleteAttr,
    AdminDefine,
    /// A tag this crate does not model, preserved so unexpected values can be
    /// reported rather than mistaken for a type we understand.
    Other(bindings::ipp_tag_t),
}

impl From<IppValueTag> for bindings::ipp_tag_t {
    fn from(tag: IppValueTag) -> bindings::ipp_tag_t {
        match tag {
            IppValueTag::Integer => bindings::ipp_tag_e_IPP_TAG_INTEGER,
            IppValueTag::Boolean => bindings::ipp_tag_e_IPP_TAG_BOOLEAN,
            IppValueTag::Enum => bindings::ipp_tag_e_IPP_TAG_ENUM,
            IppValueTag::String => bindings::ipp_tag_e_IPP_TAG_STRING,
            IppValueTag::Text => bindings::ipp_tag_e_IPP_TAG_TEXT,
            IppValueTag::Name => bindings::ipp_tag_e_IPP_TAG_NAME,
            IppValueTag::Keyword => bindings::ipp_tag_e_IPP_TAG_KEYWORD,
            IppValueTag::Uri => bindings::ipp_tag_e_IPP_TAG_URI,
            IppValueTag::Charset => bindings::ipp_tag_e_IPP_TAG_CHARSET,
            IppValueTag::Language => bindings::ipp_tag_e_IPP_TAG_LANGUAGE,
            IppValueTag::MimeType => bindings::ipp_tag_e_IPP_TAG_MIMETYPE,
            IppValueTag::TextLang => bindings::ipp_tag_e_IPP_TAG_TEXTLANG,
            IppValueTag::NameLang => bindings::ipp_tag_e_IPP_TAG_NAMELANG,
            IppValueTag::UriScheme => bindings::ipp_tag_e_IPP_TAG_URISCHEME,
            IppValueTag::Date => bindings::ipp_tag_e_IPP_TAG_DATE,
            IppValueTag::Resolution => bindings::ipp_tag_e_IPP_TAG_RESOLUTION,
            IppValueTag::Range => bindings::ipp_tag_e_IPP_TAG_RANGE,
            IppValueTag::BeginCollection => bindings::ipp_tag_e_IPP_TAG_BEGIN_COLLECTION,
            IppValueTag::EndCollection => bindings::ipp_tag_e_IPP_TAG_END_COLLECTION,
            IppValueTag::MemberName => bindings::ipp_tag_e_IPP_TAG_MEMBERNAME,
            IppValueTag::UnsupportedValue => bindings::ipp_tag_e_IPP_TAG_UNSUPPORTED_VALUE,
            IppValueTag::Default => bindings::ipp_tag_e_IPP_TAG_DEFAULT,
            IppValueTag::Unknown => bindings::ipp_tag_e_IPP_TAG_UNKNOWN,
            IppValueTag::NoValue => bindings::ipp_tag_e_IPP_TAG_NOVALUE,
            IppValueTag::NotSettable => bindings::ipp_tag_e_IPP_TAG_NOTSETTABLE,
            IppValueTag::DeleteAttr => bindings::ipp_tag_e_IPP_TAG_DELETEATTR,
            IppValueTag::AdminDefine => bindings::ipp_tag_e_IPP_TAG_ADMINDEFINE,
            IppValueTag::Other(code) => code,
        }
    }
}

impl IppValueTag {
    /// Converts a raw value tag reported by libcups into a modelled tag.
    ///
    /// Unrecognized tags become [`IppValueTag::Other`] rather than an error, so a
    /// peer sending something unexpected can be diagnosed instead of crashing
    /// the caller.
    pub(crate) fn from_code(code: bindings::ipp_tag_t) -> Self {
        match code {
            bindings::ipp_tag_e_IPP_TAG_INTEGER => Self::Integer,
            bindings::ipp_tag_e_IPP_TAG_BOOLEAN => Self::Boolean,
            bindings::ipp_tag_e_IPP_TAG_ENUM => Self::Enum,
            bindings::ipp_tag_e_IPP_TAG_STRING => Self::String,
            bindings::ipp_tag_e_IPP_TAG_TEXT => Self::Text,
            bindings::ipp_tag_e_IPP_TAG_NAME => Self::Name,
            bindings::ipp_tag_e_IPP_TAG_KEYWORD => Self::Keyword,
            bindings::ipp_tag_e_IPP_TAG_URI => Self::Uri,
            bindings::ipp_tag_e_IPP_TAG_CHARSET => Self::Charset,
            bindings::ipp_tag_e_IPP_TAG_LANGUAGE => Self::Language,
            bindings::ipp_tag_e_IPP_TAG_MIMETYPE => Self::MimeType,
            bindings::ipp_tag_e_IPP_TAG_TEXTLANG => Self::TextLang,
            bindings::ipp_tag_e_IPP_TAG_NAMELANG => Self::NameLang,
            bindings::ipp_tag_e_IPP_TAG_URISCHEME => Self::UriScheme,
            bindings::ipp_tag_e_IPP_TAG_DATE => Self::Date,
            bindings::ipp_tag_e_IPP_TAG_RESOLUTION => Self::Resolution,
            bindings::ipp_tag_e_IPP_TAG_RANGE => Self::Range,
            bindings::ipp_tag_e_IPP_TAG_BEGIN_COLLECTION => Self::BeginCollection,
            bindings::ipp_tag_e_IPP_TAG_END_COLLECTION => Self::EndCollection,
            bindings::ipp_tag_e_IPP_TAG_MEMBERNAME => Self::MemberName,
            bindings::ipp_tag_e_IPP_TAG_UNSUPPORTED_VALUE => Self::UnsupportedValue,
            bindings::ipp_tag_e_IPP_TAG_DEFAULT => Self::Default,
            bindings::ipp_tag_e_IPP_TAG_UNKNOWN => Self::Unknown,
            bindings::ipp_tag_e_IPP_TAG_NOVALUE => Self::NoValue,
            bindings::ipp_tag_e_IPP_TAG_NOTSETTABLE => Self::NotSettable,
            bindings::ipp_tag_e_IPP_TAG_DELETEATTR => Self::DeleteAttr,
            bindings::ipp_tag_e_IPP_TAG_ADMINDEFINE => Self::AdminDefine,
            other => Self::Other(other),
        }
    }

    /// Returns true when the value is a text-like string type.
    ///
    /// Both the plain and the with-language forms qualify, because a peer may
    /// send either for the same attribute.
    pub(crate) fn is_text_like(self) -> bool {
        matches!(
            self,
            Self::Text | Self::TextLang | Self::Name | Self::NameLang | Self::Keyword
        )
    }
}

/// IPP operation codes
///
/// These codes identify the operation being performed in an IPP request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IppOperation {
    PrintJob,
    ValidateJob,
    CreateJob,
    SendDocument,
    CancelJob,
    GetJobAttributes,
    GetJobs,
    GetPrinterAttributes,
    GetSystemAttributes,
    HoldJob,
    ReleaseJob,
    PausePrinter,
    ResumePrinter,
    /// IPP System Service `Create-Printer`.
    CreatePrinter,
    /// IPP System Service `Delete-Printer`.
    DeletePrinter,
    /// IPP System Service `Get-Printers`.
    GetPrinters,
    CupsAddModifyPrinter,
    CupsCreateLocalPrinter,
    CupsDeletePrinter,
    CupsMoveJob,
    CupsSetDefault,
    /// An operation this crate does not name, such as a vendor extension.
    ///
    /// Printer Applications built on PAPPL expose their device and driver
    /// enumeration this way; see [`IppOperation::PAPPL_FIND_DEVICES`] and its
    /// siblings.
    Other(u16),
}

impl IppOperation {
    /// `PAPPL-Find-Devices`, which asks a Printer Application which output
    /// devices it can currently see.
    pub const PAPPL_FIND_DEVICES: Self = Self::Other(0x402b);

    /// `PAPPL-Find-Drivers`, which asks a Printer Application which of its
    /// drivers match a device ID.
    pub const PAPPL_FIND_DRIVERS: Self = Self::Other(0x402c);

    /// Returns the numeric operation code sent on the wire.
    pub fn code(self) -> u16 {
        let code: bindings::ipp_op_t = self.into();
        code as u16
    }
}

impl From<IppOperation> for bindings::ipp_op_t {
    fn from(op: IppOperation) -> bindings::ipp_op_t {
        match op {
            IppOperation::PrintJob => bindings::ipp_op_e_IPP_OP_PRINT_JOB,
            IppOperation::ValidateJob => bindings::ipp_op_e_IPP_OP_VALIDATE_JOB,
            IppOperation::CreateJob => bindings::ipp_op_e_IPP_OP_CREATE_JOB,
            IppOperation::SendDocument => bindings::ipp_op_e_IPP_OP_SEND_DOCUMENT,
            IppOperation::CancelJob => bindings::ipp_op_e_IPP_OP_CANCEL_JOB,
            IppOperation::GetJobAttributes => bindings::ipp_op_e_IPP_OP_GET_JOB_ATTRIBUTES,
            IppOperation::GetJobs => bindings::ipp_op_e_IPP_OP_GET_JOBS,
            IppOperation::GetPrinterAttributes => bindings::ipp_op_e_IPP_OP_GET_PRINTER_ATTRIBUTES,
            IppOperation::GetSystemAttributes => bindings::ipp_op_e_IPP_OP_GET_SYSTEM_ATTRIBUTES,
            IppOperation::HoldJob => bindings::ipp_op_e_IPP_OP_HOLD_JOB,
            IppOperation::ReleaseJob => bindings::ipp_op_e_IPP_OP_RELEASE_JOB,
            IppOperation::PausePrinter => bindings::ipp_op_e_IPP_OP_PAUSE_PRINTER,
            IppOperation::ResumePrinter => bindings::ipp_op_e_IPP_OP_RESUME_PRINTER,
            IppOperation::CreatePrinter => bindings::ipp_op_e_IPP_OP_CREATE_PRINTER,
            IppOperation::DeletePrinter => bindings::ipp_op_e_IPP_OP_DELETE_PRINTER,
            IppOperation::GetPrinters => bindings::ipp_op_e_IPP_OP_GET_PRINTERS,
            IppOperation::CupsAddModifyPrinter => bindings::ipp_op_e_IPP_OP_CUPS_ADD_MODIFY_PRINTER,
            IppOperation::CupsCreateLocalPrinter => {
                bindings::ipp_op_e_IPP_OP_CUPS_CREATE_LOCAL_PRINTER
            }
            IppOperation::CupsDeletePrinter => bindings::ipp_op_e_IPP_OP_CUPS_DELETE_PRINTER,
            IppOperation::CupsMoveJob => bindings::ipp_op_e_IPP_OP_CUPS_MOVE_JOB,
            IppOperation::CupsSetDefault => bindings::ipp_op_e_IPP_OP_CUPS_SET_DEFAULT,
            IppOperation::Other(code) => bindings::ipp_op_t::from(code),
        }
    }
}

/// IPP status codes
///
/// These codes indicate the result of an IPP operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IppStatus {
    Ok,
    OkIgnoredOrSubstituted,
    OkConflicting,
    ErrorBadRequest,
    ErrorForbidden,
    ErrorNotAuthenticated,
    ErrorNotAuthorized,
    ErrorNotPossible,
    ErrorTimeout,
    ErrorNotFound,
    ErrorGone,
    ErrorRequestEntity,
    ErrorRequestValue,
    ErrorDocumentFormatNotSupported,
    ErrorOperationNotSupported,
    ErrorConflicting,
    ErrorPrinterIsDeactivated,
    ErrorTooManyJobs,
    ErrorInternalError,
}

impl IppStatus {
    pub fn from_code(code: bindings::ipp_status_t) -> Self {
        match code {
            bindings::ipp_status_e_IPP_STATUS_OK => IppStatus::Ok,
            bindings::ipp_status_e_IPP_STATUS_OK_IGNORED_OR_SUBSTITUTED => {
                IppStatus::OkIgnoredOrSubstituted
            }
            bindings::ipp_status_e_IPP_STATUS_OK_CONFLICTING => IppStatus::OkConflicting,
            bindings::ipp_status_e_IPP_STATUS_ERROR_BAD_REQUEST => IppStatus::ErrorBadRequest,
            bindings::ipp_status_e_IPP_STATUS_ERROR_FORBIDDEN => IppStatus::ErrorForbidden,
            bindings::ipp_status_e_IPP_STATUS_ERROR_NOT_AUTHENTICATED => {
                IppStatus::ErrorNotAuthenticated
            }
            bindings::ipp_status_e_IPP_STATUS_ERROR_NOT_AUTHORIZED => IppStatus::ErrorNotAuthorized,
            bindings::ipp_status_e_IPP_STATUS_ERROR_NOT_POSSIBLE => IppStatus::ErrorNotPossible,
            bindings::ipp_status_e_IPP_STATUS_ERROR_TIMEOUT => IppStatus::ErrorTimeout,
            bindings::ipp_status_e_IPP_STATUS_ERROR_NOT_FOUND => IppStatus::ErrorNotFound,
            bindings::ipp_status_e_IPP_STATUS_ERROR_GONE => IppStatus::ErrorGone,
            bindings::ipp_status_e_IPP_STATUS_ERROR_REQUEST_ENTITY => IppStatus::ErrorRequestEntity,
            bindings::ipp_status_e_IPP_STATUS_ERROR_REQUEST_VALUE => IppStatus::ErrorRequestValue,
            bindings::ipp_status_e_IPP_STATUS_ERROR_DOCUMENT_FORMAT_NOT_SUPPORTED => {
                IppStatus::ErrorDocumentFormatNotSupported
            }
            bindings::ipp_status_e_IPP_STATUS_ERROR_OPERATION_NOT_SUPPORTED => {
                IppStatus::ErrorOperationNotSupported
            }
            bindings::ipp_status_e_IPP_STATUS_ERROR_CONFLICTING => IppStatus::ErrorConflicting,
            bindings::ipp_status_e_IPP_STATUS_ERROR_PRINTER_IS_DEACTIVATED => {
                IppStatus::ErrorPrinterIsDeactivated
            }
            bindings::ipp_status_e_IPP_STATUS_ERROR_TOO_MANY_JOBS => IppStatus::ErrorTooManyJobs,
            bindings::ipp_status_e_IPP_STATUS_ERROR_INTERNAL => IppStatus::ErrorInternalError,
            _ => IppStatus::ErrorInternalError,
        }
    }

    pub fn is_successful(&self) -> bool {
        matches!(
            self,
            IppStatus::Ok | IppStatus::OkIgnoredOrSubstituted | IppStatus::OkConflicting
        )
    }
}

/// An IPP request message
///
/// Represents an IPP request that can be customized with attributes and sent to a CUPS server.
/// The request is automatically freed when dropped.
///
/// # Examples
///
/// ```no_run
/// use cups_rs::{IppRequest, IppOperation, IppTag, IppValueTag};
///
/// let mut request = IppRequest::new(IppOperation::GetPrinterAttributes)
///     .expect("Failed to create request");
///
/// request.add_string(IppTag::Operation, IppValueTag::Keyword,
///                   "requested-attributes", "printer-state")
///     .expect("Failed to add attribute");
/// ```
pub struct IppRequest {
    ipp: *mut bindings::_ipp_s,
    _phantom: PhantomData<bindings::_ipp_s>,
}

impl IppRequest {
    /// Create a new IPP request
    pub fn new(operation: IppOperation) -> Result<Self> {
        let ipp = unsafe { bindings::ippNewRequest(operation.into()) };

        if ipp.is_null() {
            return Err(Error::UnsupportedFeature(
                "Failed to create IPP request".to_string(),
            ));
        }

        Ok(IppRequest {
            ipp,
            _phantom: PhantomData,
        })
    }

    /// Get the raw pointer to the ipp_t structure
    pub fn as_ptr(&self) -> *mut bindings::_ipp_s {
        self.ipp
    }

    /// Add a string attribute
    pub fn add_string(
        &mut self,
        group: IppTag,
        value_tag: IppValueTag,
        name: &str,
        value: &str,
    ) -> Result<()> {
        let name_c = CString::new(name)?;
        let value_c = CString::new(value)?;

        let attr = unsafe {
            bindings::ippAddString(
                self.ipp,
                group.into(),
                value_tag.into(),
                name_c.as_ptr(),
                ptr::null(),
                value_c.as_ptr(),
            )
        };

        if attr.is_null() {
            Err(Error::UnsupportedFeature(format!(
                "Failed to add string attribute '{}'",
                name
            )))
        } else {
            Ok(())
        }
    }

    /// Add an integer attribute
    pub fn add_integer(
        &mut self,
        group: IppTag,
        value_tag: IppValueTag,
        name: &str,
        value: i32,
    ) -> Result<()> {
        let name_c = CString::new(name)?;

        let attr = unsafe {
            bindings::ippAddInteger(
                self.ipp,
                group.into(),
                value_tag.into(),
                name_c.as_ptr(),
                value,
            )
        };

        if attr.is_null() {
            Err(Error::UnsupportedFeature(format!(
                "Failed to add integer attribute '{}'",
                name
            )))
        } else {
            Ok(())
        }
    }

    /// Add a boolean attribute
    pub fn add_boolean(&mut self, group: IppTag, name: &str, value: bool) -> Result<()> {
        let name_c = CString::new(name)?;

        let attr =
            unsafe { bindings::ippAddBoolean(self.ipp, group.into(), name_c.as_ptr(), value) };

        if attr.is_null() {
            Err(Error::UnsupportedFeature(format!(
                "Failed to add boolean attribute '{}'",
                name
            )))
        } else {
            Ok(())
        }
    }

    /// Add multiple string attributes
    pub fn add_strings(
        &mut self,
        group: IppTag,
        value_tag: IppValueTag,
        name: &str,
        values: &[&str],
    ) -> Result<()> {
        let name_c = CString::new(name)?;
        let values_c: Vec<CString> = values
            .iter()
            .map(|v| CString::new(*v).map_err(Error::from))
            .collect::<Result<Vec<_>>>()?;

        let values_ptrs: Vec<*const ::std::os::raw::c_char> =
            values_c.iter().map(|s| s.as_ptr()).collect();

        let attr = unsafe {
            bindings::ippAddStrings(
                self.ipp,
                group.into(),
                value_tag.into(),
                name_c.as_ptr(),
                values.len(),
                ptr::null(),
                values_ptrs.as_ptr(),
            )
        };

        if attr.is_null() {
            Err(Error::UnsupportedFeature(format!(
                "Failed to add string array attribute '{}'",
                name
            )))
        } else {
            Ok(())
        }
    }

    /// Send this request and receive a response
    pub fn send(&self, connection: &HttpConnection, resource: &str) -> Result<IppResponse> {
        let resource_c = CString::new(resource)?;

        // cupsDoRequest frees the request, so send a copy.
        // create an empty IPP message for the outgoing copy
        let request_copy = unsafe { bindings::ippNew() };
        if request_copy.is_null() {
            return Err(Error::UnsupportedFeature(
                "Failed to copy IPP request".to_string(),
            ));
        }

        unsafe {
            // Copy request header fields
            bindings::ippSetOperation(request_copy, bindings::ippGetOperation(self.ipp));
            bindings::ippSetRequestId(request_copy, bindings::ippGetRequestId(self.ipp));

            // Copy all attributes
            bindings::ippCopyAttributes(request_copy, self.ipp, false, None, ptr::null_mut());
        }

        let response = unsafe {
            bindings::cupsDoRequest(connection.as_ptr(), request_copy, resource_c.as_ptr())
        };

        if response.is_null() {
            Err(Error::ServerError(
                "No response received from server".to_string(),
            ))
        } else {
            Ok(IppResponse {
                ipp: response,
                _phantom: PhantomData,
            })
        }
    }

    /// Send this request to the default CUPS scheduler connection.
    pub fn send_default(&self, resource: &str) -> Result<IppResponse> {
        let resource_c = CString::new(resource)?;

        let request_copy = unsafe { bindings::ippNew() };
        if request_copy.is_null() {
            return Err(Error::UnsupportedFeature(
                "Failed to copy IPP request".to_string(),
            ));
        }

        unsafe {
            bindings::ippCopyAttributes(request_copy, self.ipp, false, None, ptr::null_mut());
        }

        let response = unsafe {
            bindings::ippSetOperation(request_copy, bindings::ippGetOperation(self.ipp));
            bindings::ippSetRequestId(request_copy, bindings::ippGetRequestId(self.ipp));
            bindings::cupsDoRequest(ptr::null_mut(), request_copy, resource_c.as_ptr())
        };

        if response.is_null() {
            Err(Error::ServerError(
                "No response received from server".to_string(),
            ))
        } else {
            Ok(IppResponse {
                ipp: response,
                _phantom: PhantomData,
            })
        }
    }
}

impl Drop for IppRequest {
    fn drop(&mut self) {
        if !self.ipp.is_null() {
            unsafe {
                bindings::ippDelete(self.ipp);
            }
            self.ipp = ptr::null_mut();
        }
    }
}

/// An IPP response message
///
/// Represents the response from an IPP request. Contains status code and attributes
/// that can be queried. The response is automatically freed when dropped.
///
/// # Examples
///
/// ```no_run
/// # use cups_rs::{IppRequest, IppOperation, IppTag, ConnectionFlags, get_default_destination};
/// # let printer = get_default_destination().unwrap();
/// # let connection = printer.connect(ConnectionFlags::Scheduler, Some(5000), None).unwrap();
/// # let request = IppRequest::new(IppOperation::GetPrinterAttributes).unwrap();
/// let response = request.send(&connection, connection.resource_path()).unwrap();
///
/// if response.is_successful() {
///     if let Some(attr) = response.find_attribute("printer-state", Some(IppTag::Printer)) {
///         println!("Printer state: {:?}", attr.get_integer(0));
///     }
/// }
/// ```
pub struct IppResponse {
    ipp: *mut bindings::_ipp_s,
    _phantom: PhantomData<bindings::_ipp_s>,
}

impl IppResponse {
    /// Get the raw pointer to the ipp_t structure
    pub fn as_ptr(&self) -> *mut bindings::_ipp_s {
        self.ipp
    }

    /// Get the status code from the response
    pub fn status(&self) -> IppStatus {
        let status_code = unsafe { bindings::ippGetStatusCode(self.ipp) };
        IppStatus::from_code(status_code)
    }

    /// Returns the raw status code exactly as the peer sent it.
    ///
    /// [`IppResponse::status`] folds codes this crate does not model into
    /// [`IppStatus::ErrorInternalError`]; this keeps the original value for
    /// diagnostics.
    pub fn status_code(&self) -> u16 {
        unsafe { bindings::ippGetStatusCode(self.ipp) as u16 }
    }

    /// Check if the response indicates success
    pub fn is_successful(&self) -> bool {
        self.status().is_successful()
    }

    /// Find an attribute by name, optionally restricted to one attribute group.
    ///
    /// `group` filters on the group the attribute arrived in — `Some(IppTag::System)`
    /// matches only System-group attributes. Passing `None` accepts any group.
    ///
    /// Note that searching moves the message's internal attribute cursor, so a
    /// walk started with [`IppResponse::attributes`] does not survive a search.
    pub fn find_attribute(&self, name: &str, group: Option<IppTag>) -> Option<IppAttribute> {
        let name_c = CString::new(name).ok()?;
        let mut attr =
            unsafe { bindings::ippFindAttribute(self.ipp, name_c.as_ptr(), IPP_TAG_ANY_VALUE) };

        while !attr.is_null() {
            let candidate = IppAttribute { attr };
            if group.is_none_or(|group| candidate.group_tag() == Some(group)) {
                return Some(candidate);
            }
            attr = unsafe {
                bindings::ippFindNextAttribute(self.ipp, name_c.as_ptr(), IPP_TAG_ANY_VALUE)
            };
        }

        None
    }

    /// Returns every attribute with this name, in the order the peer sent them.
    ///
    /// IPP allows a name to repeat within a message, and PAPPL relies on that:
    /// `PAPPL-Find-Devices` reports one `smi55357-device-col` per device. Using
    /// [`IppResponse::find_attribute`] would silently see only the first one.
    pub fn attributes_named(&self, name: &str) -> Vec<IppAttribute> {
        let Ok(name_c) = CString::new(name) else {
            return Vec::new();
        };

        let mut found = Vec::new();
        let mut attr =
            unsafe { bindings::ippFindAttribute(self.ipp, name_c.as_ptr(), IPP_TAG_ANY_VALUE) };
        while !attr.is_null() {
            found.push(IppAttribute { attr });
            attr = unsafe {
                bindings::ippFindNextAttribute(self.ipp, name_c.as_ptr(), IPP_TAG_ANY_VALUE)
            };
        }

        found
    }

    /// Get all attributes in the response
    pub fn attributes(&self) -> Vec<IppAttribute> {
        let mut attributes = Vec::new();
        let mut attr = unsafe { bindings::ippGetFirstAttribute(self.ipp) };

        while !attr.is_null() {
            attributes.push(IppAttribute { attr });
            attr = unsafe { bindings::ippGetNextAttribute(self.ipp) };
        }

        attributes
    }
}

/// Matches any value type when searching for an attribute by name.
const IPP_TAG_ANY_VALUE: bindings::ipp_tag_t = bindings::ipp_tag_e_IPP_TAG_ZERO;

impl Drop for IppResponse {
    fn drop(&mut self) {
        if !self.ipp.is_null() {
            unsafe {
                bindings::ippDelete(self.ipp);
            }
            self.ipp = ptr::null_mut();
        }
    }
}

/// An IPP attribute
///
/// Represents a single attribute from an IPP response. Attributes can contain
/// one or more values of various types (string, integer, boolean, etc.).
#[derive(Clone, Copy)]
pub struct IppAttribute {
    attr: *mut bindings::_ipp_attribute_s,
}

impl IppAttribute {
    /// Get the attribute name
    pub fn name(&self) -> Option<String> {
        unsafe {
            let name_ptr = bindings::ippGetName(self.attr);
            if name_ptr.is_null() {
                None
            } else {
                Some(CStr::from_ptr(name_ptr).to_string_lossy().into_owned())
            }
        }
    }

    /// Get the number of values
    pub fn count(&self) -> usize {
        unsafe { bindings::ippGetCount(self.attr) as usize }
    }

    /// Returns the type of the values this attribute holds.
    ///
    /// Use this before reading a value to confirm the peer sent the type you
    /// expect, rather than trusting an attribute name.
    pub fn value_tag(&self) -> IppValueTag {
        IppValueTag::from_code(unsafe { bindings::ippGetValueTag(self.attr) })
    }

    /// Returns the attribute group this attribute arrived in.
    ///
    /// `None` means the group tag is not one of the known groups, which is
    /// grounds for rejecting the attribute rather than interpreting it.
    pub fn group_tag(&self) -> Option<IppTag> {
        IppTag::from_code(unsafe { bindings::ippGetGroupTag(self.attr) })
    }

    /// Reads one collection value.
    ///
    /// Returns `None` when the index is out of range or the attribute is not a
    /// collection, so a peer sending the wrong type cannot be misread as one.
    /// The returned collection borrows this attribute's message.
    pub(crate) fn get_collection(&self, index: usize) -> Option<IppCollection<'_>> {
        if self.value_tag() != IppValueTag::BeginCollection || index >= self.count() {
            return None;
        }

        let ipp = unsafe { bindings::ippGetCollection(self.attr, index) };
        if ipp.is_null() {
            return None;
        }

        Some(IppCollection {
            ipp,
            _borrow: PhantomData,
        })
    }

    /// Reads every collection value in order.
    pub fn collections(&self) -> Vec<IppCollection<'_>> {
        (0..self.count())
            .filter_map(|index| self.get_collection(index))
            .collect()
    }

    /// Get a string value
    pub fn get_string(&self, index: usize) -> Option<String> {
        unsafe {
            let value_ptr = bindings::ippGetString(self.attr, index, ptr::null_mut());
            if value_ptr.is_null() {
                None
            } else {
                Some(CStr::from_ptr(value_ptr).to_string_lossy().into_owned())
            }
        }
    }

    /// Get an integer value
    pub fn get_integer(&self, index: usize) -> i32 {
        unsafe { bindings::ippGetInteger(self.attr, index) }
    }

    /// Get a boolean value
    pub fn get_boolean(&self, index: usize) -> bool {
        unsafe { bindings::ippGetBoolean(self.attr, index) }
    }
}

/// One collection value read out of an IPP attribute.
///
/// Collections are how IPP carries a record with named members. PAPPL uses them
/// to report output devices (`smi55357-device-col`) and drivers
/// (`smi55357-driver-col`), one collection per device or driver.
///
/// The collection borrows the message it came from and is never freed
/// separately: libcups owns it as part of the parent attribute.
pub struct IppCollection<'a> {
    ipp: *mut bindings::_ipp_s,
    _borrow: PhantomData<&'a IppAttribute>,
}

impl IppCollection<'_> {
    /// Finds a member by name.
    ///
    /// Members carry no group tag of their own, so unlike
    /// [`IppResponse::find_attribute`] there is nothing to filter on. Check the
    /// returned attribute's [`IppAttribute::value_tag`] before reading it.
    pub fn find(&self, name: &str) -> Option<IppAttribute> {
        let name_c = CString::new(name).ok()?;
        let attr =
            unsafe { bindings::ippFindAttribute(self.ipp, name_c.as_ptr(), IPP_TAG_ANY_VALUE) };

        (!attr.is_null()).then_some(IppAttribute { attr })
    }

    /// Reads a single-valued text-like member, rejecting the wrong type.
    ///
    /// Returns `None` when the member is absent, is not a text-like type, holds
    /// no usable value, or is empty after trimming — the cases a malformed peer
    /// produces. Multi-valued members yield their first value, because IPP
    /// permits a sender to repeat a member the receiver treats as single.
    pub fn text(&self, name: &str) -> Option<String> {
        let attr = self.find(name)?;
        if !attr.value_tag().is_text_like() && attr.value_tag() != IppValueTag::Uri {
            return None;
        }

        let value = attr.get_string(0)?;
        let trimmed = value.trim();

        (!trimmed.is_empty()).then(|| trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipp_request_creation() {
        let request = IppRequest::new(IppOperation::GetPrinterAttributes);
        assert!(request.is_ok());
    }

    #[test]
    fn test_system_attributes_request_creation() {
        let request = IppRequest::new(IppOperation::GetSystemAttributes);
        assert!(request.is_ok());
    }

    #[test]
    fn test_cups_move_job_request_creation() {
        let request = IppRequest::new(IppOperation::CupsMoveJob);
        assert!(request.is_ok());
    }

    #[test]
    fn test_ipp_add_string() {
        let mut request = IppRequest::new(IppOperation::GetPrinterAttributes).unwrap();
        let result = request.add_string(
            IppTag::Operation,
            IppValueTag::Uri,
            "printer-uri",
            "ipp://localhost/printers/test",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_ipp_add_integer() {
        let mut request = IppRequest::new(IppOperation::GetJobs).unwrap();
        let result = request.add_integer(IppTag::Operation, IppValueTag::Integer, "limit", 10);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ipp_add_boolean() {
        let mut request = IppRequest::new(IppOperation::GetJobs).unwrap();
        let result = request.add_boolean(IppTag::Operation, "my-jobs", true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ipp_status() {
        assert!(IppStatus::Ok.is_successful());
        assert!(IppStatus::OkIgnoredOrSubstituted.is_successful());
        assert!(!IppStatus::ErrorBadRequest.is_successful());
        assert!(!IppStatus::ErrorNotFound.is_successful());
    }

    #[test]
    fn vendor_operations_keep_their_wire_codes() {
        assert_eq!(IppOperation::PAPPL_FIND_DEVICES.code(), 0x402b);
        assert_eq!(IppOperation::PAPPL_FIND_DRIVERS.code(), 0x402c);
        assert_eq!(IppOperation::CreatePrinter.code(), 0x004c);
        assert_eq!(IppOperation::GetPrinters.code(), 0x004f);
    }

    #[test]
    fn vendor_operation_requests_can_be_created() {
        assert!(IppRequest::new(IppOperation::PAPPL_FIND_DEVICES).is_ok());
        assert!(IppRequest::new(IppOperation::CreatePrinter).is_ok());
    }

    #[test]
    fn unknown_value_tags_are_preserved_rather_than_guessed() {
        assert_eq!(
            IppValueTag::from_code(bindings::ipp_tag_e_IPP_TAG_BEGIN_COLLECTION),
            IppValueTag::BeginCollection
        );
        assert_eq!(IppValueTag::from_code(0x7e), IppValueTag::Other(0x7e));
        assert!(IppValueTag::NameLang.is_text_like());
        assert!(!IppValueTag::Integer.is_text_like());
    }

    #[test]
    fn group_tags_reject_values_that_are_not_groups() {
        assert_eq!(
            IppTag::from_code(bindings::ipp_tag_e_IPP_TAG_SYSTEM),
            Some(IppTag::System)
        );
        assert_eq!(IppTag::from_code(bindings::ipp_tag_e_IPP_TAG_KEYWORD), None);
    }

    /// Builds a message shaped like a `PAPPL-Find-Devices` response: two
    /// `smi55357-device-col` collections in the System group.
    ///
    /// The member collections are deliberately not freed here — `ippAddCollection`
    /// hands them to the parent message, which releases them on `ippDelete`.
    fn find_devices_response() -> IppResponse {
        unsafe {
            let ipp = bindings::ippNew();
            assert!(!ipp.is_null());

            for (device_id, info, uri) in [
                (
                    "MFG:Acme;MDL:Test Laser 9000;CMD:POSTSCRIPT;SN:SERIAL-1;",
                    "Acme Test Laser 9000",
                    "socket://192.0.2.10:9100",
                ),
                (
                    "MFG:Acme;MDL:Test Label 100;CMD:PCL;SN:SERIAL-2;",
                    "Acme Test Label 100",
                    "usb://Acme/Test%20Label%20100?serial=SERIAL-2",
                ),
            ] {
                let col = bindings::ippNew();
                assert!(!col.is_null());

                let name = CString::new("smi55357-device-id").unwrap();
                let value = CString::new(device_id).unwrap();
                bindings::ippAddString(
                    col,
                    bindings::ipp_tag_e_IPP_TAG_ZERO,
                    bindings::ipp_tag_e_IPP_TAG_TEXT,
                    name.as_ptr(),
                    ptr::null(),
                    value.as_ptr(),
                );

                let name = CString::new("smi55357-device-info").unwrap();
                let value = CString::new(info).unwrap();
                bindings::ippAddString(
                    col,
                    bindings::ipp_tag_e_IPP_TAG_ZERO,
                    bindings::ipp_tag_e_IPP_TAG_TEXT,
                    name.as_ptr(),
                    ptr::null(),
                    value.as_ptr(),
                );

                let name = CString::new("smi55357-device-uri").unwrap();
                let value = CString::new(uri).unwrap();
                bindings::ippAddString(
                    col,
                    bindings::ipp_tag_e_IPP_TAG_ZERO,
                    bindings::ipp_tag_e_IPP_TAG_URI,
                    name.as_ptr(),
                    ptr::null(),
                    value.as_ptr(),
                );

                let name = CString::new("smi55357-device-col").unwrap();
                bindings::ippAddCollection(
                    ipp,
                    bindings::ipp_tag_e_IPP_TAG_SYSTEM,
                    name.as_ptr(),
                    col,
                );
            }

            let name = CString::new("system-name").unwrap();
            let value = CString::new("Test Printer Application").unwrap();
            bindings::ippAddString(
                ipp,
                bindings::ipp_tag_e_IPP_TAG_SYSTEM,
                bindings::ipp_tag_e_IPP_TAG_NAME,
                name.as_ptr(),
                ptr::null(),
                value.as_ptr(),
            );

            IppResponse {
                ipp,
                _phantom: PhantomData,
            }
        }
    }

    #[test]
    fn repeated_collections_are_all_reachable() {
        let response = find_devices_response();

        let devices = response.attributes_named("smi55357-device-col");
        assert_eq!(devices.len(), 2);

        let uris = devices
            .iter()
            .map(|attr| {
                let collection = attr.get_collection(0).expect("collection value");
                collection.text("smi55357-device-uri").expect("device uri")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            uris,
            vec![
                "socket://192.0.2.10:9100".to_string(),
                "usb://Acme/Test%20Label%20100?serial=SERIAL-2".to_string(),
            ]
        );
    }

    #[test]
    fn collection_members_report_their_types() {
        let response = find_devices_response();
        let device = response
            .find_attribute("smi55357-device-col", Some(IppTag::System))
            .expect("device collection attribute");

        assert_eq!(device.value_tag(), IppValueTag::BeginCollection);
        assert_eq!(device.group_tag(), Some(IppTag::System));

        let collection = device.get_collection(0).expect("collection value");
        assert_eq!(
            collection
                .find("smi55357-device-uri")
                .map(|member| member.value_tag()),
            Some(IppValueTag::Uri)
        );
        assert_eq!(
            collection
                .find("smi55357-device-id")
                .map(|member| member.value_tag()),
            Some(IppValueTag::Text)
        );
        assert!(collection.find("smi55357-device-type").is_none());
    }

    #[test]
    fn group_filter_rejects_attributes_from_another_group() {
        let response = find_devices_response();

        assert!(
            response
                .find_attribute("system-name", Some(IppTag::System))
                .is_some()
        );
        assert!(
            response
                .find_attribute("system-name", Some(IppTag::Printer))
                .is_none()
        );
        assert!(response.find_attribute("system-name", None).is_some());
    }

    #[test]
    fn non_collection_attributes_do_not_yield_collections() {
        let response = find_devices_response();
        let name = response
            .find_attribute("system-name", None)
            .expect("system-name");

        assert!(name.get_collection(0).is_none());
        assert!(name.collections().is_empty());
    }

    #[test]
    fn out_of_range_collection_index_is_rejected() {
        let response = find_devices_response();
        let device = response
            .find_attribute("smi55357-device-col", None)
            .expect("device collection attribute");

        assert_eq!(device.count(), 1);
        assert!(device.get_collection(1).is_none());
    }

    #[test]
    fn collection_text_rejects_the_wrong_type_and_blank_values() {
        let collection_owner = unsafe {
            let ipp = bindings::ippNew();
            let col = bindings::ippNew();

            let name = CString::new("smi55357-device-id").unwrap();
            bindings::ippAddInteger(
                col,
                bindings::ipp_tag_e_IPP_TAG_ZERO,
                bindings::ipp_tag_e_IPP_TAG_INTEGER,
                name.as_ptr(),
                42,
            );

            let name = CString::new("smi55357-device-info").unwrap();
            let value = CString::new("   ").unwrap();
            bindings::ippAddString(
                col,
                bindings::ipp_tag_e_IPP_TAG_ZERO,
                bindings::ipp_tag_e_IPP_TAG_TEXT,
                name.as_ptr(),
                ptr::null(),
                value.as_ptr(),
            );

            let name = CString::new("smi55357-device-col").unwrap();
            bindings::ippAddCollection(ipp, bindings::ipp_tag_e_IPP_TAG_SYSTEM, name.as_ptr(), col);

            IppResponse {
                ipp,
                _phantom: PhantomData,
            }
        };

        let device = collection_owner
            .find_attribute("smi55357-device-col", None)
            .expect("device collection attribute");
        let collection = device.get_collection(0).expect("collection value");

        assert_eq!(collection.text("smi55357-device-id"), None);
        assert_eq!(collection.text("smi55357-device-info"), None);
        assert_eq!(collection.text("smi55357-device-uri"), None);
    }
}
