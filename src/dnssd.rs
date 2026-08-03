use crate::{Error, Result, bindings};
use std::ffi::{CStr, CString, c_void};
use std::ptr;
use std::sync::Arc;
use std::sync::mpsc::Sender;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnssdBrowseEvent {
    pub added: bool,
    pub interface_index: u32,
    pub name: String,
    pub service_type: String,
    pub domain: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnssdResolveEvent {
    pub name: String,
    pub service_type: String,
    pub domain: String,
    pub interface_index: u32,
    pub full_name: String,
    pub hostname: String,
    pub port: u16,
    pub txt: Vec<(String, String)>,
}

pub struct Dnssd {
    inner: Arc<DnssdInner>,
}

struct DnssdInner {
    raw: *mut bindings::_cups_dnssd_s,
    error_state: Box<ErrorState>,
}

struct ErrorState(Sender<String>);
struct BrowseState(Sender<DnssdBrowseEvent>);
struct ResolveState {
    sender: Sender<DnssdResolveEvent>,
    name: String,
    service_type: String,
    domain: String,
}

impl Dnssd {
    pub fn new(error_sender: Sender<String>) -> Result<Self> {
        let mut error_state = Box::new(ErrorState(error_sender));
        let raw = unsafe {
            bindings::cupsDNSSDNew(
                Some(error_callback),
                (&mut *error_state as *mut ErrorState).cast(),
            )
        };
        if raw.is_null() {
            return Err(Error::NetworkError(
                "failed to create libcups DNS-SD context".into(),
            ));
        }
        Ok(Self {
            inner: Arc::new(DnssdInner { raw, error_state }),
        })
    }

    pub fn browse(
        &self,
        service_types: &str,
        domain: Option<&str>,
        sender: Sender<DnssdBrowseEvent>,
    ) -> Result<DnssdBrowser> {
        let service_types = CString::new(service_types)?;
        let domain = domain.map(CString::new).transpose()?;
        let mut state = Box::new(BrowseState(sender));
        let raw = unsafe {
            bindings::cupsDNSSDBrowseNew(
                self.inner.raw,
                bindings::CUPS_DNSSD_IF_INDEX_ANY,
                service_types.as_ptr(),
                domain.as_ref().map_or(ptr::null(), |value| value.as_ptr()),
                Some(browse_callback),
                (&mut *state as *mut BrowseState).cast(),
            )
        };
        if raw.is_null() {
            return Err(Error::NetworkError(
                "failed to create libcups DNS-SD browser".into(),
            ));
        }
        Ok(DnssdBrowser {
            raw,
            state,
            _context: Arc::clone(&self.inner),
        })
    }

    pub fn resolve(
        &self,
        service: &DnssdBrowseEvent,
        sender: Sender<DnssdResolveEvent>,
    ) -> Result<DnssdResolver> {
        let name = CString::new(service.name.as_str())?;
        let service_type = CString::new(service.service_type.as_str())?;
        let domain = CString::new(service.domain.as_str())?;
        let mut state = Box::new(ResolveState {
            sender,
            name: service.name.clone(),
            service_type: service.service_type.clone(),
            domain: service.domain.clone(),
        });
        let raw = unsafe {
            bindings::cupsDNSSDResolveNew(
                self.inner.raw,
                service.interface_index,
                name.as_ptr(),
                service_type.as_ptr(),
                domain.as_ptr(),
                Some(resolve_callback),
                (&mut *state as *mut ResolveState).cast(),
            )
        };
        if raw.is_null() {
            return Err(Error::NetworkError(format!(
                "failed to resolve DNS-SD service '{}'",
                service.name
            )));
        }
        Ok(DnssdResolver {
            raw,
            state,
            _context: Arc::clone(&self.inner),
        })
    }
}

impl Drop for DnssdInner {
    fn drop(&mut self) {
        unsafe { bindings::cupsDNSSDDelete(self.raw) };
        let _ = &self.error_state;
    }
}

pub struct DnssdBrowser {
    raw: *mut bindings::_cups_dnssd_browse_s,
    state: Box<BrowseState>,
    _context: Arc<DnssdInner>,
}

impl Drop for DnssdBrowser {
    fn drop(&mut self) {
        unsafe { bindings::cupsDNSSDBrowseDelete(self.raw) };
        let _ = &self.state;
    }
}

pub struct DnssdResolver {
    raw: *mut bindings::_cups_dnssd_resolve_s,
    state: Box<ResolveState>,
    _context: Arc<DnssdInner>,
}

impl Drop for DnssdResolver {
    fn drop(&mut self) {
        unsafe { bindings::cupsDNSSDResolveDelete(self.raw) };
        let _ = &self.state;
    }
}

unsafe extern "C" fn error_callback(cb_data: *mut c_void, message: *const i8) {
    if cb_data.is_null() || message.is_null() {
        return;
    }
    let state = unsafe { &*(cb_data.cast::<ErrorState>()) };
    let message = unsafe { CStr::from_ptr(message) }
        .to_string_lossy()
        .into_owned();
    let _ = state.0.send(message);
}

unsafe extern "C" fn browse_callback(
    _browser: *mut bindings::_cups_dnssd_browse_s,
    cb_data: *mut c_void,
    flags: bindings::cups_dnssd_flags_t,
    interface_index: u32,
    name: *const i8,
    service_type: *const i8,
    domain: *const i8,
) {
    if cb_data.is_null() || name.is_null() || service_type.is_null() || domain.is_null() {
        return;
    }
    let state = unsafe { &*(cb_data.cast::<BrowseState>()) };
    let event = DnssdBrowseEvent {
        added: flags & bindings::cups_dnssd_flags_e_CUPS_DNSSD_FLAGS_ADD != 0,
        interface_index,
        name: unsafe { CStr::from_ptr(name) }
            .to_string_lossy()
            .into_owned(),
        service_type: unsafe { CStr::from_ptr(service_type) }
            .to_string_lossy()
            .into_owned(),
        domain: unsafe { CStr::from_ptr(domain) }
            .to_string_lossy()
            .into_owned(),
    };
    let _ = state.0.send(event);
}

unsafe extern "C" fn resolve_callback(
    _resolver: *mut bindings::_cups_dnssd_resolve_s,
    cb_data: *mut c_void,
    flags: bindings::cups_dnssd_flags_t,
    interface_index: u32,
    full_name: *const i8,
    hostname: *const i8,
    port: u16,
    num_txt: usize,
    txt: *mut bindings::cups_option_s,
) {
    if cb_data.is_null()
        || full_name.is_null()
        || hostname.is_null()
        || flags & bindings::cups_dnssd_flags_e_CUPS_DNSSD_FLAGS_ERROR != 0
    {
        return;
    }
    let state = unsafe { &*(cb_data.cast::<ResolveState>()) };
    let mut options = Vec::with_capacity(num_txt);
    for index in 0..num_txt {
        let option = unsafe { &*txt.add(index) };
        if !option.name.is_null() && !option.value.is_null() {
            options.push((
                unsafe { CStr::from_ptr(option.name) }
                    .to_string_lossy()
                    .into_owned(),
                unsafe { CStr::from_ptr(option.value) }
                    .to_string_lossy()
                    .into_owned(),
            ));
        }
    }
    let _ = state.sender.send(DnssdResolveEvent {
        name: state.name.clone(),
        service_type: state.service_type.clone(),
        domain: state.domain.clone(),
        interface_index,
        full_name: unsafe { CStr::from_ptr(full_name) }
            .to_string_lossy()
            .into_owned(),
        hostname: unsafe { CStr::from_ptr(hostname) }
            .to_string_lossy()
            .trim_end_matches('.')
            .to_string(),
        port,
        txt: options,
    });
}
