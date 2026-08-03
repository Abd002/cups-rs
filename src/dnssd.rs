use crate::{Error, Result, bindings};
use std::ffi::{CStr, CString, c_void};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;
use std::slice;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender};

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

/// A DNS-SD service resolution together with its current addresses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnssdResolvedService {
    pub service: DnssdResolveEvent,
    pub addresses: Vec<IpAddr>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DnssdAddressEvent {
    added: bool,
    interface_index: u32,
    hostname: String,
    address: IpAddr,
}

#[derive(Clone)]
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
struct QueryState(Sender<DnssdAddressEvent>);

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

    /// Resolves SRV/TXT data and A/AAAA addresses for a service.
    ///
    /// Call [`DnssdServiceResolver::try_recv`] from the same event loop that
    /// consumes browse events. A result is emitted once at least one address
    /// has been resolved and again whenever the address set changes.
    pub fn resolve_service(&self, service: &DnssdBrowseEvent) -> Result<DnssdServiceResolver> {
        // libcups' Avahi backend uses a context-wide `in_callback` flag when
        // deciding whether to take its internal lock. Keep deferred resolve
        // operations off the actively browsing context so another callback
        // cannot make that decision for the wrong thread.
        let dnssd = Dnssd::new(self.inner.error_state.0.clone())?;
        let (resolve_sender, resolve_receiver) = mpsc::channel();
        let resolver = dnssd.resolve(service, resolve_sender)?;
        let (address_sender, address_receiver) = mpsc::channel();
        Ok(DnssdServiceResolver {
            dnssd,
            resolver,
            resolve_receiver,
            address_sender,
            address_receiver,
            address_queries: None,
            resolved: None,
            addresses: Vec::new(),
        })
    }

    fn query_addresses(
        &self,
        hostname: &str,
        interface_index: u32,
        sender: Sender<DnssdAddressEvent>,
    ) -> Result<DnssdAddressQueries> {
        // Each deferred query also gets an idle context. Creating a second
        // query on a context whose first query is already dispatching has the
        // same cross-thread race in libcups' Avahi backend.
        let ipv4_context = Dnssd::new(self.inner.error_state.0.clone())?;
        let ipv4 = ipv4_context.query_address(hostname, interface_index, 1, sender.clone())?;
        let ipv6_context = Dnssd::new(self.inner.error_state.0.clone())?;
        let ipv6 = ipv6_context.query_address(hostname, interface_index, 28, sender)?;
        Ok(DnssdAddressQueries { ipv4, ipv6 })
    }

    fn query_address(
        &self,
        hostname: &str,
        interface_index: u32,
        record_type: u16,
        sender: Sender<DnssdAddressEvent>,
    ) -> Result<DnssdQuery> {
        let hostname = CString::new(hostname)?;
        let mut state = Box::new(QueryState(sender));
        let raw = unsafe {
            bindings::cupsDNSSDQueryNew(
                self.inner.raw,
                interface_index,
                hostname.as_ptr(),
                record_type,
                Some(query_callback),
                (&mut *state as *mut QueryState).cast(),
            )
        };
        if raw.is_null() {
            return Err(Error::NetworkError(format!(
                "failed to query DNS-SD addresses for '{hostname:?}'"
            )));
        }
        Ok(DnssdQuery {
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

/// Keeps a service resolver and its A/AAAA queries alive.
pub struct DnssdServiceResolver {
    dnssd: Dnssd,
    resolver: DnssdResolver,
    resolve_receiver: Receiver<DnssdResolveEvent>,
    address_sender: Sender<DnssdAddressEvent>,
    address_receiver: Receiver<DnssdAddressEvent>,
    address_queries: Option<DnssdAddressQueries>,
    resolved: Option<DnssdResolveEvent>,
    addresses: Vec<IpAddr>,
}

struct DnssdAddressQueries {
    ipv4: DnssdQuery,
    ipv6: DnssdQuery,
}

struct DnssdQuery {
    raw: *mut bindings::_cups_dnssd_query_s,
    state: Box<QueryState>,
    _context: Arc<DnssdInner>,
}

impl DnssdServiceResolver {
    /// Returns the latest combined service update without blocking.
    pub fn try_recv(&mut self) -> Result<Option<DnssdResolvedService>> {
        while let Ok(service) = self.resolve_receiver.try_recv() {
            self.addresses.clear();
            self.address_queries = Some(self.dnssd.query_addresses(
                &service.hostname,
                service.interface_index,
                self.address_sender.clone(),
            )?);
            self.resolved = Some(service);
        }

        let mut changed = false;
        while let Ok(event) = self.address_receiver.try_recv() {
            let Some(service) = &self.resolved else {
                continue;
            };
            if event.interface_index != service.interface_index
                || normalize_name(&event.hostname) != normalize_name(&service.hostname)
            {
                continue;
            }

            if event.added {
                if !self.addresses.contains(&event.address) {
                    self.addresses.push(event.address);
                    changed = true;
                }
            } else if let Some(index) = self
                .addresses
                .iter()
                .position(|address| *address == event.address)
            {
                self.addresses.remove(index);
                changed = true;
            }
        }

        if !changed {
            return Ok(None);
        }
        self.addresses.sort();
        Ok(self.resolved.clone().map(|service| DnssdResolvedService {
            service,
            addresses: self.addresses.clone(),
        }))
    }
}

fn normalize_name(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

impl Drop for DnssdResolver {
    fn drop(&mut self) {
        unsafe { bindings::cupsDNSSDResolveDelete(self.raw) };
        let _ = &self.state;
    }
}

impl Drop for DnssdQuery {
    fn drop(&mut self) {
        unsafe { bindings::cupsDNSSDQueryDelete(self.raw) };
        let _ = &self.state;
    }
}

impl Drop for DnssdAddressQueries {
    fn drop(&mut self) {
        let _ = (&self.ipv4, &self.ipv6);
    }
}

impl Drop for DnssdServiceResolver {
    fn drop(&mut self) {
        let _ = &self.resolver;
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

unsafe extern "C" fn query_callback(
    _query: *mut bindings::_cups_dnssd_query_s,
    cb_data: *mut c_void,
    flags: bindings::cups_dnssd_flags_t,
    interface_index: u32,
    full_name: *const i8,
    record_type: u16,
    query_data: *const c_void,
    query_len: u16,
) {
    if cb_data.is_null()
        || full_name.is_null()
        || query_data.is_null()
        || flags & bindings::cups_dnssd_flags_e_CUPS_DNSSD_FLAGS_ERROR != 0
    {
        return;
    }

    let bytes = unsafe { slice::from_raw_parts(query_data.cast::<u8>(), usize::from(query_len)) };
    let address = match (record_type, bytes) {
        (1, [a, b, c, d]) => IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)),
        (28, bytes) if bytes.len() == 16 => {
            let Ok(octets) = <[u8; 16]>::try_from(bytes) else {
                return;
            };
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => return,
    };
    let state = unsafe { &*(cb_data.cast::<QueryState>()) };
    let _ = state.0.send(DnssdAddressEvent {
        added: flags & bindings::cups_dnssd_flags_e_CUPS_DNSSD_FLAGS_ADD != 0,
        interface_index,
        hostname: unsafe { CStr::from_ptr(full_name) }
            .to_string_lossy()
            .trim_end_matches('.')
            .to_string(),
        address,
    });
}
