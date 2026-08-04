use crate::destination::{DestCallback, Destination};
use crate::error::{Error, Result};
use crate::{bindings, config::EncryptionMode};
use std::ffi::{CStr, CString};
use std::marker::PhantomData;
use std::os::raw::{c_int, c_void};
use std::ptr;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};

/// Connection flags for controlling how to connect to a destination
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionFlags {
    /// Connect to CUPS scheduler
    Scheduler = 0,
    /// Connect directly to device/printer
    Device = 1,
}

impl From<ConnectionFlags> for u32 {
    fn from(flags: ConnectionFlags) -> u32 {
        match flags {
            ConnectionFlags::Scheduler => crate::DEST_FLAGS_NONE,
            ConnectionFlags::Device => crate::DEST_FLAGS_DEVICE,
        }
    }
}

/// Represents an HTTP connection to a CUPS server or printer
///
/// This structure provides a safe wrapper around the CUPS `http_t` type.
/// Connections are automatically closed when the HttpConnection is dropped.
///
/// # Examples
///
/// ```no_run
/// use cups_rs::{get_default_destination, ConnectionFlags};
///
/// let printer = get_default_destination().expect("No default printer");
/// let connection = printer.connect(ConnectionFlags::Scheduler, Some(5000), None)
///     .expect("Failed to connect");
///
/// println!("Connected to: {}", connection.resource_path());
/// ```
pub struct HttpConnection {
    http: *mut bindings::_http_s,
    resource: String,
    _phantom: PhantomData<bindings::_http_s>,
}

impl HttpConnection {
    /// Create a new HttpConnection from a raw http_t pointer
    pub(crate) unsafe fn from_raw(http: *mut bindings::_http_s, resource: String) -> Result<Self> {
        if http.is_null() {
            return Err(Error::ConnectionFailed(
                "Failed to establish connection".to_string(),
            ));
        }

        Ok(HttpConnection {
            http,
            resource,
            _phantom: PhantomData,
        })
    }

    /// Connect directly to a host and resource path.
    pub fn connect_host(
        host: &str,
        port: u16,
        resource: &str,
        timeout_ms: Option<i32>,
    ) -> Result<Self> {
        Self::connect_host_with_encryption(
            host,
            port,
            resource,
            EncryptionMode::IfRequested,
            timeout_ms,
        )
    }

    /// Connect directly to a host with an explicit encryption policy.
    pub fn connect_host_with_encryption(
        host: &str,
        port: u16,
        resource: &str,
        encryption: EncryptionMode,
        timeout_ms: Option<i32>,
    ) -> Result<Self> {
        let host = CString::new(host)?;
        let http = unsafe {
            bindings::httpConnect(
                host.as_ptr(),
                port.into(),
                ptr::null_mut(),
                0,
                encryption.into(),
                true,
                timeout_ms.unwrap_or(-1),
                ptr::null_mut(),
            )
        };
        if http.is_null() {
            return Err(Error::ConnectionFailed(
                "Failed to connect to printer URI".to_string(),
            ));
        }

        Ok(Self {
            http,
            resource: resource.to_string(),
            _phantom: PhantomData,
        })
    }

    /// Get the raw pointer to the http_t structure
    pub fn as_ptr(&self) -> *mut bindings::_http_s {
        self.http
    }

    /// Sets how long an individual read or write on this connection may stall.
    ///
    /// The timeout passed to [`HttpConnection::connect_host`] only bounds
    /// connection setup. This bounds the wait for a reply, which matters for
    /// operations that do real work before responding — a Printer Application
    /// answering `PAPPL-Find-Devices` rescans USB, SNMP and DNS-SD first, and can
    /// take tens of seconds.
    ///
    /// A non-positive value restores the default of waiting indefinitely.
    pub fn set_timeout(&mut self, seconds: f64) {
        unsafe {
            bindings::httpSetTimeout(self.http, seconds, None, ptr::null_mut());
        }
    }

    /// Get the resource path for this connection
    pub fn resource_path(&self) -> &str {
        &self.resource
    }

    /// Returns the hostname selected for this connection.
    pub fn hostname(&self) -> Option<String> {
        let mut buffer = [0i8; 1024];
        let hostname =
            unsafe { bindings::httpGetHostname(self.http, buffer.as_mut_ptr(), buffer.len()) };
        if hostname.is_null() {
            return None;
        }

        Some(
            unsafe { CStr::from_ptr(hostname) }
                .to_string_lossy()
                .trim_end_matches('.')
                .to_string(),
        )
        .filter(|hostname| !hostname.is_empty())
    }

    /// Returns the peer address selected for this connection.
    pub fn address(&self) -> Option<std::net::IpAddr> {
        let address = unsafe { bindings::httpGetAddress(self.http) };
        if address.is_null() {
            return None;
        }

        let mut buffer = [0i8; 128];
        let value =
            unsafe { bindings::httpAddrGetString(address, buffer.as_mut_ptr(), buffer.len()) };
        if value.is_null() {
            return None;
        }

        std::net::IpAddr::from_str(unsafe { CStr::from_ptr(value) }.to_str().ok()?).ok()
    }

    /// Returns the peer port selected for this connection.
    pub fn port(&self) -> Option<u16> {
        let address = unsafe { bindings::httpGetAddress(self.http) };
        if address.is_null() {
            return None;
        }

        u16::try_from(unsafe { bindings::httpAddrGetPort(address) }).ok()
    }

    /// Close the HTTP connection
    pub fn close(&mut self) {
        if !self.http.is_null() {
            unsafe {
                bindings::httpClose(self.http);
            }
            self.http = ptr::null_mut();
        }
    }

    /// Check if the connection is still valid
    pub fn is_connected(&self) -> bool {
        !self.http.is_null()
    }
}

impl Drop for HttpConnection {
    fn drop(&mut self) {
        self.close();
    }
}

impl Destination {
    /// Connect to this destination
    ///
    /// Opens a direct connection to the destination, which can be used for
    /// sending IPP requests directly to the printer or CUPS scheduler.
    ///
    /// # Arguments
    /// * `flags` - Whether to connect to scheduler or device directly
    /// * `timeout_ms` - Connection timeout in milliseconds, None for indefinite
    /// * `cancel` - Optional cancellation flag
    ///
    /// # Returns
    /// * `Ok((HttpConnection, String))` - Connection and resource path
    /// * `Err(Error)` - Connection failed
    pub fn connect(
        &self,
        flags: ConnectionFlags,
        timeout_ms: Option<i32>,
        cancel: Option<&AtomicBool>,
    ) -> Result<HttpConnection> {
        // Create a raw cups_dest_t for this destination
        let dest_ptr = self.as_ptr();
        if dest_ptr.is_null() {
            return Err(Error::NullPointer);
        }

        let timeout = timeout_ms.unwrap_or(-1);
        let mut cancel_int: c_int = 0;
        let cancel_ptr = if cancel.is_some() {
            &mut cancel_int as *mut c_int
        } else {
            ptr::null_mut()
        };

        // Allocate resource buffer
        const RESOURCE_SIZE: usize = 1024;
        let mut resource_buf: Vec<u8> = vec![0; RESOURCE_SIZE];

        let http_conn = unsafe {
            bindings::cupsConnectDest(
                dest_ptr,
                flags.into(),
                timeout,
                cancel_ptr,
                resource_buf.as_mut_ptr() as *mut ::std::os::raw::c_char,
                RESOURCE_SIZE,
                None,            // No callback for now
                ptr::null_mut(), // No user data
            )
        };

        // Check for cancellation
        if let Some(cancel_flag) = cancel {
            if cancel_int != 0 {
                cancel_flag.store(true, Ordering::SeqCst);
            }
        }

        if http_conn.is_null() {
            return Err(Error::ConnectionFailed(format!(
                "Failed to connect to destination '{}'",
                self.name
            )));
        }

        // Convert resource buffer to string
        let resource_len = resource_buf.iter().position(|&x| x == 0).unwrap_or(0);
        let resource = String::from_utf8_lossy(&resource_buf[..resource_len]).into_owned();

        unsafe { HttpConnection::from_raw(http_conn, resource) }
    }

    /// Connect to this destination with a callback
    ///
    /// Opens a connection with a callback function that can monitor the
    /// connection process and potentially cancel it.
    ///
    /// # Arguments
    /// * `flags` - Whether to connect to scheduler or device directly
    /// * `timeout_ms` - Connection timeout in milliseconds, None for indefinite
    /// * `cancel` - Optional cancellation flag
    /// * `callback` - Callback function for connection monitoring
    /// * `user_data` - User data passed to callback
    ///
    /// # Returns
    /// * `Ok(HttpConnection)` - Established connection
    /// * `Err(Error)` - Connection failed or was cancelled
    pub fn connect_with_callback<T>(
        &self,
        flags: ConnectionFlags,
        timeout_ms: Option<i32>,
        cancel: Option<&AtomicBool>,
        callback: &mut DestCallback<T>,
        user_data: &mut T,
    ) -> Result<HttpConnection> {
        // Create a raw cups_dest_t for this destination
        let dest_ptr = self.as_ptr();
        if dest_ptr.is_null() {
            return Err(Error::NullPointer);
        }

        let timeout = timeout_ms.unwrap_or(-1);
        let mut cancel_int: c_int = 0;
        let cancel_ptr = if cancel.is_some() {
            &mut cancel_int as *mut c_int
        } else {
            ptr::null_mut()
        };

        // Create callback context
        let mut context = ConnectContext {
            callback,
            user_data,
        };

        // Allocate resource buffer
        const RESOURCE_SIZE: usize = 1024;
        let mut resource_buf: Vec<u8> = vec![0; RESOURCE_SIZE];

        let http_conn = unsafe {
            bindings::cupsConnectDest(
                dest_ptr,
                flags.into(),
                timeout,
                cancel_ptr,
                resource_buf.as_mut_ptr() as *mut ::std::os::raw::c_char,
                RESOURCE_SIZE,
                Some(connect_dest_callback::<T>),
                &mut context as *mut _ as *mut c_void,
            )
        };

        // Check for cancellation
        if let Some(cancel_flag) = cancel {
            if cancel_int != 0 {
                cancel_flag.store(true, Ordering::SeqCst);
            }
        }

        if http_conn.is_null() {
            return Err(Error::ConnectionFailed(format!(
                "Failed to connect to destination '{}' or connection was cancelled",
                self.name
            )));
        }

        // Convert resource buffer to string
        let resource_len = resource_buf.iter().position(|&x| x == 0).unwrap_or(0);
        let resource = String::from_utf8_lossy(&resource_buf[..resource_len]).into_owned();

        unsafe { HttpConnection::from_raw(http_conn, resource) }
    }
}

// Context structure for the connection callback
struct ConnectContext<'a, T> {
    callback: &'a mut DestCallback<T>,
    user_data: &'a mut T,
}

// C-compatible callback function for connection monitoring
unsafe extern "C" fn connect_dest_callback<T>(
    user_data: *mut c_void,
    flags: u32,
    dest_ptr: *mut bindings::cups_dest_s,
) -> bool {
    // Reconstruct our context
    let context = unsafe { &mut *(user_data as *mut ConnectContext<T>) };

    // Convert the raw destination to our Rust type
    unsafe {
        match Destination::from_raw(dest_ptr) {
            Ok(dest) => {
                // Call the user's callback
                if (context.callback)(flags, &dest, context.user_data) {
                    true // Continue connection
                } else {
                    false // Cancel connection
                }
            }
            Err(_) => {
                // Error parsing destination, but continue anyway
                true
            }
        }
    }
}

/// Connect to a destination
///
/// This is a convenience function that creates a connection to a destination.
///
/// # Arguments
/// * `dest` - Destination to connect to
/// * `flags` - Connection flags
/// * `timeout_ms` - Connection timeout in milliseconds, None for indefinite
/// * `cancel` - Optional cancellation flag
///
/// # Returns
/// * `Ok(HttpConnection)` - Established connection
/// * `Err(Error)` - Connection failed
pub fn connect_to_destination(
    dest: &Destination,
    flags: ConnectionFlags,
    timeout_ms: Option<i32>,
    cancel: Option<&AtomicBool>,
) -> Result<HttpConnection> {
    dest.connect(flags, timeout_ms, cancel)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destination::get_all_destinations;

    #[test]
    fn test_connection_flags() {
        assert_eq!(
            u32::from(ConnectionFlags::Scheduler),
            crate::DEST_FLAGS_NONE
        );
        assert_eq!(u32::from(ConnectionFlags::Device), crate::DEST_FLAGS_DEVICE);
    }

    #[test]
    fn test_connect_to_scheduler() {
        // This test requires a CUPS server to be running
        if let Ok(destinations) = get_all_destinations() {
            if let Some(dest) = destinations.first() {
                // Try to connect with a short timeout
                match dest.connect(ConnectionFlags::Scheduler, Some(1000), None) {
                    Ok(conn) => {
                        assert!(conn.is_connected());
                        assert!(!conn.resource_path().is_empty());
                        println!(
                            "Connected to '{}' with resource path: '{}'",
                            dest.name,
                            conn.resource_path()
                        );
                    }
                    Err(e) => {
                        // Connection might fail in test environment, that's OK
                        println!("Connection failed (expected in test): {}", e);
                    }
                }
            }
        }
    }
}
