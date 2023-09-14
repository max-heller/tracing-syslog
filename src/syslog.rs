use std::{borrow::Cow, cell::RefCell, ffi::CStr, io, sync::atomic::AtomicBool};
use tracing_core::{Level, Metadata};
use tracing_subscriber::fmt::MakeWriter;

/// `syslog` options.
///
/// # Examples
/// ```
/// use syslog_tracing::Options;
/// // Log PID with messages and log to stderr as well as `syslog`.
/// let opts = Options::LOG_PID | Options::LOG_PERROR;
/// ```
#[derive(Copy, Clone, Debug, Default)]
pub struct Options(libc::c_int);

impl Options {
    /// Log the pid with each message.
    pub const LOG_PID: Self = Self(libc::LOG_PID);
    /// Log on the console if errors in sending.
    pub const LOG_CONS: Self = Self(libc::LOG_CONS);
    /// Delay open until first syslog() (default).
    pub const LOG_ODELAY: Self = Self(libc::LOG_ODELAY);
    /// Don't delay open.
    pub const LOG_NDELAY: Self = Self(libc::LOG_NDELAY);
    /// Don't wait for console forks: DEPRECATED.
    pub const LOG_NOWAIT: Self = Self(libc::LOG_NOWAIT);
    /// Log to stderr as well.
    pub const LOG_PERROR: Self = Self(libc::LOG_PERROR);
}

impl std::ops::BitOr for Options {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

/// `syslog` facility.
#[derive(Copy, Clone, Debug)]
#[repr(i32)]
pub enum Facility {
    /// Generic user-level messages.
    #[cfg_attr(docsrs, doc(alias = "LOG_USER"))]
    User = libc::LOG_USER,
    /// Mail subsystem.
    #[cfg_attr(docsrs, doc(alias = "LOG_MAIL"))]
    Mail = libc::LOG_MAIL,
    /// System daemons without separate facility value.
    #[cfg_attr(docsrs, doc(alias = "LOG_DAEMON"))]
    Daemon = libc::LOG_DAEMON,
    /// Security/authorization messages.
    #[cfg_attr(docsrs, doc(alias = "LOG_AUTH"))]
    Auth = libc::LOG_AUTH,
    /// Line printer subsystem.
    #[cfg_attr(docsrs, doc(alias = "LOG_LPR"))]
    Lpr = libc::LOG_LPR,
    /// USENET news subsystem.
    #[cfg_attr(docsrs, doc(alias = "LOG_NEWS"))]
    News = libc::LOG_NEWS,
    /// UUCP subsystem.
    #[cfg_attr(docsrs, doc(alias = "LOG_UUCP"))]
    Uucp = libc::LOG_UUCP,
    /// Clock daemon (`cron` and `at`).
    #[cfg_attr(docsrs, doc(alias = "LOG_CRON"))]
    Cron = libc::LOG_CRON,
    /// Security/authorization messages (private).
    #[cfg_attr(docsrs, doc(alias = "LOG_AUTHPRIV"))]
    AuthPriv = libc::LOG_AUTHPRIV,
    /// FTP daemon.
    #[cfg_attr(docsrs, doc(alias = "LOG_FTP"))]
    Ftp = libc::LOG_FTP,
    /// Reserved for local use.
    #[cfg_attr(docsrs, doc(alias = "LOG_LOCAL0"))]
    Local0 = libc::LOG_LOCAL0,
    /// Reserved for local use.
    #[cfg_attr(docsrs, doc(alias = "LOG_LOCAL1"))]
    Local1 = libc::LOG_LOCAL1,
    /// Reserved for local use.
    #[cfg_attr(docsrs, doc(alias = "LOG_LOCAL2"))]
    Local2 = libc::LOG_LOCAL2,
    /// Reserved for local use.
    #[cfg_attr(docsrs, doc(alias = "LOG_LOCAL3"))]
    Local3 = libc::LOG_LOCAL3,
    /// Reserved for local use.
    #[cfg_attr(docsrs, doc(alias = "LOG_LOCAL4"))]
    Local4 = libc::LOG_LOCAL4,
    /// Reserved for local use.
    #[cfg_attr(docsrs, doc(alias = "LOG_LOCAL5"))]
    Local5 = libc::LOG_LOCAL5,
    /// Reserved for local use.
    #[cfg_attr(docsrs, doc(alias = "LOG_LOCAL6"))]
    Local6 = libc::LOG_LOCAL6,
    /// Reserved for local use.
    #[cfg_attr(docsrs, doc(alias = "LOG_LOCAL7"))]
    Local7 = libc::LOG_LOCAL7,
}

impl Default for Facility {
    fn default() -> Self {
        Self::User
    }
}

/// `syslog` severity.
#[derive(Copy, Clone)]
#[repr(i32)]
// There are more `syslog` severities than `tracing` levels, so some severities
// aren't used. They're included here for completeness and so the level mapping
// could easily change to include them.
#[allow(dead_code)]
enum Severity {
    /// System is unusable.
    #[cfg_attr(docsrs, doc(alias = "LOG_EMERG"))]
    Emergency = libc::LOG_EMERG,
    /// Action must be taken immediately.
    #[cfg_attr(docsrs, doc(alias = "LOG_ALERT"))]
    Alert = libc::LOG_ALERT,
    /// Critical conditions.
    #[cfg_attr(docsrs, doc(alias = "LOG_CRIT"))]
    Critical = libc::LOG_CRIT,
    /// Error conditions.
    #[cfg_attr(docsrs, doc(alias = "LOG_ERR"))]
    Error = libc::LOG_ERR,
    /// Warning conditions.
    #[cfg_attr(docsrs, doc(alias = "LOG_WARNING"))]
    Warning = libc::LOG_WARNING,
    /// Normal, but significant, condition.
    #[cfg_attr(docsrs, doc(alias = "LOG_NOTICE"))]
    Notice = libc::LOG_NOTICE,
    /// Informational message.
    #[cfg_attr(docsrs, doc(alias = "LOG_INFO"))]
    Info = libc::LOG_INFO,
    /// Debug-level message.
    #[cfg_attr(docsrs, doc(alias = "LOG_DEBUG"))]
    Debug = libc::LOG_DEBUG,
}

impl From<Level> for Severity {
    fn from(level: Level) -> Self {
        match level {
            Level::ERROR => Self::Error,
            Level::WARN => Self::Warning,
            Level::INFO => Self::Notice,
            Level::DEBUG => Self::Info,
            Level::TRACE => Self::Debug,
        }
    }
}

/// `syslog` priority.
#[derive(Copy, Clone, Debug)]
struct Priority(libc::c_int);

impl Priority {
    fn new(facility: Facility, level: Level) -> Self {
        let severity = Severity::from(level);
        Self((facility as libc::c_int) | (severity as libc::c_int))
    }
}

fn syslog(priority: Priority, msg: &CStr) {
    // SAFETY: the second argument must be a valid pointer to a nul-terminated
    // format string and formatting placeholders e.g. %s must correspond to
    // one of the variable-length arguments. By construction, the format string
    // is nul-terminated, and the only string formatting placeholder corresponds
    // to `msg.as_ptr()`, which is a valid, nul-terminated string in C world
    // because `msg` is a `CStr`.
    unsafe { libc::syslog(priority.0, "%s\0".as_ptr().cast(), msg.as_ptr()) }
}

/// [`MakeWriter`] that logs to `syslog` via `libc`'s [`syslog()`](libc::syslog) function.
///
/// # Level Mapping
///
/// `tracing` [`Level`]s are mapped to `syslog` severities as follows:
///
/// ```raw
/// Level::ERROR => Severity::LOG_ERR,
/// Level::WARN  => Severity::LOG_WARNING,
/// Level::INFO  => Severity::LOG_NOTICE,
/// Level::DEBUG => Severity::LOG_INFO,
/// Level::TRACE => Severity::LOG_DEBUG,
/// ```
///
/// **Note:** the mapping is lossless, but the corresponding `syslog` severity
/// names differ from `tracing`'s level names towards the bottom. `syslog`
/// does not have a level lower than `LOG_DEBUG`, so this is unavoidable.
///
/// # Examples
///
/// Initializing a global logger that writes to `syslog` with an identity of `example-program`
/// and the default `syslog` options and facility:
///
/// ```
/// let identity = std::ffi::CStr::from_bytes_with_nul(b"example-program\0").unwrap();
/// let (options, facility) = Default::default();
/// let syslog = syslog_tracing::Syslog::new(identity, options, facility).unwrap();
/// tracing_subscriber::fmt().with_writer(syslog).init();
/// ```
pub struct Syslog {
    /// Identity e.g. program name. Referenced by syslog, so we store it here to
    /// ensure it lives until we are done logging.
    #[allow(dead_code)]
    identity: Cow<'static, CStr>,
    facility: Facility,
}

impl Syslog {
    /// Tracks whether there is a logger currently initialized (i.e. whether there
    /// has been an `openlog()` call without a corresponding `closelog()` call).
    fn initialized() -> &'static AtomicBool {
        static INITIALIZED: AtomicBool = AtomicBool::new(false);
        &INITIALIZED
    }

    /// Creates a [`tracing`] [`MakeWriter`] that writes to `syslog`.
    ///
    /// This calls [`libc::openlog()`] to initialize the logger. The corresponding
    /// [`libc::closelog()`] call happens when the returned logger is dropped.
    /// If a logger already exists, returns `None`.
    ///
    /// # Examples
    ///
    /// Creating a `syslog` [`MakeWriter`] with an identity of `example-program` and
    /// the default `syslog` options and facility:
    ///
    /// ```
    /// use syslog_tracing::Syslog;
    /// let identity = std::ffi::CStr::from_bytes_with_nul(b"example-program\0").unwrap();
    /// let (options, facility) = Default::default();
    /// let syslog = Syslog::new(identity, options, facility).unwrap();
    /// ```
    ///
    /// Two loggers cannot coexist, since [`libc::syslog()`] writes to a global logger:
    ///
    /// ```
    /// # use syslog_tracing::Syslog;
    /// # let identity = std::ffi::CStr::from_bytes_with_nul(b"example-program\0").unwrap();
    /// # let (options, facility) = Default::default();
    /// let syslog = Syslog::new(identity, options, facility).unwrap();
    /// assert!(Syslog::new(identity, options, facility).is_none());
    /// ```
    pub fn new(
        identity: impl Into<Cow<'static, CStr>>,
        options: Options,
        facility: Facility,
    ) -> Option<Self> {
        use std::sync::atomic::Ordering;
        // Make sure another logger isn't already initialized
        if let Ok(false) =
            Self::initialized().compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        {
            let identity = identity.into();
            // SAFETY: identity will remain alive until the returned struct's fields
            // are dropped, by which point `closelog` will have been called by the
            // `Drop` implementation.
            unsafe { libc::openlog(identity.as_ptr(), options.0, facility as libc::c_int) };
            Some(Syslog { identity, facility })
        } else {
            None
        }
    }
}

impl Drop for Syslog {
    /// Calls [`libc::closelog()`].
    fn drop(&mut self) {
        unsafe { libc::closelog() };

        // Since only one logger can be initialized at a time (enforced by the
        // constructor), dropping a logger means there is now no initialized
        // logger.
        use std::sync::atomic::Ordering;
        assert!(Self::initialized().swap(false, Ordering::SeqCst));
    }
}

impl<'a> MakeWriter<'a> for Syslog {
    type Writer = SyslogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        SyslogWriter::new(self.facility, Level::INFO)
    }

    fn make_writer_for(&'a self, meta: &Metadata<'_>) -> Self::Writer {
        SyslogWriter::new(self.facility, *meta.level())
    }
}

/// [Writer](io::Write) to `syslog` produced by [`MakeWriter`].
pub struct SyslogWriter {
    facility: Facility,
    level: Level,
}

impl SyslogWriter {
    fn new(facility: Facility, level: Level) -> Self {
        SyslogWriter {
            facility,
            level,
        }
    }
}

thread_local! { static BUF: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(256)) }

impl io::Write for SyslogWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        // Check if the data is already a cstr
        if let Ok(cstr) = CStr::from_bytes_with_nul(bytes) {
            syslog(Priority::new(self.facility, self.level), cstr);
            return Ok(bytes.len());
        }

        // If we got here, it means that there's an interior nul or it's not nul
        // terminated

        if bytes.last() == Some(&0x00) {
            // We're nul terminated, which means that we must have had a
            // interior nul.
            //
            // Interior nuls are never valid CStrs, so instead of truncating,
            // fail instead.
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Data provided to syslog must be not have interior nuls"));
        }

        // We have a non-nul terminated string; Re-use the buffer to create a
        // nul-terminated cstr
        #[cfg(debug_assertions)]
        assert!(bytes.iter().all(|b| *b != 0x00), "we should have non-null data here");
        BUF.with(|buf| {
            let mut buf = buf.borrow_mut();
            buf.clear();
            buf.extend_from_slice(bytes);
            buf.push(0x00);

            // SAFETY: We just added a nul terminator and asserted that the
            // data has no interior nuls. We also cleared the buffer, so the
            // only data in there is a interior-nul-free, nul-terminated slice.
            let cstr = unsafe { CStr::from_bytes_with_nul_unchecked(&buf) };
            syslog(Priority::new(self.facility, self.level), cstr);
            Ok(bytes.len())
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use once_cell::sync::Lazy;
    use std::sync::Mutex;

    const IDENTITY: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"example-program\0") };
    const OPTIONS: Options = Options(0);
    const FACILITY: Facility = Facility::User;

    static INITIALIZED: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    fn capture_stderr(f: impl FnOnce()) -> String {
        use std::io::Read;
        let mut buf = gag::BufferRedirect::stderr().unwrap();
        f();
        let mut output = String::new();
        buf.read_to_string(&mut output).unwrap();
        output
    }

    fn with_initialized(f: impl FnOnce()) -> Vec<String> {
        let _lock = INITIALIZED.lock();
        let syslog = Syslog::new(IDENTITY, OPTIONS | Options::LOG_PERROR, FACILITY).unwrap();
        let subscriber = tracing_subscriber::fmt().with_writer(syslog).finish();
        tracing::subscriber::with_default(subscriber, || capture_stderr(f))
            .lines()
            .map(String::from)
            .collect()
    }

    #[test]
    fn double_init() {
        let _lock = INITIALIZED.lock();
        let _syslog = Syslog::new(IDENTITY, OPTIONS, FACILITY).unwrap();
        assert!(
            Syslog::new(IDENTITY, OPTIONS, FACILITY).is_none(),
            "double initialization"
        );
    }

    #[test]
    fn init_after_drop() {
        let _lock = INITIALIZED.lock();
        let syslog = Syslog::new(IDENTITY, OPTIONS, FACILITY).unwrap();
        drop(syslog);
        Syslog::new(IDENTITY, OPTIONS, FACILITY).unwrap();
    }

    #[test]
    fn basic_log() {
        let text = "test message";
        match with_initialized(|| tracing::info!("{}", text)).as_slice() {
            [msg] if msg.contains(text) => (),
            x => panic!("expected log message containing '{}', got '{:?}'", text, x),
        }
    }
}
