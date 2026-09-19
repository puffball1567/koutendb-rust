//! Native TCP access without the KoutenDB shared library.
//! Operations exclusively borrow the client; connections are not multiplexed.
mod client;
mod connection;
pub use client::TcpClient;
use std::{
    fmt, io,
    path::PathBuf,
    str::FromStr,
    time::{Duration, Instant},
};
use zeroize::Zeroize;

const HEADER: usize = 8192;
const MAX_FRAME: usize = 64 * 1024 * 1024;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Connection,
    Timeout,
    Authentication,
    Protocol,
    VersionMismatch,
    Server,
    IndeterminateWrite,
    InvalidInput,
}
#[derive(Debug)]
pub struct Error {
    pub kind: ErrorKind,
    message: &'static str,
}
impl Error {
    fn new(kind: ErrorKind, message: &'static str) -> Self {
        Self { kind, message }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message)
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;
fn protocol() -> Error {
    Error::new(ErrorKind::Protocol, "Invalid wire response")
}
fn input() -> Error {
    Error::new(ErrorKind::InvalidInput, "Invalid TCP option or request")
}
fn io_error(e: io::Error) -> Error {
    if matches!(
        e.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ) {
        Error::new(ErrorKind::Timeout, "TCP operation timed out")
    } else {
        Error::new(ErrorKind::Connection, "TCP connection failed")
    }
}
fn left(deadline: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| Error::new(ErrorKind::Timeout, "TCP operation timed out"))
}
fn length(s: &str, max: usize) -> Result<usize> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0'))
    {
        return Err(protocol());
    }
    s.parse::<usize>()
        .ok()
        .filter(|n| *n <= max)
        .ok_or_else(protocol)
}
fn expect(parts: &[String], tag: &str, n: usize, auth: bool) -> Result<()> {
    if parts.first().map(String::as_str) == Some("ERR") {
        return Err(Error::new(
            if auth {
                ErrorKind::Authentication
            } else {
                ErrorKind::Server
            },
            "Server rejected request",
        ));
    }
    if parts.len() != n || parts[0] != tag {
        return Err(protocol());
    }
    Ok(())
}

/// Complete server-supplied identity; no placement calculation is performed.
#[derive(Debug, Clone, PartialEq)]
pub struct TcpId {
    pub parent: u64,
    pub epoch: u32,
    pub seq: u32,
    pub t_write: f64,
    pub period: f64,
    pub head: f64,
}
impl TcpId {
    fn fields(parts: &[&str]) -> Result<Self> {
        if parts.len() != 6 {
            return Err(protocol());
        }
        for part in &parts[..3] {
            if part.is_empty()
                || !part.bytes().all(|b| b.is_ascii_digit())
                || (part.len() > 1 && part.starts_with('0'))
            {
                return Err(protocol());
            }
        }
        let id = Self {
            parent: parts[0].parse().map_err(|_| protocol())?,
            epoch: parts[1].parse().map_err(|_| protocol())?,
            seq: parts[2].parse().map_err(|_| protocol())?,
            t_write: parts[3].parse().map_err(|_| protocol())?,
            period: parts[4].parse().map_err(|_| protocol())?,
            head: parts[5].parse().map_err(|_| protocol())?,
        };
        if !id.t_write.is_finite()
            || !id.period.is_finite()
            || id.period <= 0.0
            || !id.head.is_finite()
        {
            return Err(protocol());
        }
        Ok(id)
    }
    fn wire(&self) -> Result<String> {
        self.to_string().parse::<Self>()?;
        Ok(self.to_string().replace(':', " "))
    }
}
impl FromStr for TcpId {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::fields(&s.split(':').collect::<Vec<_>>())
    }
}
impl fmt::Display for TcpId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}:{}:{}",
            self.parent, self.epoch, self.seq, self.t_write, self.period, self.head
        )
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    Raw,
    Json,
    Nif,
    Bif,
}
impl Codec {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Json => "json",
            Self::Nif => "nif",
            Self::Bif => "bif",
        }
    }
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "raw" => Ok(Self::Raw),
            "json" => Ok(Self::Json),
            "nif" => Ok(Self::Nif),
            "bif" => Ok(Self::Bif),
            _ => Err(protocol()),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedPayload {
    pub payload: Vec<u8>,
    pub codec: Codec,
}
#[derive(Default)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    pub auth_token: String,
    pub secret_key: String,
}
impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Credentials([REDACTED])")
    }
}
impl Drop for Credentials {
    fn drop(&mut self) {
        self.username.zeroize();
        self.password.zeroize();
        self.auth_token.zeroize();
        self.secret_key.zeroize();
    }
}
#[derive(Debug, Default)]
pub struct TlsOptions {
    pub ca_file: Option<PathBuf>,
    pub server_name: Option<String>,
    /// Development only: bypasses both certificate and hostname verification.
    pub insecure_skip_verify: bool,
}
#[derive(Debug)]
pub struct TcpOptions {
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub write_timeout: Duration,
    pub max_frame_bytes: usize,
    pub max_redirects: usize,
    pub retry_reads: bool,
    pub credentials: Credentials,
    pub galaxy: String,
    pub tls: Option<TlsOptions>,
}
impl Default for TcpOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(3),
            read_timeout: Duration::from_secs(5),
            write_timeout: Duration::from_secs(5),
            max_frame_bytes: MAX_FRAME,
            max_redirects: 8,
            retry_reads: true,
            credentials: Credentials::default(),
            galaxy: String::new(),
            tls: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_bounds() {
        let text = "18446744073709551615:4294967295:4294967295:1.25:60:0.5";
        assert_eq!(text.parse::<TcpId>().unwrap().to_string(), text);
        for text in [
            "18446744073709551616:1:1:1:60:0",
            "1:4294967296:1:1:60:0",
            "1:1:1:NaN:60:0",
            "1:1:1:1:0:0",
            "1:1:1:1:60:inf",
        ] {
            assert!(text.parse::<TcpId>().is_err());
        }
    }
    #[test]
    fn bounded_lengths() {
        assert_eq!(length("0", 10).unwrap(), 0);
        assert_eq!(length("10", 10).unwrap(), 10);
        for s in ["-1", "11", "1e1", "99999999999999999999999", "01"] {
            assert!(length(s, 10).is_err());
        }
    }
    #[test]
    fn secret_debug() {
        let mut c = Credentials::default();
        c.password = "private-password".into();
        assert!(!format!("{c:?}").contains("private-password"));
    }
    #[test]
    fn invalid_options() {
        assert!(TcpClient::connect(vec![], TcpOptions::default()).is_err());
        let o = TcpOptions {
            read_timeout: Duration::ZERO,
            ..Default::default()
        };
        assert!(TcpClient::connect(vec!["localhost:1".into()], o).is_err());
    }
}
