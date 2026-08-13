use std::error::Error as StdError;
use std::ffi::{CStr, CString, NulError};
use std::fmt;
use std::os::raw::{c_char, c_double, c_float, c_int, c_void};
use std::ptr;
use std::slice;
use std::str::FromStr;
use std::sync::Once;

pub const KOUTEN_ABI_VERSION: i32 = 2;

const KOUTEN_OK: c_int = 0;
const KOUTEN_CODEC_RAW: c_int = 0;
const KOUTEN_CODEC_JSON: c_int = 1;
const KOUTEN_CODEC_NIF: c_int = 2;
const KOUTEN_CODEC_BIF: c_int = 3;

static INIT: Once = Once::new();

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct KoutenId {
    pub parent: u64,
    pub epoch: u32,
    pub seq: u32,
    pub t_write: f64,
}

impl KoutenId {
    pub fn new(parent: u64, epoch: u32, seq: u32, t_write: f64) -> Self {
        Self {
            parent,
            epoch,
            seq,
            t_write,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.parent == 0 && self.epoch == 0 && self.seq == 0 && self.t_write == 0.0
    }

    pub fn parse(value: &str) -> Result<Self, Error> {
        value.parse()
    }
}

impl fmt::Display for KoutenId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}:{}",
            self.parent, self.epoch, self.seq, self.t_write
        )
    }
}

impl FromStr for KoutenId {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut parts = value.split(':');
        let parent = parse_id_part::<u64>(&mut parts, "parent")?;
        let epoch = parse_id_part::<u32>(&mut parts, "epoch")?;
        let seq = parse_id_part::<u32>(&mut parts, "seq")?;
        let t_write = parse_id_part::<f64>(&mut parts, "t_write")?;
        if parts.next().is_some() {
            return Err(Error::new(
                ErrorKind::InvalidId,
                format!("invalid KoutenDB id '{}': too many fields", value),
            ));
        }
        Ok(Self::new(parent, epoch, seq, t_write))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadCodec {
    Raw,
    Json,
    Nif,
    Bif,
}

/// Text format used by KoutenDB operational metrics endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum MetricsFormat {
    KeyValue = 0,
    Prometheus = 1,
    OpenMetrics = 2,
}

/// Options for opening a persistent embedded store with the v0.12 read layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenDirOptions {
    pub nodes: i32,
    pub strong_durability: bool,
    pub disk_backed: bool,
}

impl Default for OpenDirOptions {
    fn default() -> Self {
        Self {
            nodes: 8,
            strong_durability: false,
            disk_backed: false,
        }
    }
}

impl OpenDirOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn nodes(mut self, value: i32) -> Self {
        self.nodes = value;
        self
    }

    pub fn strong_durability(mut self, value: bool) -> Self {
        self.strong_durability = value;
        self
    }

    pub fn disk_backed(mut self, value: bool) -> Self {
        self.disk_backed = value;
        self
    }

    pub fn open(self, dir: &str) -> Result<KoutenDb, Error> {
        KoutenDb::open_dir_with(dir, self)
    }
}

/// Selection and resource bounds shared by maintenance planning and execution.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SegmentMaintenancePolicy {
    pub stale_ratio: f64,
    pub min_stale_records: i32,
    pub max_rings: i32,
    pub max_bytes: i64,
    pub max_elapsed_ms: i64,
}

impl Default for SegmentMaintenancePolicy {
    fn default() -> Self {
        Self {
            stale_ratio: 0.25,
            min_stale_records: 256,
            max_rings: 0,
            max_bytes: 0,
            max_elapsed_ms: 0,
        }
    }
}

impl SegmentMaintenancePolicy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn stale_threshold(mut self, ratio: f64, min_records: i32) -> Self {
        self.stale_ratio = ratio;
        self.min_stale_records = min_records;
        self
    }

    pub fn max_rings(mut self, value: i32) -> Self {
        self.max_rings = value;
        self
    }

    pub fn max_bytes(mut self, value: i64) -> Self {
        self.max_bytes = value;
        self
    }

    pub fn max_elapsed_ms(mut self, value: i64) -> Self {
        self.max_elapsed_ms = value;
        self
    }
}

impl PayloadCodec {
    fn as_c(self) -> c_int {
        match self {
            Self::Raw => KOUTEN_CODEC_RAW,
            Self::Json => KOUTEN_CODEC_JSON,
            Self::Nif => KOUTEN_CODEC_NIF,
            Self::Bif => KOUTEN_CODEC_BIF,
        }
    }

    fn from_c(value: c_int) -> Result<Self, Error> {
        match value {
            KOUTEN_CODEC_RAW => Ok(Self::Raw),
            KOUTEN_CODEC_JSON => Ok(Self::Json),
            KOUTEN_CODEC_NIF => Ok(Self::Nif),
            KOUTEN_CODEC_BIF => Ok(Self::Bif),
            _ => Err(Error::new(
                ErrorKind::Abi,
                format!("invalid KoutenDB payload codec {}", value),
            )),
        }
    }
}

#[repr(C)]
struct KoutenValue {
    data: *mut c_void,
    len: usize,
}

#[repr(C)]
struct KoutenBatchResult {
    len: usize,
    values: *mut KoutenValue,
}

#[repr(C)]
struct KoutenHitRaw {
    id: KoutenId,
    score: c_double,
    payload: *mut c_void,
    payload_len: usize,
}

#[repr(C)]
struct KoutenRetrieveResultRaw {
    len: usize,
    hits: *mut KoutenHitRaw,
    total_vectors: c_int,
    scanned: c_int,
    skipped_vectors: c_int,
    returned: c_int,
    rings_touched: c_int,
    payload_bytes: c_int,
    estimated_tokens: c_int,
    fanout_nodes: c_int,
    candidate_reduction: c_double,
}

#[link(name = "koutendb")]
extern "C" {
    fn kouten_init();
    fn kouten_abi_version() -> c_int;
    fn kouten_last_error() -> *const c_char;
    fn kouten_open(nodes: c_int) -> *mut c_void;
    fn kouten_open_dir(nodes: c_int, dir: *const c_char) -> *mut c_void;
    fn kouten_open_dir_options(
        nodes: c_int,
        dir: *const c_char,
        durability_strong: c_int,
        disk_backed: c_int,
    ) -> *mut c_void;
    fn kouten_connect(peers: *const c_char) -> *mut c_void;
    fn kouten_connect_auth(
        peers: *const c_char,
        username: *const c_char,
        password: *const c_char,
        auth_token: *const c_char,
        secret_key: *const c_char,
        galaxy: *const c_char,
    ) -> *mut c_void;
    fn kouten_connect_auth_tls(
        peers: *const c_char,
        username: *const c_char,
        password: *const c_char,
        auth_token: *const c_char,
        secret_key: *const c_char,
        galaxy: *const c_char,
        tls: c_int,
        tls_ca_file: *const c_char,
        tls_server_name: *const c_char,
        tls_insecure_skip_verify: c_int,
    ) -> *mut c_void;
    fn kouten_close(db: *mut c_void);
    fn kouten_free(p: *mut c_void);
    fn kouten_metrics_text(db: *mut c_void, format: c_int, out_len: *mut usize) -> *mut c_void;
    fn kouten_checkpoint_metrics_text(
        root: *const c_char,
        format: c_int,
        out_len: *mut usize,
    ) -> *mut c_void;
    fn kouten_now(db: *mut c_void) -> c_double;
    fn kouten_advance(db: *mut c_void, dt: c_double);
    fn kouten_ring_configure(db: *mut c_void, ring: *const c_char, period: c_double) -> c_int;
    fn kouten_set_galaxy_description(db: *mut c_void, description: *const c_char) -> c_int;
    fn kouten_set_ring_description(
        db: *mut c_void,
        ring: *const c_char,
        description: *const c_char,
    ) -> c_int;
    fn kouten_put(
        db: *mut c_void,
        ring: *const c_char,
        data: *const c_void,
        len: usize,
        out_id: *mut KoutenId,
    ) -> c_int;
    fn kouten_put_codec(
        db: *mut c_void,
        ring: *const c_char,
        data: *const c_void,
        len: usize,
        codec: c_int,
        out_id: *mut KoutenId,
    ) -> c_int;
    fn kouten_put_vec(
        db: *mut c_void,
        ring: *const c_char,
        data: *const c_void,
        len: usize,
        vec: *const c_float,
        vec_len: usize,
        out_id: *mut KoutenId,
    ) -> c_int;
    fn kouten_put_vec_codec(
        db: *mut c_void,
        ring: *const c_char,
        data: *const c_void,
        len: usize,
        codec: c_int,
        vec: *const c_float,
        vec_len: usize,
        out_id: *mut KoutenId,
    ) -> c_int;
    fn kouten_get(db: *mut c_void, id: KoutenId, out_len: *mut usize) -> *mut c_void;
    fn kouten_get_codec(
        db: *mut c_void,
        id: KoutenId,
        out_len: *mut usize,
        out_codec: *mut c_int,
    ) -> *mut c_void;
    fn kouten_exists(db: *mut c_void, id: KoutenId) -> c_int;
    fn kouten_update(db: *mut c_void, id: KoutenId, data: *const c_void, len: usize) -> c_int;
    fn kouten_update_codec(
        db: *mut c_void,
        id: KoutenId,
        data: *const c_void,
        len: usize,
        codec: c_int,
    ) -> c_int;
    fn kouten_remove(db: *mut c_void, id: KoutenId) -> c_int;
    fn kouten_batch_get(
        db: *mut c_void,
        ids: *const KoutenId,
        ids_len: usize,
    ) -> *mut KoutenBatchResult;
    fn kouten_batch_get_free(r: *mut KoutenBatchResult);
    fn kouten_query(
        db: *mut c_void,
        id: KoutenId,
        selection: *const c_char,
        out_len: *mut usize,
    ) -> *mut c_void;
    fn kouten_read_ring_json(
        db: *mut c_void,
        ring: *const c_char,
        filter_json: *const c_char,
        selection: *const c_char,
        limit: c_int,
        cursor: *const c_char,
        pagination: c_int,
        page: c_int,
        page_limit: c_int,
        sort_field: *const c_char,
        sort_desc: c_int,
        out_len: *mut usize,
    ) -> *mut c_void;
    fn kouten_retrieve(
        db: *mut c_void,
        vec: *const c_float,
        vec_len: usize,
        ring: *const c_char,
        budget: c_int,
        top_rings: c_int,
        focus: c_int,
    ) -> *mut KoutenRetrieveResultRaw;
    fn kouten_retrieve_free(r: *mut KoutenRetrieveResultRaw);
    fn kouten_atlas(
        db: *mut c_void,
        query_vec: *const c_float,
        query_vec_len: usize,
        max_centroid_dims: c_int,
        out_len: *mut usize,
    ) -> *mut c_void;
    fn kouten_segment_status_json(
        db: *mut c_void,
        stale_ratio: c_double,
        min_stale_records: c_int,
        out_len: *mut usize,
    ) -> *mut c_void;
    fn kouten_segment_maintenance_plan_json(
        db: *mut c_void,
        stale_ratio: c_double,
        min_stale_records: c_int,
        max_rings: c_int,
        max_bytes: i64,
        max_elapsed_ms: i64,
        out_len: *mut usize,
    ) -> *mut c_void;
    fn kouten_segment_maintenance_run_json(
        db: *mut c_void,
        stale_ratio: c_double,
        min_stale_records: c_int,
        max_rings: c_int,
        max_bytes: i64,
        max_elapsed_ms: i64,
        out_len: *mut usize,
    ) -> *mut c_void;
    fn kouten_segment_maintenance_status_json(db: *mut c_void, out_len: *mut usize) -> *mut c_void;
    fn kouten_segment_maintenance_recover(db: *mut c_void, out_recovered: *mut c_int) -> c_int;
    fn kouten_checkpoint_create_json(
        db: *mut c_void,
        root: *const c_char,
        checkpoint_id: *const c_char,
        out_len: *mut usize,
    ) -> *mut c_void;
    fn kouten_checkpoint_status_json(
        checkpoint_dir: *const c_char,
        out_len: *mut usize,
    ) -> *mut c_void;
    fn kouten_checkpoint_list_json(root: *const c_char, out_len: *mut usize) -> *mut c_void;
    fn kouten_checkpoint_cleanup_json(
        root: *const c_char,
        keep: c_int,
        out_len: *mut usize,
    ) -> *mut c_void;
    fn kouten_checkpoint_restore_json(
        checkpoint_dir: *const c_char,
        data_dir: *const c_char,
        overwrite: c_int,
        out_len: *mut usize,
    ) -> *mut c_void;
    fn kouten_locate(db: *mut c_void, id: KoutenId, at: c_double) -> c_int;
    fn kouten_next_visit(db: *mut c_void, id: KoutenId, node: c_int) -> c_double;
    fn kouten_next_join(db: *mut c_void, a: KoutenId, b: KoutenId) -> c_double;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Abi,
    AbiVersionMismatch,
    InvalidId,
    NotFound,
    NulByte,
    Utf8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    kind: ErrorKind,
    message: String,
}

impl Error {
    fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    fn last() -> Self {
        unsafe {
            let p = kouten_last_error();
            if p.is_null() {
                return Self::new(ErrorKind::Abi, "KoutenDB C ABI error");
            }
            let s = CStr::from_ptr(p).to_string_lossy();
            if s.is_empty() {
                Self::new(ErrorKind::Abi, "KoutenDB C ABI error")
            } else {
                let message = s.into_owned();
                let kind = classify_abi_error(&message);
                Self::new(kind, message)
            }
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.message.fmt(f)
    }
}

impl StdError for Error {}

impl From<NulError> for Error {
    fn from(value: NulError) -> Self {
        Self::new(ErrorKind::NulByte, value.to_string())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Hit {
    pub id: KoutenId,
    pub score: f64,
    pub payload: Vec<u8>,
}

impl Hit {
    pub fn payload_utf8(&self) -> Result<&str, Error> {
        std::str::from_utf8(&self.payload).map_err(|e| Error::new(ErrorKind::Utf8, e.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedPayload {
    pub data: Vec<u8>,
    pub codec: PayloadCodec,
}

impl EncodedPayload {
    pub fn new(data: impl Into<Vec<u8>>, codec: PayloadCodec) -> Self {
        Self {
            data: data.into(),
            codec,
        }
    }

    pub fn raw(data: impl Into<Vec<u8>>) -> Self {
        Self::new(data, PayloadCodec::Raw)
    }

    pub fn json(data: impl Into<Vec<u8>>) -> Self {
        Self::new(data, PayloadCodec::Json)
    }

    pub fn nif(data: impl Into<Vec<u8>>) -> Self {
        Self::new(data, PayloadCodec::Nif)
    }

    pub fn bif(data: impl Into<Vec<u8>>) -> Self {
        Self::new(data, PayloadCodec::Bif)
    }

    pub fn as_utf8(&self) -> Result<&str, Error> {
        std::str::from_utf8(&self.data).map_err(|e| Error::new(ErrorKind::Utf8, e.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RetrieveStats {
    pub total_vectors: i32,
    pub scanned: i32,
    pub skipped_vectors: i32,
    pub returned: i32,
    pub rings_touched: i32,
    pub payload_bytes: i32,
    pub estimated_tokens: i32,
    pub fanout_nodes: i32,
    pub candidate_reduction: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RetrieveResult {
    pub hits: Vec<Hit>,
    pub stats: RetrieveStats,
}

impl RetrieveResult {
    pub fn is_empty(&self) -> bool {
        self.hits.is_empty()
    }

    pub fn len(&self) -> usize {
        self.hits.len()
    }

    pub fn first(&self) -> Option<&Hit> {
        self.hits.first()
    }

    pub fn payloads(&self) -> impl Iterator<Item = &[u8]> {
        self.hits.iter().map(|hit| hit.payload.as_slice())
    }

    pub fn payload_strings(&self) -> Result<Vec<&str>, Error> {
        self.hits.iter().map(Hit::payload_utf8).collect()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectOptions {
    pub peers: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub auth_token: Option<String>,
    pub secret_key: Option<String>,
    pub galaxy: Option<String>,
    pub tls: bool,
    pub tls_ca_file: Option<String>,
    pub tls_server_name: Option<String>,
    pub tls_insecure_skip_verify: bool,
}

impl ConnectOptions {
    pub fn new(peers: impl Into<String>) -> Self {
        Self {
            peers: peers.into(),
            ..Self::default()
        }
    }

    pub fn username(mut self, value: impl Into<String>) -> Self {
        self.username = Some(value.into());
        self
    }

    pub fn password(mut self, value: impl Into<String>) -> Self {
        self.password = Some(value.into());
        self
    }

    pub fn auth_token(mut self, value: impl Into<String>) -> Self {
        self.auth_token = Some(value.into());
        self
    }

    pub fn secret_key(mut self, value: impl Into<String>) -> Self {
        self.secret_key = Some(value.into());
        self
    }

    pub fn galaxy(mut self, value: impl Into<String>) -> Self {
        self.galaxy = Some(value.into());
        self
    }

    /// Enable TLS. Requires a KoutenDB core built with `-d:ssl`.
    pub fn tls(mut self) -> Self {
        self.tls = true;
        self
    }

    /// Verify the server against a CA or self-signed certificate PEM, and
    /// enable TLS. Certificate verification stays on, so this is the right way
    /// to reach a server with a private CA or self-signed certificate.
    pub fn tls_ca_file(mut self, value: impl Into<String>) -> Self {
        self.tls_ca_file = Some(value.into());
        self.tls = true;
        self
    }

    /// Override the hostname used for verification and SNI.
    pub fn tls_server_name(mut self, value: impl Into<String>) -> Self {
        self.tls_server_name = Some(value.into());
        self.tls = true;
        self
    }

    /// Disable certificate verification entirely, and enable TLS.
    ///
    /// This accepts any certificate, which makes the connection trivially
    /// impersonable — encrypted but unauthenticated. Intended only for local
    /// smoke tests; never enable it against a production server. To reach a
    /// server with a self-signed certificate while keeping verification on,
    /// use [`ConnectOptions::tls_ca_file`] instead.
    pub fn danger_accept_invalid_certs(mut self) -> Self {
        self.tls_insecure_skip_verify = true;
        self.tls = true;
        self
    }

    pub fn connect(self) -> Result<KoutenDb, Error> {
        KoutenDb::connect_options(&self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetrieveOptions {
    pub ring: Option<String>,
    pub budget: i32,
    pub top_rings: i32,
    pub focus: i32,
}

impl Default for RetrieveOptions {
    fn default() -> Self {
        Self {
            ring: None,
            budget: 8,
            top_rings: 0,
            focus: 0,
        }
    }
}

impl RetrieveOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn ring(mut self, value: impl Into<String>) -> Self {
        self.ring = Some(value.into());
        self
    }

    pub fn budget(mut self, value: i32) -> Self {
        self.budget = value;
        self
    }

    pub fn top_rings(mut self, value: i32) -> Self {
        self.top_rings = value;
        self
    }

    pub fn focus(mut self, value: i32) -> Self {
        self.focus = value;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadRingOptions {
    pub filter_json: Option<String>,
    pub selection: Option<String>,
    pub limit: i32,
    pub cursor: Option<String>,
    pub pagination: bool,
    pub page: i32,
    pub page_limit: i32,
    pub sort_field: Option<String>,
    pub sort_desc: bool,
}

impl Default for ReadRingOptions {
    fn default() -> Self {
        Self {
            filter_json: None,
            selection: None,
            limit: 100,
            cursor: None,
            pagination: false,
            page: 1,
            page_limit: 20,
            sort_field: None,
            sort_desc: true,
        }
    }
}

impl ReadRingOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn filter_json(mut self, value: impl Into<String>) -> Self {
        self.filter_json = Some(value.into());
        self
    }

    pub fn selection(mut self, value: impl Into<String>) -> Self {
        self.selection = Some(value.into());
        self
    }

    pub fn limit(mut self, value: i32) -> Self {
        self.limit = value;
        self
    }

    pub fn cursor(mut self, value: impl Into<String>) -> Self {
        self.cursor = Some(value.into());
        self
    }

    pub fn pagination(mut self, value: bool) -> Self {
        self.pagination = value;
        self
    }

    pub fn page(mut self, value: i32) -> Self {
        self.page = value;
        self
    }

    pub fn page_limit(mut self, value: i32) -> Self {
        self.page_limit = value;
        self
    }

    pub fn sort(mut self, field: impl Into<String>) -> Self {
        self.sort_field = Some(field.into());
        self.sort_desc = false;
        self
    }

    pub fn rsort(mut self, field: impl Into<String>) -> Self {
        self.sort_field = Some(field.into());
        self.sort_desc = true;
        self
    }
}

pub struct KoutenDb {
    raw: *mut c_void,
}

unsafe impl Send for KoutenDb {}

impl KoutenDb {
    pub fn open_default() -> Result<Self, Error> {
        Self::open(8)
    }

    pub fn open(nodes: i32) -> Result<Self, Error> {
        init()?;
        let raw = unsafe { kouten_open(nodes as c_int) };
        Self::from_raw(raw)
    }

    pub fn open_dir(nodes: i32, dir: &str) -> Result<Self, Error> {
        init()?;
        let dir = CString::new(dir)?;
        let raw = unsafe { kouten_open_dir(nodes as c_int, dir.as_ptr()) };
        Self::from_raw(raw)
    }

    pub fn open_dir_with(dir: &str, options: OpenDirOptions) -> Result<Self, Error> {
        init()?;
        let dir = CString::new(dir)?;
        let raw = unsafe {
            kouten_open_dir_options(
                options.nodes as c_int,
                dir.as_ptr(),
                c_int::from(options.strong_durability),
                c_int::from(options.disk_backed),
            )
        };
        Self::from_raw(raw)
    }

    pub fn connect(peers: &str) -> Result<Self, Error> {
        init()?;
        let peers = CString::new(peers)?;
        let raw = unsafe { kouten_connect(peers.as_ptr()) };
        Self::from_raw(raw)
    }

    pub fn connect_options(options: &ConnectOptions) -> Result<Self, Error> {
        if !options.tls {
            return Self::connect_auth(
                &options.peers,
                options.username.as_deref(),
                options.password.as_deref(),
                options.auth_token.as_deref(),
                options.secret_key.as_deref(),
                options.galaxy.as_deref(),
            );
        }
        Self::connect_auth_tls(
            &options.peers,
            options.username.as_deref(),
            options.password.as_deref(),
            options.auth_token.as_deref(),
            options.secret_key.as_deref(),
            options.galaxy.as_deref(),
            options.tls,
            options.tls_ca_file.as_deref(),
            options.tls_server_name.as_deref(),
            options.tls_insecure_skip_verify,
        )
    }

    pub fn connect_auth(
        peers: &str,
        username: Option<&str>,
        password: Option<&str>,
        auth_token: Option<&str>,
        secret_key: Option<&str>,
        galaxy: Option<&str>,
    ) -> Result<Self, Error> {
        init()?;
        let peers = CString::new(peers)?;
        let username = opt_cstring(username)?;
        let password = opt_cstring(password)?;
        let auth_token = opt_cstring(auth_token)?;
        let secret_key = opt_cstring(secret_key)?;
        let galaxy = opt_cstring(galaxy)?;
        let raw = unsafe {
            kouten_connect_auth(
                peers.as_ptr(),
                opt_ptr(&username),
                opt_ptr(&password),
                opt_ptr(&auth_token),
                opt_ptr(&secret_key),
                opt_ptr(&galaxy),
            )
        };
        Self::from_raw(raw)
    }

    /// Authenticated cluster connection with TLS. Enabling `tls` requires a
    /// KoutenDB core built with `-d:ssl`.
    ///
    /// Prefer [`ConnectOptions`] unless you need to mirror the C ABI directly.
    /// Setting `tls_insecure_skip_verify` disables certificate verification and
    /// is intended only for local smoke tests; pass `tls_ca_file` instead to
    /// verify against a private CA or self-signed certificate.
    #[allow(clippy::too_many_arguments)]
    pub fn connect_auth_tls(
        peers: &str,
        username: Option<&str>,
        password: Option<&str>,
        auth_token: Option<&str>,
        secret_key: Option<&str>,
        galaxy: Option<&str>,
        tls: bool,
        tls_ca_file: Option<&str>,
        tls_server_name: Option<&str>,
        tls_insecure_skip_verify: bool,
    ) -> Result<Self, Error> {
        init()?;
        let peers = CString::new(peers)?;
        let username = opt_cstring(username)?;
        let password = opt_cstring(password)?;
        let auth_token = opt_cstring(auth_token)?;
        let secret_key = opt_cstring(secret_key)?;
        let galaxy = opt_cstring(galaxy)?;
        let tls_ca_file = opt_cstring(tls_ca_file)?;
        let tls_server_name = opt_cstring(tls_server_name)?;
        let raw = unsafe {
            kouten_connect_auth_tls(
                peers.as_ptr(),
                opt_ptr(&username),
                opt_ptr(&password),
                opt_ptr(&auth_token),
                opt_ptr(&secret_key),
                opt_ptr(&galaxy),
                c_int::from(tls),
                opt_ptr(&tls_ca_file),
                opt_ptr(&tls_server_name),
                c_int::from(tls_insecure_skip_verify),
            )
        };
        Self::from_raw(raw)
    }

    fn from_raw(raw: *mut c_void) -> Result<Self, Error> {
        if raw.is_null() {
            Err(Error::last())
        } else {
            Ok(Self { raw })
        }
    }

    pub fn now(&self) -> f64 {
        unsafe { kouten_now(self.raw) }
    }

    pub fn advance(&self, dt: f64) {
        unsafe { kouten_advance(self.raw, dt) };
    }

    pub fn configure_ring(&self, ring: &str, period: f64) -> Result<(), Error> {
        let ring = CString::new(ring)?;
        self.check(unsafe { kouten_ring_configure(self.raw, ring.as_ptr(), period) })
    }

    pub fn set_galaxy_description(&self, description: &str) -> Result<(), Error> {
        let description = CString::new(description)?;
        self.check(unsafe { kouten_set_galaxy_description(self.raw, description.as_ptr()) })
    }

    pub fn set_ring_description(&self, ring: &str, description: &str) -> Result<(), Error> {
        let ring = CString::new(ring)?;
        let description = CString::new(description)?;
        self.check(unsafe {
            kouten_set_ring_description(self.raw, ring.as_ptr(), description.as_ptr())
        })
    }

    pub fn put(&self, ring: &str, payload: &[u8]) -> Result<KoutenId, Error> {
        let ring = CString::new(ring)?;
        let mut id = empty_id();
        let data = if payload.is_empty() {
            ptr::null()
        } else {
            payload.as_ptr() as *const c_void
        };
        self.check(unsafe { kouten_put(self.raw, ring.as_ptr(), data, payload.len(), &mut id) })?;
        Ok(id)
    }

    pub fn put_codec(
        &self,
        ring: &str,
        payload: &[u8],
        codec: PayloadCodec,
    ) -> Result<KoutenId, Error> {
        let ring = CString::new(ring)?;
        let mut id = empty_id();
        let data = if payload.is_empty() {
            ptr::null()
        } else {
            payload.as_ptr() as *const c_void
        };
        self.check(unsafe {
            kouten_put_codec(
                self.raw,
                ring.as_ptr(),
                data,
                payload.len(),
                codec.as_c(),
                &mut id,
            )
        })?;
        Ok(id)
    }

    pub fn put_str(&self, ring: &str, payload: &str) -> Result<KoutenId, Error> {
        self.put(ring, payload.as_bytes())
    }

    pub fn put_json(&self, ring: &str, payload: &str) -> Result<KoutenId, Error> {
        self.put_codec(ring, payload.as_bytes(), PayloadCodec::Json)
    }

    pub fn put_nif(&self, ring: &str, payload: &str) -> Result<KoutenId, Error> {
        self.put_codec(ring, payload.as_bytes(), PayloadCodec::Nif)
    }

    pub fn put_bif(&self, ring: &str, payload: &[u8]) -> Result<KoutenId, Error> {
        self.put_codec(ring, payload, PayloadCodec::Bif)
    }

    pub fn put_vec(&self, ring: &str, payload: &[u8], vec: &[f32]) -> Result<KoutenId, Error> {
        let ring = CString::new(ring)?;
        let mut id = empty_id();
        let data = if payload.is_empty() {
            ptr::null()
        } else {
            payload.as_ptr() as *const c_void
        };
        let vec_ptr = if vec.is_empty() {
            ptr::null()
        } else {
            vec.as_ptr()
        };
        self.check(unsafe {
            kouten_put_vec(
                self.raw,
                ring.as_ptr(),
                data,
                payload.len(),
                vec_ptr,
                vec.len(),
                &mut id,
            )
        })?;
        Ok(id)
    }

    pub fn put_vec_codec(
        &self,
        ring: &str,
        payload: &[u8],
        vec: &[f32],
        codec: PayloadCodec,
    ) -> Result<KoutenId, Error> {
        let ring = CString::new(ring)?;
        let mut id = empty_id();
        let data = if payload.is_empty() {
            ptr::null()
        } else {
            payload.as_ptr() as *const c_void
        };
        let vec_ptr = if vec.is_empty() {
            ptr::null()
        } else {
            vec.as_ptr()
        };
        self.check(unsafe {
            kouten_put_vec_codec(
                self.raw,
                ring.as_ptr(),
                data,
                payload.len(),
                codec.as_c(),
                vec_ptr,
                vec.len(),
                &mut id,
            )
        })?;
        Ok(id)
    }

    pub fn put_json_vec(&self, ring: &str, payload: &str, vec: &[f32]) -> Result<KoutenId, Error> {
        self.put_vec_codec(ring, payload.as_bytes(), vec, PayloadCodec::Json)
    }

    pub fn put_nif_vec(&self, ring: &str, payload: &str, vec: &[f32]) -> Result<KoutenId, Error> {
        self.put_vec_codec(ring, payload.as_bytes(), vec, PayloadCodec::Nif)
    }

    pub fn put_bif_vec(&self, ring: &str, payload: &[u8], vec: &[f32]) -> Result<KoutenId, Error> {
        self.put_vec_codec(ring, payload, vec, PayloadCodec::Bif)
    }

    pub fn get(&self, id: KoutenId) -> Result<Option<Vec<u8>>, Error> {
        let mut len = 0usize;
        let p = unsafe { kouten_get(self.raw, id, &mut len) };
        if p.is_null() {
            let err = Error::last();
            if err.message.contains("not found") || err.message.contains("key not found") {
                return Ok(None);
            }
            return Err(err);
        }
        Ok(Some(unsafe { take_buffer(p, len) }))
    }

    pub fn get_encoded(&self, id: KoutenId) -> Result<Option<EncodedPayload>, Error> {
        let mut len = 0usize;
        let mut codec = KOUTEN_CODEC_RAW;
        let p = unsafe { kouten_get_codec(self.raw, id, &mut len, &mut codec) };
        if p.is_null() {
            let err = Error::last();
            if err.message.contains("not found") || err.message.contains("key not found") {
                return Ok(None);
            }
            return Err(err);
        }
        Ok(Some(EncodedPayload {
            data: unsafe { take_buffer(p, len) },
            codec: PayloadCodec::from_c(codec)?,
        }))
    }

    pub fn get_string(&self, id: KoutenId) -> Result<Option<String>, Error> {
        self.get(id)?
            .map(String::from_utf8)
            .transpose()
            .map_err(|e| Error::new(ErrorKind::Utf8, e.to_string()))
    }

    pub fn exists(&self, id: KoutenId) -> Result<bool, Error> {
        match unsafe { kouten_exists(self.raw, id) } {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::last()),
        }
    }

    pub fn update(&self, id: KoutenId, payload: &[u8]) -> Result<(), Error> {
        self.check(unsafe {
            kouten_update(
                self.raw,
                id,
                payload.as_ptr() as *const c_void,
                payload.len(),
            )
        })
    }

    pub fn update_codec(
        &self,
        id: KoutenId,
        payload: &[u8],
        codec: PayloadCodec,
    ) -> Result<(), Error> {
        self.check(unsafe {
            kouten_update_codec(
                self.raw,
                id,
                payload.as_ptr() as *const c_void,
                payload.len(),
                codec.as_c(),
            )
        })
    }

    pub fn update_str(&self, id: KoutenId, payload: &str) -> Result<(), Error> {
        self.update(id, payload.as_bytes())
    }

    pub fn update_json(&self, id: KoutenId, json: &str) -> Result<(), Error> {
        self.update_codec(id, json.as_bytes(), PayloadCodec::Json)
    }

    pub fn remove(&self, id: KoutenId) -> Result<(), Error> {
        self.check(unsafe { kouten_remove(self.raw, id) })
    }

    pub fn batch_get(&self, ids: &[KoutenId]) -> Result<Vec<Vec<u8>>, Error> {
        let ptr = if ids.is_empty() {
            ptr::null()
        } else {
            ids.as_ptr()
        };
        let r = unsafe { kouten_batch_get(self.raw, ptr, ids.len()) };
        if r.is_null() {
            return Err(Error::last());
        }
        let result = unsafe {
            let values = slice::from_raw_parts((*r).values, (*r).len);
            let mut out = Vec::with_capacity(values.len());
            for value in values {
                let bytes = if value.data.is_null() {
                    Vec::new()
                } else {
                    slice::from_raw_parts(value.data as *const u8, value.len).to_vec()
                };
                out.push(bytes);
            }
            kouten_batch_get_free(r);
            out
        };
        Ok(result)
    }

    pub fn query(&self, id: KoutenId, selection: &str) -> Result<Vec<u8>, Error> {
        let selection = CString::new(selection)?;
        let mut len = 0usize;
        let p = unsafe { kouten_query(self.raw, id, selection.as_ptr(), &mut len) };
        if p.is_null() {
            return Err(Error::last());
        }
        Ok(unsafe { take_buffer(p, len) })
    }

    pub fn query_string(&self, id: KoutenId, selection: &str) -> Result<String, Error> {
        String::from_utf8(self.query(id, selection)?)
            .map_err(|e| Error::new(ErrorKind::Utf8, e.to_string()))
    }

    pub fn read_ring_json(&self, ring: &str, options: &ReadRingOptions) -> Result<String, Error> {
        let ring = CString::new(ring)?;
        let filter_json = opt_cstring(options.filter_json.as_deref())?;
        let selection = opt_cstring(options.selection.as_deref())?;
        let cursor = opt_cstring(options.cursor.as_deref())?;
        let sort_field = opt_cstring(options.sort_field.as_deref())?;
        let mut len = 0usize;
        let p = unsafe {
            kouten_read_ring_json(
                self.raw,
                ring.as_ptr(),
                opt_ptr(&filter_json),
                opt_ptr(&selection),
                options.limit as c_int,
                opt_ptr(&cursor),
                if options.pagination { 1 } else { 0 },
                options.page as c_int,
                options.page_limit as c_int,
                opt_ptr(&sort_field),
                if options.sort_desc { 1 } else { 0 },
                &mut len,
            )
        };
        if p.is_null() {
            return Err(Error::last());
        }
        String::from_utf8(unsafe { take_buffer(p, len) })
            .map_err(|e| Error::new(ErrorKind::Utf8, e.to_string()))
    }

    pub fn retrieve(
        &self,
        vec: &[f32],
        ring: Option<&str>,
        budget: i32,
        top_rings: i32,
        focus: i32,
    ) -> Result<RetrieveResult, Error> {
        let ring = opt_cstring(ring)?;
        let vec_ptr = if vec.is_empty() {
            ptr::null()
        } else {
            vec.as_ptr()
        };
        let r = unsafe {
            kouten_retrieve(
                self.raw,
                vec_ptr,
                vec.len(),
                opt_ptr(&ring),
                budget,
                top_rings,
                focus,
            )
        };
        if r.is_null() {
            return Err(Error::last());
        }
        let result = unsafe {
            let raw = &*r;
            let raw_hits = slice::from_raw_parts(raw.hits, raw.len);
            let hits = raw_hits
                .iter()
                .map(|h| Hit {
                    id: h.id,
                    score: h.score,
                    payload: if h.payload.is_null() {
                        Vec::new()
                    } else {
                        slice::from_raw_parts(h.payload as *const u8, h.payload_len).to_vec()
                    },
                })
                .collect();
            let stats = RetrieveStats {
                total_vectors: raw.total_vectors,
                scanned: raw.scanned,
                skipped_vectors: raw.skipped_vectors,
                returned: raw.returned,
                rings_touched: raw.rings_touched,
                payload_bytes: raw.payload_bytes,
                estimated_tokens: raw.estimated_tokens,
                fanout_nodes: raw.fanout_nodes,
                candidate_reduction: raw.candidate_reduction,
            };
            kouten_retrieve_free(r);
            RetrieveResult { hits, stats }
        };
        Ok(result)
    }

    pub fn retrieve_with(
        &self,
        vec: &[f32],
        options: RetrieveOptions,
    ) -> Result<RetrieveResult, Error> {
        self.retrieve(
            vec,
            options.ring.as_deref(),
            options.budget,
            options.top_rings,
            options.focus,
        )
    }

    pub fn atlas(
        &self,
        query_vec: Option<&[f32]>,
        max_centroid_dims: i32,
    ) -> Result<String, Error> {
        let vec = query_vec.unwrap_or(&[]);
        let vec_ptr = if vec.is_empty() {
            ptr::null()
        } else {
            vec.as_ptr()
        };
        let mut len = 0usize;
        let p = unsafe { kouten_atlas(self.raw, vec_ptr, vec.len(), max_centroid_dims, &mut len) };
        if p.is_null() {
            return Err(Error::last());
        }
        let bytes = unsafe { take_buffer(p, len) };
        String::from_utf8(bytes).map_err(|e| Error::new(ErrorKind::Utf8, e.to_string()))
    }

    pub fn metrics(&self, format: MetricsFormat) -> Result<String, Error> {
        owned_text(|len| unsafe { kouten_metrics_text(self.raw, format as c_int, len) })
    }

    pub fn segment_status(
        &self,
        stale_ratio: f64,
        min_stale_records: i32,
    ) -> Result<String, Error> {
        owned_text(|len| unsafe {
            kouten_segment_status_json(self.raw, stale_ratio, min_stale_records, len)
        })
    }

    pub fn plan_segment_maintenance(
        &self,
        policy: SegmentMaintenancePolicy,
    ) -> Result<String, Error> {
        owned_text(|len| unsafe {
            kouten_segment_maintenance_plan_json(
                self.raw,
                policy.stale_ratio,
                policy.min_stale_records,
                policy.max_rings,
                policy.max_bytes,
                policy.max_elapsed_ms,
                len,
            )
        })
    }

    pub fn run_segment_maintenance(
        &self,
        policy: SegmentMaintenancePolicy,
    ) -> Result<String, Error> {
        owned_text(|len| unsafe {
            kouten_segment_maintenance_run_json(
                self.raw,
                policy.stale_ratio,
                policy.min_stale_records,
                policy.max_rings,
                policy.max_bytes,
                policy.max_elapsed_ms,
                len,
            )
        })
    }

    pub fn segment_maintenance_status(&self) -> Result<String, Error> {
        owned_text(|len| unsafe { kouten_segment_maintenance_status_json(self.raw, len) })
    }

    pub fn recover_segment_maintenance(&self) -> Result<bool, Error> {
        let mut recovered = 0;
        self.check(unsafe { kouten_segment_maintenance_recover(self.raw, &mut recovered) })?;
        Ok(recovered != 0)
    }

    pub fn create_checkpoint(
        &self,
        root: Option<&str>,
        checkpoint_id: Option<&str>,
    ) -> Result<String, Error> {
        let root = opt_cstring(root)?;
        let checkpoint_id = opt_cstring(checkpoint_id)?;
        owned_text(|len| unsafe {
            kouten_checkpoint_create_json(self.raw, opt_ptr(&root), opt_ptr(&checkpoint_id), len)
        })
    }

    pub fn checkpoint_status(checkpoint_dir: &str) -> Result<String, Error> {
        init()?;
        let checkpoint_dir = CString::new(checkpoint_dir)?;
        owned_text(|len| unsafe { kouten_checkpoint_status_json(checkpoint_dir.as_ptr(), len) })
    }

    pub fn list_checkpoints(root: &str) -> Result<String, Error> {
        init()?;
        let root = CString::new(root)?;
        owned_text(|len| unsafe { kouten_checkpoint_list_json(root.as_ptr(), len) })
    }

    pub fn cleanup_checkpoints(root: &str, keep: i32) -> Result<String, Error> {
        init()?;
        let root = CString::new(root)?;
        owned_text(|len| unsafe { kouten_checkpoint_cleanup_json(root.as_ptr(), keep, len) })
    }

    pub fn restore_checkpoint(
        checkpoint_dir: &str,
        data_dir: &str,
        overwrite: bool,
    ) -> Result<String, Error> {
        init()?;
        let checkpoint_dir = CString::new(checkpoint_dir)?;
        let data_dir = CString::new(data_dir)?;
        owned_text(|len| unsafe {
            kouten_checkpoint_restore_json(
                checkpoint_dir.as_ptr(),
                data_dir.as_ptr(),
                c_int::from(overwrite),
                len,
            )
        })
    }

    pub fn checkpoint_metrics(root: &str, format: MetricsFormat) -> Result<String, Error> {
        init()?;
        let root = CString::new(root)?;
        owned_text(|len| unsafe {
            kouten_checkpoint_metrics_text(root.as_ptr(), format as c_int, len)
        })
    }

    pub fn locate(&self, id: KoutenId, at: Option<f64>) -> Result<i32, Error> {
        let node = unsafe { kouten_locate(self.raw, id, at.unwrap_or(-1.0)) };
        if node < 0 {
            Err(Error::last())
        } else {
            Ok(node)
        }
    }

    pub fn next_visit(&self, id: KoutenId, node: i32) -> Result<f64, Error> {
        let t = unsafe { kouten_next_visit(self.raw, id, node) };
        if t < 0.0 {
            Err(Error::last())
        } else {
            Ok(t)
        }
    }

    pub fn next_join(&self, a: KoutenId, b: KoutenId) -> Result<Option<f64>, Error> {
        let t = unsafe { kouten_next_join(self.raw, a, b) };
        if t < 0.0 {
            Ok(None)
        } else {
            Ok(Some(t))
        }
    }

    fn check(&self, rc: c_int) -> Result<(), Error> {
        if rc == KOUTEN_OK {
            Ok(())
        } else {
            Err(Error::last())
        }
    }
}

impl Drop for KoutenDb {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe { kouten_close(self.raw) };
            self.raw = ptr::null_mut();
        }
    }
}

fn init() -> Result<(), Error> {
    INIT.call_once(|| unsafe { kouten_init() });
    let version = unsafe { kouten_abi_version() };
    if version != KOUTEN_ABI_VERSION {
        Err(Error::new(
            ErrorKind::AbiVersionMismatch,
            format!(
                "KoutenDB ABI version mismatch: expected {}, got {}",
                KOUTEN_ABI_VERSION, version
            ),
        ))
    } else {
        Ok(())
    }
}

fn classify_abi_error(message: &str) -> ErrorKind {
    let lower = message.to_ascii_lowercase();
    if lower.contains("not found") || lower.contains("key not found") {
        ErrorKind::NotFound
    } else {
        ErrorKind::Abi
    }
}

fn parse_id_part<T>(parts: &mut std::str::Split<'_, char>, name: &str) -> Result<T, Error>
where
    T: FromStr,
    T::Err: fmt::Display,
{
    let raw = parts.next().ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidId,
            format!("invalid KoutenDB id: missing {}", name),
        )
    })?;
    raw.parse::<T>().map_err(|e| {
        Error::new(
            ErrorKind::InvalidId,
            format!("invalid KoutenDB id field '{}': {}", name, e),
        )
    })
}

fn empty_id() -> KoutenId {
    KoutenId {
        parent: 0,
        epoch: 0,
        seq: 0,
        t_write: 0.0,
    }
}

fn opt_cstring(value: Option<&str>) -> Result<Option<CString>, Error> {
    value.map(CString::new).transpose().map_err(Error::from)
}

fn opt_ptr(value: &Option<CString>) -> *const c_char {
    value.as_ref().map_or(ptr::null(), |s| s.as_ptr())
}

unsafe fn take_buffer(p: *mut c_void, len: usize) -> Vec<u8> {
    let bytes = slice::from_raw_parts(p as *const u8, len).to_vec();
    kouten_free(p);
    bytes
}

fn owned_text(call: impl FnOnce(*mut usize) -> *mut c_void) -> Result<String, Error> {
    let mut len = 0usize;
    let p = call(&mut len);
    if p.is_null() {
        return Err(Error::last());
    }
    let bytes = unsafe { take_buffer(p, len) };
    String::from_utf8(bytes).map_err(|e| Error::new(ErrorKind::Utf8, e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_roundtrip_retrieve_and_atlas() {
        let db = KoutenDb::open_default().unwrap();
        db.set_galaxy_description("Rust test galaxy").unwrap();
        db.set_ring_description("docs/rust", "Rust driver documents")
            .unwrap();
        db.configure_ring("docs/rust", 30.0).unwrap();

        let payload = br#"{"title":"hello rust","lang":"rust"}"#;
        let id = db
            .put_json_vec(
                "docs/rust",
                std::str::from_utf8(payload).unwrap(),
                &[1.0, 0.0],
            )
            .unwrap();
        assert!(!id.is_empty());
        assert!(id.to_string().contains(':'));
        assert_eq!(KoutenId::parse(&id.to_string()).unwrap(), id);
        assert_eq!(db.get(id).unwrap().unwrap(), payload);
        let encoded = db.get_encoded(id).unwrap().unwrap();
        assert_eq!(encoded.codec, PayloadCodec::Json);
        assert_eq!(encoded.data, payload);
        assert_eq!(
            encoded.as_utf8().unwrap(),
            r#"{"title":"hello rust","lang":"rust"}"#
        );
        assert_eq!(
            db.get_string(id).unwrap().unwrap(),
            r#"{"title":"hello rust","lang":"rust"}"#
        );

        let values = db.batch_get(&[id]).unwrap();
        assert_eq!(values, vec![payload.to_vec()]);

        let selected = db.query_string(id, "{ title }").unwrap();
        assert!(selected.contains("hello rust"));

        let page = db
            .read_ring_json(
                "docs/rust",
                &ReadRingOptions::new()
                    .filter_json(r#"{"lang":"rust"}"#)
                    .selection("{ title }")
                    .limit(1)
                    .rsort("time"),
            )
            .unwrap();
        assert!(page.contains(r#""items""#));
        assert!(page.contains(r#""count":1"#));
        assert!(page.contains("hello rust"));
        assert!(page.contains(r#""sort":"time""#));
        assert!(page.contains(r#""sortDirection":"desc""#));

        let bif_id = db
            .put_bif_vec("artifacts/bif", &[1, 2, 3, 4], &[0.0, 1.0])
            .unwrap();
        let bif_encoded = db.get_encoded(bif_id).unwrap().unwrap();
        assert_eq!(bif_encoded.codec, PayloadCodec::Bif);
        assert_eq!(bif_encoded.data, vec![1, 2, 3, 4]);
        let bif_page = db
            .read_ring_json("artifacts/bif", &ReadRingOptions::new().limit(1))
            .unwrap();
        assert!(bif_page.contains(r#""codec":"bif""#));
        assert!(bif_page.contains(r#""encoding":"base64""#));

        let rr = db
            .retrieve_with(
                &[1.0, 0.0],
                RetrieveOptions::new().ring("docs/rust").budget(4),
            )
            .unwrap();
        assert_eq!(rr.hits.len(), 1);
        assert!(!rr.is_empty());
        assert!(rr.first().is_some());
        assert_eq!(rr.stats.scanned, 1);
        assert_eq!(rr.payloads().collect::<Vec<_>>(), vec![payload.as_slice()]);
        assert_eq!(
            rr.payload_strings().unwrap(),
            vec![r#"{"title":"hello rust","lang":"rust"}"#]
        );
        assert_eq!(
            rr.hits[0].payload_utf8().unwrap(),
            r#"{"title":"hello rust","lang":"rust"}"#
        );

        let atlas = db.atlas(Some(&[1.0, 0.0]), 8).unwrap();
        assert!(atlas.contains("Rust test galaxy"));
        assert!(atlas.contains("Rust driver documents"));

        let node = db.locate(id, None).unwrap();
        assert!(node >= 0);
        assert!(db.next_visit(id, node).unwrap() >= 0.0);

        let now = db.now();
        db.advance(2.5);
        assert!(db.now() >= now + 2.5);
    }

    #[test]
    fn errors_include_c_abi_message() {
        let db = KoutenDb::open(8).unwrap();
        let err = db.put("bad\0ring", b"x").unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NulByte);
        assert!(err.to_string().contains("nul byte"));
    }

    #[test]
    fn tls_builders_imply_tls_and_keep_verification_separate() {
        let plain = ConnectOptions::new("127.0.0.1:7000");
        assert!(!plain.tls);
        assert!(!plain.tls_insecure_skip_verify);

        let ca = ConnectOptions::new("127.0.0.1:7000").tls_ca_file("/etc/kouten/ca.pem");
        assert!(ca.tls);
        assert_eq!(ca.tls_ca_file.as_deref(), Some("/etc/kouten/ca.pem"));
        assert!(!ca.tls_insecure_skip_verify);

        let named = ConnectOptions::new("127.0.0.1:7000").tls_server_name("kouten.internal");
        assert!(named.tls);
        assert!(!named.tls_insecure_skip_verify);

        let insecure = ConnectOptions::new("127.0.0.1:7000").danger_accept_invalid_certs();
        assert!(insecure.tls);
        assert!(insecure.tls_insecure_skip_verify);
    }

    // Current core connections fail eagerly when the peer or TLS setup is
    // unavailable, rather than returning a handle that fails on first use.
    #[test]
    fn tls_connect_fails_eagerly() {
        let result = ConnectOptions::new("127.0.0.1:1")
            .tls_ca_file("/nonexistent/ca.pem")
            .connect();
        let err = match result {
            Ok(_) => panic!("connect unexpectedly succeeded"),
            Err(err) => err,
        };
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn id_parse_reports_invalid_input() {
        let parsed = KoutenId::parse("1:2:3:4.5").unwrap();
        assert_eq!(parsed, KoutenId::new(1, 2, 3, 4.5));
        assert_eq!(parsed.to_string(), "1:2:3:4.5");
        assert_eq!("1:2:3:4.5".parse::<KoutenId>().unwrap(), parsed);

        let err = KoutenId::parse("1:2:3").unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidId);
        assert!(err.message().contains("missing"));

        let err = KoutenId::parse("1:2:3:4:5").unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidId);
        assert!(err.message().contains("too many"));
    }

    #[test]
    fn open_dir_reopens_persisted_data() {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "koutendb-rust-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let id = {
            let db = KoutenDb::open_dir(4, dir.to_str().unwrap()).unwrap();
            db.put_str("persist/rust", "persistent rust payload")
                .unwrap()
        };

        let db = KoutenDb::open_dir(4, dir.to_str().unwrap()).unwrap();
        assert_eq!(
            db.get_string(id).unwrap().unwrap(),
            "persistent rust payload"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn v012_crud_maintenance_and_checkpoint_surface() {
        let nonce = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let root = std::env::temp_dir().join(format!("koutendb-rust-v012-{nonce}"));
        let checkpoints = std::env::temp_dir().join(format!("koutendb-rust-cp-{nonce}"));
        let restored = std::env::temp_dir().join(format!("koutendb-rust-restore-{nonce}"));
        std::fs::create_dir_all(&root).unwrap();

        let db = OpenDirOptions::new()
            .nodes(1)
            .strong_durability(true)
            .disk_backed(true)
            .open(root.to_str().unwrap())
            .unwrap();
        let id = db.put_str("docs/mutable", "before").unwrap();
        assert!(db.exists(id).unwrap());
        db.update_json(id, r#"{"state":"after"}"#).unwrap();
        assert_eq!(
            db.get_encoded(id).unwrap().unwrap().codec,
            PayloadCodec::Json
        );
        assert!(db
            .metrics(MetricsFormat::Prometheus)
            .unwrap()
            .contains("koutendb_items"));

        let policy = SegmentMaintenancePolicy::new()
            .stale_threshold(0.0, 0)
            .max_rings(1)
            .max_bytes(1_048_576)
            .max_elapsed_ms(1_000);
        assert!(db
            .plan_segment_maintenance(policy)
            .unwrap()
            .contains("decisions"));
        assert!(db
            .run_segment_maintenance(policy)
            .unwrap()
            .contains("decisions"));
        assert!(db.segment_status(0.0, 0).unwrap().contains("rings"));
        assert!(!db.recover_segment_maintenance().unwrap());

        let created = db
            .create_checkpoint(Some(checkpoints.to_str().unwrap()), Some("rust-1"))
            .unwrap();
        assert!(created.contains(r#""verified":true"#));
        let checkpoint_dir = checkpoints.join("rust-1");
        assert!(
            KoutenDb::checkpoint_status(checkpoint_dir.to_str().unwrap())
                .unwrap()
                .contains(r#""reason":"verified""#)
        );
        assert!(KoutenDb::list_checkpoints(checkpoints.to_str().unwrap())
            .unwrap()
            .contains(r#""count":1"#));
        assert!(KoutenDb::checkpoint_metrics(
            checkpoints.to_str().unwrap(),
            MetricsFormat::OpenMetrics,
        )
        .unwrap()
        .contains("# EOF"));
        drop(db);

        KoutenDb::restore_checkpoint(
            checkpoint_dir.to_str().unwrap(),
            restored.to_str().unwrap(),
            false,
        )
        .unwrap();
        let restored_db = OpenDirOptions::new()
            .nodes(1)
            .strong_durability(true)
            .disk_backed(true)
            .open(restored.to_str().unwrap())
            .unwrap();
        assert!(restored_db.exists(id).unwrap());
        restored_db.remove(id).unwrap();
        assert!(!restored_db.exists(id).unwrap());
        drop(restored_db);

        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(checkpoints).unwrap();
        std::fs::remove_dir_all(restored).unwrap();
    }
}
