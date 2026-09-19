use super::connection::{derive, encrypt, Connection, Stream};
use super::*;
use native_tls::{Certificate, Protocol, TlsConnector};
use std::{
    collections::HashMap,
    net::{TcpStream, ToSocketAddrs},
};
use zeroize::Zeroizing;

pub struct TcpClient {
    peers: Vec<String>,
    options: TcpOptions,
    connections: HashMap<usize, Connection>,
    closed: bool,
}
impl fmt::Debug for TcpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpClient")
            .field("closed", &self.closed)
            .finish()
    }
}
impl TcpClient {
    pub fn connect(peers: Vec<String>, mut options: TcpOptions) -> Result<Self> {
        if peers.is_empty()
            || peers.len() > 64
            || options.max_frame_bytes == 0
            || options.max_frame_bytes > MAX_FRAME
            || options.max_redirects > 32
        {
            return Err(input());
        }
        for t in [
            options.connect_timeout,
            options.read_timeout,
            options.write_timeout,
        ] {
            if t.is_zero() || t > Duration::from_secs(3600) {
                return Err(input());
            }
        }
        for p in &peers {
            let (host, port) = p.rsplit_once(':').ok_or_else(input)?;
            if host.is_empty()
                || host.contains(['/', '\\', ' ', '\n', '\r', '\0'])
                || port.parse::<u16>().ok().filter(|n| *n > 0).is_none()
            {
                return Err(input());
            }
        }
        let c = &mut options.credentials;
        if c.username.is_empty() && !c.auth_token.is_empty() {
            c.username = "token".into();
            c.password = c.auth_token.clone();
        }
        for field in [&c.username, &c.password, &options.galaxy] {
            if field.len() > 1024 || field.bytes().any(|b| b <= 32 || b == 127) {
                return Err(input());
            }
        }
        if c.username.is_empty() && (!c.password.is_empty() || !c.secret_key.is_empty()) {
            return Err(input());
        }
        let mut client = Self {
            peers,
            options,
            connections: HashMap::new(),
            closed: false,
        };
        client.ensure(0)?;
        Ok(client)
    }
    pub fn close(&mut self) {
        self.connections.clear();
        self.closed = true;
    }
    fn ensure(&mut self, node: usize) -> Result<()> {
        if self.closed {
            return Err(Error::new(ErrorKind::Connection, "TCP client is closed"));
        }
        if node >= self.peers.len() {
            return Err(protocol());
        }
        if self.connections.contains_key(&node) {
            return Ok(());
        }
        let o = &self.options;
        // DNS uses the system resolver. Returned addresses share a connect budget.
        let addresses = self.peers[node].to_socket_addrs().map_err(io_error)?;
        let deadline = Instant::now() + o.connect_timeout;
        let mut stream = None;
        let mut error = Error::new(ErrorKind::Connection, "No usable TCP address");
        for addr in addresses {
            match TcpStream::connect_timeout(&addr, left(deadline)?) {
                Ok(s) => {
                    stream = Some(s);
                    break;
                }
                Err(e) => error = io_error(e),
            }
        }
        let s = stream.ok_or(error)?;
        s.set_nodelay(true).map_err(io_error)?;
        s.set_read_timeout(Some(left(deadline)?))
            .map_err(io_error)?;
        s.set_write_timeout(Some(left(deadline)?))
            .map_err(io_error)?;
        let s = if let Some(tls) = &o.tls {
            let fail = || Error::new(ErrorKind::Connection, "Unable to establish or verify TLS");
            let mut builder = TlsConnector::builder();
            builder.min_protocol_version(Some(Protocol::Tlsv12));
            builder
                .danger_accept_invalid_certs(tls.insecure_skip_verify)
                .danger_accept_invalid_hostnames(tls.insecure_skip_verify);
            if let Some(path) = &tls.ca_file {
                builder.add_root_certificate(
                    Certificate::from_pem(&std::fs::read(path).map_err(|_| fail())?)
                        .map_err(|_| fail())?,
                );
            }
            let host = self.peers[node]
                .rsplit_once(':')
                .ok_or_else(input)?
                .0
                .trim_matches(['[', ']']);
            Stream::Tls(
                builder
                    .build()
                    .map_err(|_| fail())?
                    .connect(tls.server_name.as_deref().unwrap_or(host), s)
                    .map_err(|_| fail())?,
            )
        } else {
            Stream::Plain(s)
        };
        let mut conn = Connection::new(s, o);
        let c = &o.credentials;
        let exchange = |conn: &mut Connection, h: &str| -> Result<Vec<String>> {
            conn.send(h, &[], o, &mut false)?;
            conn.header(o.max_frame_bytes)
        };
        if !c.username.is_empty() {
            if c.secret_key.is_empty() {
                expect(
                    &exchange(&mut conn, &format!("AUTH {} {}", c.username, c.password))?,
                    "OK",
                    2,
                    true,
                )?;
            } else {
                let chal = exchange(&mut conn, &format!("AUTHCHAL {}", c.username))?;
                expect(&chal, "CHAL", 2, true)?;
                if chal[1].len() != 64 || !chal[1].bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(protocol());
                }
                let key = derive(&[b"koutendb-auth-v1\0box\0", c.secret_key.as_bytes()]);
                let msg = Zeroizing::new(format!(
                    "koutendb-auth-v1\n{}\n{}\n{}",
                    c.username, c.password, chal[1]
                ));
                let cipher = encrypt(&key, msg.as_bytes())?;
                let hex: String = cipher.iter().map(|b| format!("{b:02x}")).collect();
                expect(
                    &exchange(&mut conn, &format!("AUTHRESP {hex}"))?,
                    "OK",
                    2,
                    true,
                )?;
                conn.key = Some(derive(&[
                    b"koutendb-auth-v1\0transport\0",
                    chal[1].as_bytes(),
                    b"\0",
                    c.secret_key.as_bytes(),
                ]));
            }
        }
        if !o.galaxy.is_empty() {
            expect(
                &exchange(&mut conn, &format!("HELLO {}", o.galaxy))?,
                "OK",
                2,
                true,
            )?;
        }
        let v = exchange(&mut conn, "WIREVER")?;
        expect(&v, "WIREVER", 2, true)?;
        if v[1] != "1" {
            return Err(Error::new(
                ErrorKind::VersionMismatch,
                "Unsupported KoutenDB wire version",
            ));
        }
        let ack = exchange(&mut conn, "CODECMETA ON")?;
        expect(&ack, "OK", 2, false)?;
        if ack[1] != "codec-metadata" {
            return Err(protocol());
        }
        self.connections.insert(node, conn);
        Ok(())
    }
    pub fn put(&mut self, ring: &str, payload: &[u8]) -> Result<TcpId> {
        self.put_codec(ring, payload, Codec::Raw)
    }
    pub fn put_json(&mut self, ring: &str, value: &serde_json::Value) -> Result<TcpId> {
        self.put_codec(
            ring,
            &serde_json::to_vec(value).map_err(|_| input())?,
            Codec::Json,
        )
    }
    pub fn put_codec(&mut self, ring: &str, payload: &[u8], codec: Codec) -> Result<TcpId> {
        if ring.is_empty()
            || ring
                .len()
                .checked_add(payload.len())
                .filter(|n| *n <= self.options.max_frame_bytes)
                .is_none()
        {
            return Err(input());
        }
        let mut attempted = false;
        let result = (|| {
            self.ensure(0)?;
            let c = self.connections.get_mut(&0).ok_or_else(protocol)?;
            let mut body = ring.as_bytes().to_vec();
            body.extend_from_slice(payload);
            c.send(
                &format!("PUTR {} {} 0 {}", ring.len(), payload.len(), codec.as_str()),
                &body,
                &self.options,
                &mut attempted,
            )?;
            let r = c.header(self.options.max_frame_bytes)?;
            expect(&r, "ID", 7, false)?;
            TcpId::fields(&r[1..].iter().map(String::as_str).collect::<Vec<_>>())
        })();
        match result {
            Err(e) => {
                self.connections.clear();
                if attempted
                    && matches!(
                        e.kind,
                        ErrorKind::Connection | ErrorKind::Timeout | ErrorKind::Protocol
                    )
                {
                    Err(Error::new(
                        ErrorKind::IndeterminateWrite,
                        "Write outcome unknown; do not automatically retry",
                    ))
                } else {
                    Err(e)
                }
            }
            ok => ok,
        }
    }
    fn retry<T>(&mut self, mut op: impl FnMut(&mut Self) -> Result<T>) -> Result<T> {
        for attempt in 0..2 {
            match op(self) {
                Ok(v) => return Ok(v),
                Err(e) => {
                    self.connections.clear();
                    if attempt == 1
                        || self.closed
                        || !self.options.retry_reads
                        || !matches!(e.kind, ErrorKind::Connection | ErrorKind::Timeout)
                    {
                        return Err(e);
                    }
                }
            }
        }
        unreachable!()
    }
    pub fn health(&mut self) -> Result<String> {
        self.retry(|s| {
            s.ensure(0)?;
            let c = s.connections.get_mut(&0).ok_or_else(protocol)?;
            c.send("HEALTH", &[], &s.options, &mut false)?;
            let r = c.header(s.options.max_frame_bytes)?;
            if r[0] == "ERR" {
                return Err(Error::new(ErrorKind::Server, "Health request rejected"));
            }
            if r.len() < 2 || r[0] != "OK" || !r[1].starts_with("node=") {
                return Err(protocol());
            }
            length(&r[1][5..], s.peers.len() - 1)?;
            Ok(r[1..].join(" "))
        })
    }
    fn read(&mut self, id: &TcpId, selection: Option<&str>) -> Result<Option<EncodedPayload>> {
        let original = id.wire()?;
        if selection.is_some_and(|s| s.len() > self.options.max_frame_bytes) {
            return Err(input());
        }
        self.retry(|s| {
            let mut fields = original.clone();
            let mut node = 0;
            for redirects in 0..=s.options.max_redirects {
                s.ensure(node)?;
                let c = s.connections.get_mut(&node).ok_or_else(protocol)?;
                let header = if let Some(q) = selection {
                    format!("QRYID {fields} {}", q.len())
                } else {
                    format!("GETID {fields}")
                };
                c.send(
                    &header,
                    selection.unwrap_or("").as_bytes(),
                    &s.options,
                    &mut false,
                )?;
                let r = c.header(s.options.max_frame_bytes)?;
                match r[0].as_str() {
                    "MISS" | "GONE" => {
                        expect(&r, &r[0], 1, false)?;
                        return Ok(None);
                    }
                    "FWD" => {
                        if redirects == s.options.max_redirects || ![7, 8].contains(&r.len()) {
                            return Err(protocol());
                        }
                        fields =
                            TcpId::fields(&r[1..7].iter().map(String::as_str).collect::<Vec<_>>())?
                                .wire()?;
                        if r.len() == 8 {
                            node = length(&r[7], s.peers.len() - 1)?;
                        }
                    }
                    _ => {
                        expect(&r, "VAL", 4, false)?;
                        length(&r[1], s.peers.len() - 1)?;
                        let n = length(&r[2], s.options.max_frame_bytes)?;
                        let codec = Codec::parse(&r[3])?;
                        return Ok(Some(EncodedPayload {
                            payload: c.bytes(n, s.options.max_frame_bytes)?,
                            codec,
                        }));
                    }
                }
            }
            Err(protocol())
        })
    }
    pub fn get_encoded(&mut self, id: &TcpId) -> Result<Option<EncodedPayload>> {
        self.read(id, None)
    }
    pub fn get(&mut self, id: &TcpId) -> Result<Option<Vec<u8>>> {
        Ok(self.get_encoded(id)?.map(|v| v.payload))
    }
    pub fn query(&mut self, id: &TcpId, selection: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.read(id, Some(selection))?.map(|v| v.payload))
    }
    pub fn get_json(&mut self, id: &TcpId) -> Result<Option<serde_json::Value>> {
        self.get(id)?
            .map(|b| serde_json::from_slice(&b).map_err(|_| protocol()))
            .transpose()
    }
    pub fn query_json(&mut self, id: &TcpId, selection: &str) -> Result<Option<serde_json::Value>> {
        self.query(id, selection)?
            .map(|b| serde_json::from_slice(&b).map_err(|_| protocol()))
            .transpose()
    }
}
