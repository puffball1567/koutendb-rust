use super::*;
use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use crypto_secretbox::{
    aead::{Aead, KeyInit},
    Nonce, XSalsa20Poly1305,
};
use native_tls::TlsStream;
use rand::{rngs::OsRng, RngCore};
use std::{
    io::{BufReader, Read, Write},
    net::TcpStream,
};
use zeroize::Zeroizing;

pub(super) enum Stream {
    Plain(TcpStream),
    Tls(TlsStream<TcpStream>),
}
impl Stream {
    fn socket(&self) -> &TcpStream {
        match self {
            Self::Plain(s) => s,
            Self::Tls(s) => s.get_ref(),
        }
    }
}
impl Read for Stream {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(s) => s.read(b),
            Self::Tls(s) => s.read(b),
        }
    }
}
impl Write for Stream {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(s) => s.write(b),
            Self::Tls(s) => s.write(b),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(s) => s.flush(),
            Self::Tls(s) => s.flush(),
        }
    }
}
pub(super) struct Connection {
    stream: BufReader<Stream>,
    pub key: Option<Zeroizing<[u8; 32]>>,
    plain: Vec<u8>,
    offset: usize,
    deadline: Instant,
}
pub(super) fn derive(parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let mut h = Blake2bVar::new(32).expect("constant digest size");
    for part in parts {
        h.update(part);
    }
    let mut out = Zeroizing::new([0; 32]);
    h.finalize_variable(out.as_mut())
        .expect("constant digest size");
    out
}
pub(super) fn encrypt(key: &[u8; 32], value: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0; 24];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| Error::new(ErrorKind::Connection, "Secure randomness unavailable"))?;
    let mut result = nonce.to_vec();
    result.extend(
        XSalsa20Poly1305::new(key.into())
            .encrypt(Nonce::from_slice(&nonce), value)
            .map_err(|_| protocol())?,
    );
    Ok(result)
}
impl Connection {
    pub fn new(stream: Stream, o: &TcpOptions) -> Self {
        Self {
            stream: BufReader::new(stream),
            key: None,
            plain: Vec::new(),
            offset: 0,
            deadline: Instant::now() + o.read_timeout,
        }
    }
    fn raw_bytes(&mut self, n: usize) -> Result<Vec<u8>> {
        let mut out = vec![0; n];
        let mut offset = 0;
        while offset < n {
            self.stream
                .get_ref()
                .socket()
                .set_read_timeout(Some(left(self.deadline)?))
                .map_err(io_error)?;
            match self.stream.read(&mut out[offset..]) {
                Ok(0) => return Err(Error::new(ErrorKind::Connection, "TCP peer disconnected")),
                Ok(n) => offset += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(io_error(e)),
            }
        }
        Ok(out)
    }
    fn raw_line(&mut self) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        loop {
            let b = self.raw_bytes(1)?[0];
            if b == b'\n' {
                return Ok(result);
            }
            result.push(b);
            if result.len() > HEADER {
                return Err(protocol());
            }
        }
    }
    fn fill_plain(&mut self, max: usize) -> Result<()> {
        let h = self.raw_line()?;
        let h = std::str::from_utf8(&h).map_err(|_| protocol())?;
        let p: Vec<_> = h.split(' ').collect();
        if p.len() != 2 || p[0] != "SEC" {
            return Err(protocol());
        }
        let n = length(p[1], max + HEADER + 41)?;
        if n < 40 {
            return Err(protocol());
        }
        let cipher = self.raw_bytes(n)?;
        let key = self.key.as_ref().ok_or_else(protocol)?;
        let value = XSalsa20Poly1305::new((&**key).into())
            .decrypt(Nonce::from_slice(&cipher[..24]), &cipher[24..])
            .map_err(|_| protocol())?;
        if self.plain.len() - self.offset + value.len() > max + HEADER + 1 {
            return Err(protocol());
        }
        self.plain.drain(..self.offset);
        self.offset = 0;
        self.plain.extend(value);
        Ok(())
    }
    pub fn bytes(&mut self, n: usize, max: usize) -> Result<Vec<u8>> {
        if self.key.is_none() {
            return self.raw_bytes(n);
        }
        while self.plain.len() - self.offset < n {
            self.fill_plain(max)?;
        }
        let out = self.plain[self.offset..self.offset + n].to_vec();
        self.offset += n;
        Ok(out)
    }
    pub fn header(&mut self, max: usize) -> Result<Vec<String>> {
        let mut line = if self.key.is_none() {
            self.raw_line()?
        } else {
            let mut out = Vec::new();
            loop {
                let b = self.bytes(1, max)?[0];
                if b == b'\n' {
                    break;
                }
                out.push(b);
                if out.len() > HEADER {
                    return Err(protocol());
                }
            }
            out
        };
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.is_empty() || !line.iter().all(|b| (32..=126).contains(b)) {
            return Err(protocol());
        }
        Ok(String::from_utf8(line)
            .map_err(|_| protocol())?
            .split(' ')
            .map(str::to_owned)
            .collect())
    }
    pub fn send(
        &mut self,
        header: &str,
        body: &[u8],
        o: &TcpOptions,
        attempted: &mut bool,
    ) -> Result<()> {
        if header.len() > HEADER
            || header.contains(['\r', '\n', '\0'])
            || body.len() > o.max_frame_bytes
        {
            return Err(input());
        }
        let mut frame = header.as_bytes().to_vec();
        frame.push(b'\n');
        frame.extend_from_slice(body);
        if let Some(key) = &self.key {
            let cipher = encrypt(key, &frame)?;
            frame = format!("SEC {}\n", cipher.len()).into_bytes();
            frame.extend(cipher);
        }
        let deadline = Instant::now() + o.write_timeout;
        let mut offset = 0;
        while offset < frame.len() {
            self.stream
                .get_ref()
                .socket()
                .set_write_timeout(Some(left(deadline)?))
                .map_err(io_error)?;
            *attempted = true;
            match self.stream.get_mut().write(&frame[offset..]) {
                Ok(0) => return Err(Error::new(ErrorKind::Connection, "TCP write failed")),
                Ok(n) => offset += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(io_error(e)),
            }
        }
        self.deadline = Instant::now() + o.read_timeout;
        Ok(())
    }
}
