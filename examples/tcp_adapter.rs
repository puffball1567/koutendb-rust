//! JSONL adapter for the core language-neutral conformance suite.
use base64::{engine::general_purpose::STANDARD, Engine};
use koutendb::tcp::{
    Codec, Credentials, Error, ErrorKind, TcpClient, TcpId, TcpOptions, TlsOptions,
};
use serde_json::{json, Value};
use std::{
    io::{self, BufRead, Write},
    time::Duration,
};

fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or("")
}
fn timeout(v: &Value, key: &str, default: f64) -> Duration {
    Duration::from_secs_f64(v[key].as_f64().unwrap_or(default))
}
fn call(db: &mut Option<TcpClient>, op: &Value) -> Result<Value, Error> {
    if text(op, "op") == "connect" {
        if let Some(db) = db {
            db.close();
        }
        let o = &op["options"];
        let mut options = TcpOptions {
            connect_timeout: timeout(op, "timeout", 1.0),
            read_timeout: timeout(op, "readTimeout", 1.0),
            write_timeout: timeout(op, "writeTimeout", 1.0),
            credentials: Credentials {
                username: text(o, "username").into(),
                password: text(o, "password").into(),
                auth_token: text(o, "authToken").into(),
                secret_key: text(o, "secretKey").into(),
            },
            galaxy: text(o, "galaxy").into(),
            ..Default::default()
        };
        if let Some(b) = o["retryReads"].as_bool() {
            options.retry_reads = b;
        }
        if let Some(n) = o["maxFrameBytes"].as_u64() {
            options.max_frame_bytes = n as usize;
        }
        if let Some(n) = o["maxRedirects"].as_u64() {
            options.max_redirects = n as usize;
        }
        if o["tls"].as_bool() == Some(true) {
            options.tls = Some(TlsOptions {
                ca_file: o["tlsCaFile"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .map(Into::into),
                server_name: o["tlsServerName"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .map(Into::into),
                insecure_skip_verify: o["tlsInsecureSkipVerify"].as_bool().unwrap_or(false),
            });
        }
        *db = Some(TcpClient::connect(
            op["peers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().into())
                .collect(),
            options,
        )?);
        return Ok(json!("connected"));
    }
    let db = db.as_mut().expect("connect first");
    let id = || text(op, "id").parse::<TcpId>();
    Ok(match text(op, "op") {
        "put" => json!(db
            .put_codec(
                text(op, "ring"),
                &STANDARD.decode(text(op, "payload")).unwrap(),
                Codec::parse(op["codec"].as_str().unwrap_or("raw"))?
            )?
            .to_string()),
        "putJson" => json!(db.put_json(text(op, "ring"), &op["value"])?.to_string()),
        "get" => match db.get_encoded(&id()?)? {
            Some(v) => json!({"payload": STANDARD.encode(v.payload), "codec": v.codec.as_str()}),
            None => Value::Null,
        },
        "getJson" => db.get_json(&id()?)?.unwrap_or(Value::Null),
        "query" => db
            .query_json(&id()?, text(op, "selection"))?
            .unwrap_or(Value::Null),
        "health" => json!(db.health()?),
        "debug" => json!(format!("{db:?}")),
        "close" => {
            db.close();
            json!("closed")
        }
        _ => panic!("unknown adapter operation"),
    })
}
fn main() {
    let mut db = None;
    for line in io::stdin().lock().lines() {
        let op: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let reply = match call(&mut db, &op) {
            Ok(v) => json!({"ok": true, "result": v}),
            Err(e) => {
                let kind = match e.kind {
                    ErrorKind::Connection => "ConnectionException",
                    ErrorKind::Timeout => "ConnectionTimeoutException",
                    ErrorKind::Authentication => "AuthenticationException",
                    ErrorKind::Protocol => "ProtocolException",
                    ErrorKind::VersionMismatch => "VersionMismatchException",
                    ErrorKind::Server => "ServerException",
                    ErrorKind::IndeterminateWrite => "IndeterminateWriteException",
                    ErrorKind::InvalidInput => "InvalidArgumentException",
                };
                json!({"ok": false, "error": kind, "message": e.to_string()})
            }
        };
        println!("{reply}");
        io::stdout().flush().unwrap();
    }
}
