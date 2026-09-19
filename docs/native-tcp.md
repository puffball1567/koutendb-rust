# Native TCP

Version 0.2.0 adds the optional `tcp` feature. The default remains `ffi`, preserving
the existing embedded API. TCP-only builds do not link libkoutendb and do not
require Nim or a KoutenDB core checkout on the application machine.

Install a TCP-only dependency:

```sh
cargo add koutendb@0.2 --no-default-features --features tcp
```

For a source checkout dependency:

```toml
[dependencies]
koutendb = { path = "../koutendb-rust", default-features = false, features = ["tcp"] }
serde_json = "1"
```

```rust
use koutendb::tcp::{TcpClient, TcpOptions};

let mut db = TcpClient::connect(vec!["127.0.0.1:17301".into()], TcpOptions::default())?;
let id = db.put_json("articles", &serde_json::json!({"title": "Hello"}))?;
let value = db.get_json(&id)?;
db.close();
# Ok::<(), koutendb::tcp::Error>(())
```

Set `TcpOptions.credentials` (`username`, `password`, `auth_token`,
`secret_key`) and `galaxy` for authenticated access. Set `tls` to
`Some(TlsOptions { ca_file: Some("ca.pem".into()), server_name:
Some("db.example.com".into()), ..Default::default() })` for a private CA.
Omit `ca_file` to use system roots. `Error.kind` is a typed `ErrorKind`.

`TcpId` contains all six wire identity fields. It is separate from the legacy
C ABI ID; do not truncate or interchange them. Serialize with `to_string()`
and parse with `parse::<TcpId>()`.

TCP is synchronous and requires exclusive `&mut` client access. Connection,
read and write timeouts are separate `Duration` fields. DNS uses the system
resolver and is not guaranteed to obey the TCP connection deadline.
Linux builds of native-tls require OpenSSL development files; macOS uses native
TLS. These are platform dependencies, not a dependency on KoutenDB's library.

```sh
cargo test --no-default-features --features tcp
cargo build --no-default-features --features tcp --example tcp_adapter
bash ../koutendb/scripts/native_driver_conformance.sh "$PWD/target/debug/examples/tcp_adapter"
```

## Server Setup

Run a TLS-enabled `koutend` build. For a local-only first test:

```sh
koutend --id=0 --peers=127.0.0.1:17301 --data=./kouten-data
```

Keep plaintext connections on localhost or an isolated, trusted private network.
A Docker network is not a substitute for access control. Use verified TLS when
traffic crosses a trust boundary. For password authentication, start the server
with `--user=app --password=...`; prefer the server's configuration/secret
management facilities for production rather than putting secrets in shell history.

Native TCP implements wire version 1: WIREVER, CODECMETA, PUTR, GETID, QRYID,
HEALTH, authentication and bounded FWD handling. It is not a replacement for
every embedded/admin API. It uses server-provided IDs and does not calculate
ring placement or orbit ownership. Peer ordering must match the server cluster
configuration, because explicit redirect owners are node indexes.

## Safety Contract

- Every new connection authenticates, checks WIREVER and enables codec metadata
  before sending application requests. Unsupported versions fail closed.
- Headers are bounded to 8 KiB; payload frames default to at most 64 MiB.
  The configurable payload cap cannot exceed that hard limit.
- Partial reads/writes are handled. A read deadline covers the complete response,
  not a fresh timeout for every fragment.
- A read may reconnect and retry once. An unknown write outcome is never retried.
- After a broken or malformed response the connection is discarded.
- Redirects default to eight hops (configurable up to 32), and an out-of-range
  owner is rejected. Missing values do not trigger a scan of every server.
- CA and hostname verification are enabled by default. TLS 1.2 is the minimum.
  Insecure verification bypass is explicitly development-only.
- Password/token and shared-secret challenge authentication are supported.
  Library transport errors do not include raw server error text or credentials.

A successful send is not proof that a write committed. If the connection breaks
or the reply is malformed after a PUT may have been sent, handle an
**indeterminate write** separately from a definite server rejection. Do not
blindly repeat the insert or assume a fallback database is now authoritative.
Reconcile at the application level until a server-side idempotency contract is
available.

The pre-v1 protocol is version-checked, not promised compatible with future
versions. Authentication errors, protocol errors, connection failures, timeouts,
server rejections and indeterminate writes are distinguishable.

## Verification

The adapter in this repository runs against KoutenDB's language-independent
`scripts/native_driver_conformance.py` suite, pinned in CI to core commit
`e36b424bcfd9cd0dfa24ae121f4b4dd028b0eaac`.

The shared matrix covers 27 scripted cases: fragmented/empty/Unicode/binary
responses, missing values, projections, invalid lengths/codecs/headers, redacted
server errors, version mismatches, connection loss, partial-response retry,
timeouts, backpressure, redirects and poisoned-connection disposal.
Six real-server configurations cover plaintext, password, token, shared-secret,
TLS and TLS plus shared-secret; these include 1 MiB round trips, invalid
credentials, untrusted certificates and hostname mismatch.

These are bounded correctness/integration checks, not endurance or throughput
benchmarks. Linux results are checked locally; Linux/macOS CI must pass before
release. Existing embedded regressions remain separate from native TCP checks.
