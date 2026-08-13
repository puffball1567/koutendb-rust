# KoutenDB Rust Driver

Rust driver for [KoutenDB](https://github.com/puffball1567/koutendb).

This crate currently wraps the KoutenDB C ABI. It gives Rust applications a safe
embedded API while KoutenDB keeps placement, ring metadata, retrieval planning,
and ID generation inside the database core.

Current driver version: `v0.1.6`.
Tested against KoutenDB core C ABI v2.
The v0.12 persistence APIs require a v0.12-compatible KoutenDB core build.

## Install

Prerequisites:

- Rust stable and Cargo
- Nim 2.2.x to build KoutenDB core. Install Nim: <https://nim-lang.org/install.html>. Nimble is included with the standard Nim installation.
- `libsodium` development headers, required by KoutenDB core. Install libsodium with your OS package manager or from <https://libsodium.org>.

```bash
cargo add koutendb
```

Or use KoutenDB's driver discovery command from the core CLI:

```bash
kouten driver install rust --manifest-path=/path/to/Cargo.toml
```

## Link KoutenDB Core

Build the KoutenDB shared library first:

```bash
git clone https://github.com/puffball1567/koutendb.git
cd koutendb
nimble install -y
nim c --app:lib -d:release --nimcache:/tmp/nimcache_kouten_capi -o:lib/libkoutendb.so src/koutendb_capi.nim
```

Then point this Rust crate at the KoutenDB core checkout or shared-library
directory:

```bash
KOUTENDB_CORE_DIR=/path/to/koutendb cargo test
```

or:

```bash
KOUTENDB_LIB_DIR=/path/to/koutendb/lib cargo test
```

If this repository is checked out next to `koutendb` or `ceresdb`, the build
script also detects `../koutendb/lib` and `../ceresdb/lib` automatically.

## Example

```rust
use koutendb::{ReadRingOptions, RetrieveOptions, KoutenDb};

let db = KoutenDb::open_default()?;
db.set_galaxy_description("Product and support knowledge")?;
db.set_ring_description("docs", "Documentation ring")?;
let id = db.put_json_vec("docs", r#"{"title":"hello","kind":"doc"}"#, &[1.0, 0.0])?;
let roundtrip_id = id.to_string().parse::<koutendb::KoutenId>()?;
assert_eq!(roundtrip_id, id);
let value = db.get_string(id)?.unwrap();
let encoded = db.get_encoded(id)?.unwrap();
assert_eq!(encoded.codec, koutendb::PayloadCodec::Json);
let selected = db.query_string(id, "{ title }")?;
let page = db.read_ring_json(
    "docs",
    &ReadRingOptions::new()
        .filter_json(r#"{"kind":"doc"}"#)
        .selection("{ title }")
        .limit(10),
)?;
let results = db.retrieve_with(
    &[1.0, 0.0],
    RetrieveOptions::new().ring("docs").budget(8),
)?;
let atlas = db.atlas(Some(&[1.0, 0.0]), 8)?;
# Ok::<(), koutendb::Error>(())
```

Run the full example:

```bash
KOUTENDB_CORE_DIR=/path/to/koutendb cargo run --example embedded
```

## TLS

TLS requires a KoutenDB core built with `-d:ssl`. The core's
`scripts/build_capi.sh` builds the shared library with it by default. A library
built without `-d:ssl` fails a TLS connect with
`TLS support requires building KoutenDB with -d:ssl`.

To reach a server whose certificate is signed by a private CA — or is
self-signed — point at the certificate PEM. Verification stays on:

```rust
let db = ConnectOptions::new("127.0.0.1:17651")
    .username("alice")
    .password("secret")
    .tls_ca_file("/path/to/server.crt")
    .connect()?;
```

`danger_accept_invalid_certs()` disables certificate verification entirely. The
connection is then encrypted but unauthenticated and trivially impersonable, so
it is for local smoke tests only — never a production server. Prefer
`tls_ca_file` for self-signed certificates.

```bash
KOUTENDB_CORE_DIR=/path/to/koutendb \
KOUTEN_PEERS=127.0.0.1:17651 KOUTEN_TLS_CA=/path/to/server.crt \
  cargo run --example cluster_tls
```

## Current API Coverage

| Area | Status |
|---|---|
| Embedded open | `KoutenDb::open_default`, `open`, `open_dir`, `open_dir_with`, `OpenDirOptions` (strong durability / disk-backed) |
| Cluster connect | `connect`, `connect_auth`, `connect_auth_tls`, `ConnectOptions` |
| TLS | `ConnectOptions::tls`, `tls_ca_file`, `tls_server_name`, `danger_accept_invalid_certs` |
| Writes / mutations | `put`, codec/vector helpers, `update`, `update_codec`, `update_str`, `update_json`, `remove` |
| Reads | `get`, `get_encoded`, `get_string`, `exists`, `batch_get`, `read_ring_json`, `ReadRingOptions` |
| Projection | `query`, `query_string` |
| Retrieval | `retrieve`, `retrieve_with`, `RetrieveOptions`, `RetrieveResult::first`, `payloads`, `payload_strings` |
| Atlas | `atlas` |
| Ring / galaxy metadata | `configure_ring`, `set_galaxy_description`, `set_ring_description` |
| Orbit helpers | `now`, `advance`, `locate`, `next_visit`, `next_join` |
| IDs | `KoutenId`, `Display`, `FromStr`, `KoutenId::parse` |
| Payload codecs | `PayloadCodec`, `EncodedPayload` |
| Metrics | `metrics`, `checkpoint_metrics`, `MetricsFormat` |
| Segment maintenance | `segment_status`, `plan_segment_maintenance`, `run_segment_maintenance`, `segment_maintenance_status`, `recover_segment_maintenance` |
| Generation checkpoints | `create_checkpoint`, `checkpoint_status`, `list_checkpoints`, `cleanup_checkpoints`, `restore_checkpoint` |
| Error handling | `Result<T, koutendb::Error>`, `ErrorKind` |

Still pending:

- transaction API;
- patch / list / count APIs, pending C ABI support;
- dump / import / backup / restore APIs (generation checkpoint restore is available);
- universe sync and broader recovery APIs;
- native TCP driver with timeout/retry/pooling.

## Development

```bash
cargo fmt
KOUTENDB_CORE_DIR=/path/to/koutendb cargo test
```

This package intentionally starts as a thin C ABI wrapper. A native TCP driver
can be added later without changing the safe embedded API.
