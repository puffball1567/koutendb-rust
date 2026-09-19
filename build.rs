use std::path::{Path, PathBuf};

fn main() {
    if std::env::var_os("CARGO_FEATURE_FFI").is_none() {
        return;
    }
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let lib_dir = lib_dir(&manifest_dir);
    let lib_dir = lib_dir.canonicalize().unwrap_or(lib_dir);
    println!("cargo:rerun-if-env-changed=KOUTENDB_LIB_DIR");
    println!("cargo:rerun-if-env-changed=KOUTENDB_CORE_DIR");
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=dylib=koutendb");
    println!("cargo:rustc-link-arg=-Wl,-rpath,{}", lib_dir.display());
}

fn lib_dir(manifest_dir: &Path) -> PathBuf {
    if let Ok(dir) = std::env::var("KOUTENDB_LIB_DIR") {
        return PathBuf::from(dir);
    }
    if let Ok(dir) = std::env::var("KOUTENDB_CORE_DIR") {
        return PathBuf::from(dir).join("lib");
    }

    let candidates = [
        manifest_dir.join("../koutendb/lib"),
        manifest_dir.join("../ceresdb/lib"),
        manifest_dir.join("../../lib"),
    ];
    candidates
        .into_iter()
        .find(|p| p.join(shared_lib_name()).exists())
        .unwrap_or_else(|| manifest_dir.join("../koutendb/lib"))
}

fn shared_lib_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "libkoutendb.dylib"
    } else {
        "libkoutendb.so"
    }
}
