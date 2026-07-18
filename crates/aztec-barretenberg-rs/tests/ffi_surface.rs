use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate parent")
        .parent()
        .expect("repo root")
        .to_path_buf()
}

fn parse_symbol_after_prefix<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
    let trimmed = line.trim_start();
    let rest = trimmed.strip_prefix(prefix)?;
    let open = rest.find('(')?;
    Some(rest[..open].trim())
}

fn collect_cpp_exports(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in text.lines() {
        if let Some(name) = parse_symbol_after_prefix(line, "int bb_") {
            out.insert(format!("bb_{name}"));
        } else if let Some(name) = parse_symbol_after_prefix(line, "void bb_") {
            out.insert(format!("bb_{name}"));
        } else if let Some(name) = parse_symbol_after_prefix(line, "void srs_") {
            out.insert(format!("srs_{name}"));
        }
    }
    out
}

fn collect_sys_decls(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in text.lines() {
        for prefix in ["bb_", "srs_"] {
            if let Some(name) = line.trim_start().strip_prefix(&format!("pub fn {prefix}")) {
                if let Some(open) = name.find('(') {
                    out.insert(format!("{prefix}{}", name[..open].trim()));
                }
            }
        }
    }
    out
}

fn collect_rs_ffi_uses(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let needle = "aztec_barretenberg_sys_rs::";
    let mut start = 0;
    while let Some(idx) = text[start..].find(needle) {
        let symbol_start = start + idx + needle.len();
        let tail = &text[symbol_start..];
        let len = tail
            .chars()
            .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
            .count();
        if len > 0 {
            let sym = &tail[..len];
            if sym.starts_with("bb_") || sym.starts_with("srs_") {
                out.insert(sym.to_string());
            }
        }
        start = symbol_start + len;
    }
    out
}

#[test]
fn ffi_surface_is_consistent() {
    let root = repo_root();
    let crypto_cpp = fs::read_to_string(root.join("barretenberg/cpp/src/bb_rust_crypto_api.cpp"))
        .expect("read bb_rust_crypto_api.cpp");
    let prover_cpp = fs::read_to_string(root.join("barretenberg/cpp/src/bb_rust_prover_api.cpp"))
        .expect("read bb_rust_prover_api.cpp");
    let crypto_sys =
        fs::read_to_string(root.join("crates/aztec-barretenberg-crypto-sys-rs/src/lib.rs"))
            .expect("read crypto sys lib.rs");
    let prover_sys = fs::read_to_string(root.join("crates/aztec-barretenberg-sys-rs/src/lib.rs"))
        .expect("read prover sys lib.rs");
    let rs = fs::read_to_string(root.join("crates/aztec-barretenberg-rs/src/lib.rs"))
        .expect("read rust lib.rs");

    let crypto_cpp_exports = collect_cpp_exports(&crypto_cpp);
    let prover_cpp_exports = collect_cpp_exports(&prover_cpp);
    let crypto_sys_decls = collect_sys_decls(&crypto_sys);
    let prover_sys_decls = collect_sys_decls(&prover_sys);
    let rust_uses = collect_rs_ffi_uses(&rs);

    assert_eq!(
        crypto_cpp_exports, crypto_sys_decls,
        "crypto C++ bb_* exports and crypto sys declarations diverged"
    );
    assert_eq!(
        prover_cpp_exports, prover_sys_decls,
        "prover C++ bb_* exports and prover sys declarations diverged"
    );

    let overlap = crypto_sys_decls
        .intersection(&prover_sys_decls)
        .cloned()
        .collect::<BTreeSet<_>>();
    assert!(
        overlap.is_empty(),
        "crypto and prover sys declarations must stay disjoint: {overlap:?}"
    );

    let all_sys_decls = crypto_sys_decls
        .union(&prover_sys_decls)
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        all_sys_decls, rust_uses,
        "split sys declarations and safe Rust bb_* usage diverged"
    );
}
