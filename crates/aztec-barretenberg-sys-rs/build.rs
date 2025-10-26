use std::env;
use std::fs;
use std::io::{self};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn cmd_exists(name: &str) -> bool {
    Command::new(name)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn run(mut cmd: Command) {
    let status = cmd.status().expect("failed to spawn command");
    if !status.success() {
        panic!("command failed: {:?}", cmd);
    }
}

fn repo_root() -> PathBuf {
    // crates/aztec-barretenberg-sys-rs -> crates -> repo root
    PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .parent().unwrap()
        .parent().unwrap()
        .to_path_buf()
}

fn bb_cpp_dir() -> PathBuf {
    repo_root().join("barretenberg/cpp")
}

fn default_build_dir(repo_root: &Path) -> PathBuf {
    let mac = repo_root.join("barretenberg/cpp/build-macos");
    if mac.exists() { mac } else { repo_root.join("barretenberg/cpp/build") }
}

fn build_dir_for_compilers(repo_root: &Path, cc: Option<&str>, cxx: Option<&str>) -> PathBuf {
    // If no explicit compilers provided, keep existing default behavior
    if cc.is_none() && cxx.is_none() {
        return default_build_dir(repo_root);
    }

    // Derive a deterministic build directory name based on the selected compilers
    fn slug(p: &str) -> String {
        let name = Path::new(p).file_name().and_then(|s| s.to_str()).unwrap_or(p);
        name.chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect()
    }

    let cc_slug = cc.map(slug).unwrap_or_else(|| "default".to_string());
    let cxx_slug = cxx.map(slug).unwrap_or_else(|| "default".to_string());
    repo_root
        .join("barretenberg/cpp")
        .join(format!("build-rs-{}-{}", cc_slug, cxx_slug))
}

fn built_lib_present(lib_dir: &Path) -> bool {
    lib_dir.join("libbarretenberg.a").exists()
}

fn target_triple() -> String {
    // Prefer explicit TARGET if provided (captures ios variants)
    if let Ok(t) = env::var("TARGET") {
        match t.as_str() {
            "x86_64-unknown-linux-gnu"
            | "aarch64-unknown-linux-gnu"
            | "aarch64-apple-darwin"
            | "aarch64-apple-ios-sim"
            | "aarch64-apple-ios" => return t,
            _ => {}
        }
    }
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    match (arch.as_str(), os.as_str()) {
        ("x86_64", "linux") => "x86_64-unknown-linux-gnu".to_string(),
        ("aarch64", "linux") => "aarch64-unknown-linux-gnu".to_string(),
        ("aarch64", "macos") => "aarch64-apple-darwin".to_string(),
        ("aarch64", "ios") => "aarch64-apple-ios-sim".to_string(),
        _ => {
            println!(
                "cargo:warning=Unsupported target {}/{}, falling back to local C++ build.",
                arch, os
            );
            String::new()
        }
    }
}

fn crate_version_tag() -> String {
    let v = env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION not set");
    format!("bb-v{}", v)
}

fn ensure_parent_dir(path: &Path) -> io::Result<()> {
    if let Some(dir) = path.parent() { fs::create_dir_all(dir)?; }
    Ok(())
}

fn download_with(cmd: &str, url: &str, dest: &Path) -> io::Result<bool> {
    ensure_parent_dir(dest)?;
    let status = match cmd {
        "curl" => Command::new("curl")
            .arg("-fL")
            .arg(url)
            .arg("-o")
            .arg(dest)
            .status(),
        "wget" => Command::new("wget")
            .arg("-qO")
            .arg(dest)
            .arg(url)
            .status(),
        _ => return Ok(false),
    }.map_err(|e| io::Error::new(io::ErrorKind::Other, format!("spawn {}: {}", cmd, e)))?;
    Ok(status.success())
}

fn download(url: &str, dest: &Path) -> io::Result<()> {
    if cmd_exists("curl") {
        if download_with("curl", url, dest)? { return Ok(()); }
    }
    if cmd_exists("wget") {
        if download_with("wget", url, dest)? { return Ok(()); }
    }
    Err(io::Error::new(io::ErrorKind::Other, format!("failed to download {} (need curl or wget)", url)))
}

fn extract_tar_gz(archive: &Path, dest: &Path) -> io::Result<()> {
    fs::create_dir_all(dest)?;
    // Use system tar for speed and to avoid extra deps
    let status = Command::new("tar")
        .arg("-xzf")
        .arg(archive)
        .arg("-C")
        .arg(dest)
        .status()?;
    if !status.success() {
        return Err(io::Error::new(io::ErrorKind::Other, "tar extraction failed"));
    }
    Ok(())
}

struct Prebuilt {
    lib: PathBuf,
    include: PathBuf,
    include_deps_msgpack: PathBuf,
    include_deps_tracy: PathBuf,
}

fn prebuilt_cache_dir() -> PathBuf {
    // Default cache under repo_root/target/bb-prebuilt
    if let Some(custom) = env::var_os("BB_PREBUILT_CACHE_DIR") { return PathBuf::from(custom); }
    repo_root().join("target/bb-prebuilt")
}

fn default_base_url() -> String {
    if let Ok(val) = env::var("BB_PREBUILT_BASE_URL") { if !val.is_empty() { return val; } }
    "https://github.com/Usernode-Labs/aztec-packages/releases".to_string()
}

// No default_prebuilt_version: we always use the crate's own version (CARGO_PKG_VERSION)

fn fetch_prebuilt(version_tag: &str, target: &str) -> io::Result<Prebuilt> {
    let base_url = default_base_url();
    let cache_root = prebuilt_cache_dir().join(version_tag).join(target);
    let lib_dir = cache_root.join("lib");
    let inc_dir = cache_root.join("include");
    if lib_dir.join("libbarretenberg.a").exists() {
        return Ok(Prebuilt{
            lib: lib_dir,
            include: inc_dir,
            include_deps_msgpack: cache_root.join("include-deps/msgpack"),
            include_deps_tracy: cache_root.join("include-deps/tracy"),
        });
    }

    fs::create_dir_all(&cache_root)?;
    // Strictly fetch assets for the crate version tag
    let asset = format!("barretenberg-{}-{}.tar.gz", version_tag, target);
    let url = format!("{}/download/{}/{}", base_url, version_tag, asset);
    let archive_path = cache_root.join(&asset);
    println!("cargo:warning=Downloading prebuilt Barretenberg: {}", url);
    download(&url, &archive_path)?;

    // Note: we intentionally skip checksum verification to keep build.rs minimal.
    // We rely on TLS + release hygiene. Advanced users can pin/verify externally.

    extract_tar_gz(&archive_path, &cache_root)?;
    let pb = Prebuilt{
        lib: lib_dir,
        include: inc_dir,
        include_deps_msgpack: cache_root.join("include-deps/msgpack"),
        include_deps_tracy: cache_root.join("include-deps/tracy"),
    };
    if !pb.lib.join("libbarretenberg.a").exists() {
        return Err(io::Error::new(io::ErrorKind::Other, "prebuilt archive missing lib/libbarretenberg.a"));
    }
    Ok(pb)
}

fn ensure_barretenberg_built(build_dir: &Path) {
    let cpp = bb_cpp_dir();
    if !cpp.exists() {
        panic!("barretenberg/cpp not found under repo root: {}", cpp.display());
    }

    println!("cargo:warning=Configuring Barretenberg in {}",
        build_dir.display());
    let mut cfg = Command::new("cmake");
    cfg.current_dir(&cpp)
        .arg("-S").arg(".")
        .arg("-B").arg(build_dir)
        .arg("-DCMAKE_BUILD_TYPE=RelWithDebInfo")
        .arg("-DTARGET_ARCH=skylake");

    // Honor CC/CXX if set by forwarding to CMake to avoid cached compiler choices
    if let Ok(cc) = env::var("CC") {
        if !cc.is_empty() { cfg.arg(format!("-DCMAKE_C_COMPILER={}", cc)); }
    }
    if let Ok(cxx) = env::var("CXX") {
        if !cxx.is_empty() { cfg.arg(format!("-DCMAKE_CXX_COMPILER={}", cxx)); }
    }

    if cmd_exists("ninja") {
        cfg.arg("-GNinja");
    }
    run(cfg);

    println!("cargo:warning=Building Barretenberg targets (bb, crypto_schnorr)
  …");
    let mut build = Command::new("cmake");
    build.current_dir(&cpp)
        .arg("--build").arg(build_dir)
        .arg("--target").arg("bb")
        .arg("--target").arg("crypto_schnorr");
    run(build);

    let lib_dir = build_dir.join("lib");
    if !built_lib_present(&lib_dir) {
        panic!("Barretenberg built, but static libs not found in {}",
            lib_dir.display());
    }

}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=BB_BUILD_DIR");
    println!("cargo:rerun-if-env-changed=BB_LIB_DIR");
    println!("cargo:rerun-if-env-changed=BB_USE_PREBUILT");
    println!("cargo:rerun-if-env-changed=BB_PREBUILT_VERSION");
    println!("cargo:rerun-if-env-changed=BB_PREBUILT_BASE_URL");
    println!("cargo:rerun-if-env-changed=BB_PREBUILT_ALLOW_BUILD_FALLBACK");
    println!("cargo:rerun-if-env-changed=BB_PREBUILT_CACHE_DIR");
    println!("cargo:rerun-if-env-changed=BB_PREBUILT_SHA256");
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=CXX");

    // Basic paths
    let repo_root = repo_root();
    let bb_cpp_src = bb_cpp_dir().join("src");

    // Resolve build/lib dirs; allow env overrides
    let env_bb_build = env::var_os("BB_BUILD_DIR").map(PathBuf::from);
    let env_bb_lib   = env::var_os("BB_LIB_DIR").map(PathBuf::from);

    let env_cc = env::var("CC").ok();
    let env_cxx = env::var("CXX").ok();

    // Resolve prebuilt usage decision
    let use_prebuilt = env::var("BB_USE_PREBUILT").ok().map(|s| s == "1" || s.eq_ignore_ascii_case("true")).unwrap_or(true);
    let allow_fallback = env::var("BB_PREBUILT_ALLOW_BUILD_FALLBACK").ok().map(|s| s == "1" || s.eq_ignore_ascii_case("true")).unwrap_or(false);

    let bb_build_dir = env_bb_build.clone().unwrap_or_else(||
        build_dir_for_compilers(&repo_root, env_cc.as_deref(), env_cxx.as_deref()));
    let mut bb_lib_dir   = env_bb_lib.clone().map(|p| p).unwrap_or_else(|| bb_build_dir.join("lib"));

    // Track include directories for shim
    let mut inc_primary = bb_cpp_dir().join("src");
    let mut inc_msgpack = bb_build_dir.join("_deps/msgpack-c/src/msgpack-c/include");
    let mut inc_tracy   = bb_build_dir.join("_deps/tracy-src/public");

    if env_bb_lib.is_some() {
        if !bb_lib_dir.exists() {
            panic!("BB_LIB_DIR was set to {:?} but it does not exist", bb_lib_dir);
        }
        println!("cargo:warning=Using BB_LIB_DIR={} (no build)", bb_lib_dir.display());
        // If BB_LIB_DIR points to a prebuilt-style tree, prefer adjacent include dirs.
        if let Some(root) = bb_lib_dir.parent() {
            let inc = root.join("include");
            let m = root.join("include-deps/msgpack");
            let t = root.join("include-deps/tracy");
            if inc.exists() { inc_primary = inc; }
            if m.exists() { inc_msgpack = m; }
            if t.exists() { inc_tracy = t; }
        }
    } else if use_prebuilt {
        let ver = env::var("BB_PREBUILT_VERSION").unwrap_or_else(|_| crate_version_tag());
        let triple = target_triple();
        if triple.is_empty() {
            if allow_fallback {
                println!("cargo:warning=No prebuilt support for this target; falling back to local build");
            } else {
                panic!("No prebuilt support for this target and fallback disabled. Set BB_PREBUILT_ALLOW_BUILD_FALLBACK=1 to proceed.");
            }
        } else {
            match fetch_prebuilt(&ver, &triple) {
                Ok(pb) => {
                    bb_lib_dir = pb.lib.clone();
                    inc_primary = pb.include.clone();
                    inc_msgpack = pb.include_deps_msgpack.clone();
                    inc_tracy = pb.include_deps_tracy.clone();
                    println!("cargo:warning=Using prebuilt Barretenberg {} for {}", ver, triple);
                }
                Err(e) => {
                    if allow_fallback {
                        println!("cargo:warning=Prebuilt unavailable ({}); falling back to local build", e);
                    } else {
                        panic!("Failed to fetch prebuilt ({}). Set BB_PREBUILT_ALLOW_BUILD_FALLBACK=1 to build locally or set BB_LIB_DIR.", e);
                    }
                }
            }
        }
    }

    // If still no libs present, optionally build locally
    if !built_lib_present(&bb_lib_dir) {
        if allow_fallback {
            println!("cargo:warning=Barretenberg libs not found at {}; building locally…", bb_lib_dir.display());
            ensure_barretenberg_built(&bb_build_dir);
            bb_lib_dir = bb_build_dir.join("lib");
            inc_primary = bb_cpp_dir().join("src");
            inc_msgpack = bb_build_dir.join("_deps/msgpack-c/src/msgpack-c/include");
            inc_tracy   = bb_build_dir.join("_deps/tracy-src/public");
        } else {
            panic!("Barretenberg libs not available and fallback disabled. Provide prebuilt (BB_USE_PREBUILT=1) or set BB_PREBUILT_ALLOW_BUILD_FALLBACK=1.");
        }
    }

    // Rebuild if static archives change (or shim source if we build locally)
    println!("cargo:rerun-if-changed={}", bb_lib_dir.join("libbarretenberg.a").display());
    println!("cargo:rerun-if-changed={}", bb_lib_dir.join("libbb_rust_api.a").display());

    // Decide whether to use a prebuilt shim or compile the local shim. If the environment
    // variable BB_FORCE_LOCAL_SHIM=1 is set, always compile the local shim to ensure the
    // latest symbols are available even when a prebuilt shim is present.
    let prebuilt_shim = bb_lib_dir.join("libbb_rust_api.a");
    let force_local_shim = env::var("BB_FORCE_LOCAL_SHIM")
        .ok()
        .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if prebuilt_shim.exists() && !force_local_shim {
        println!("cargo:warning=Using prebuilt bb_rust_api from {}", prebuilt_shim.display());
        println!("cargo:rustc-link-lib=static=bb_rust_api");
    } else {
        if allow_fallback || force_local_shim {
            println!("cargo:warning=Compiling local C++ shim (force_local_shim={})", force_local_shim);
            // Compile shim from a temporary copy to avoid local source-tree header collisions when linking against prebuilt.
            let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
            let shim_src = out_dir.join("bb_rust_api.cpp");
            let shim_in = bb_cpp_src.join("bb_rust_api.cpp");
            std::fs::copy(&shim_in, &shim_src).expect("copy bb_rust_api.cpp");

            let mut cc_build = cc::Build::new();
            cc_build
                .cpp(true)
                .flag("-std=c++20")
                .flag("-fPIC")
                .flag("-Wno-error")
                .flag_if_supported("-Wno-unused-parameter")
                .flag_if_supported(if env::var("SANITIZE").ok().as_deref() == Some("address") {
                    "-fsanitize=address"
                } else {
                    ""
                })
                .flag_if_supported(if env::var("SANITIZE").ok().as_deref() == Some("address") {
                    "-fno-omit-frame-pointer"
                } else {
                    ""
                })
                // Only include prebuilt (or built) headers, not local source tree headers
                .include(&inc_primary)
                .include(&inc_msgpack)
                .include(&inc_tracy)
                .file(&shim_src);
            cc_build.compile("bb_rust_api");
        } else {
            panic!(
                "libbb_rust_api.a not found in {} and fallback compilation disabled.",
                bb_lib_dir.display()
            );
        }
    }

    // Link against barretenberg and related static libs
    println!("cargo:rustc-link-search=native={}", bb_lib_dir.display());
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let is_linux = target_os == "linux";
    if is_linux {
        println!("cargo:rustc-link-arg=-Wl,--start-group");
    }
    println!("cargo:rustc-link-lib=static=barretenberg");
    println!("cargo:rustc-link-lib=static=env");
    println!("cargo:rustc-link-lib=static=crypto_pedersen_commitment");
    println!("cargo:rustc-link-lib=static=crypto_pedersen_hash");
    println!("cargo:rustc-link-lib=static=crypto_poseidon2");
    println!("cargo:rustc-link-lib=static=ecc");
    println!("cargo:rustc-link-lib=static=crypto_schnorr");
    if is_linux {
        println!("cargo:rustc-link-arg=-Wl,--end-group");
    }

    if env::var("SANITIZE").ok().as_deref() == Some("address") {
        println!("cargo:rustc-link-lib=asan");
    }

    // Math + pthread everywhere
    println!("cargo:rustc-link-lib=dylib=m");
    println!("cargo:rustc-link-lib=dylib=pthread");

    // Platform-specific C++ runtime
    if target_os == "macos" || target_os == "ios" {
        println!("cargo:rustc-link-lib=dylib=c++"); // libc++ on Apple (macOS/iOS)
    } else {
        // Link libstdc++/libgcc dynamically on Linux (ensures symbols resolved)
        println!("cargo:rustc-link-lib=dylib=stdc++");
        println!("cargo:rustc-link-lib=dylib=gcc_s");
        println!("cargo:rustc-link-lib=dylib=dl");
    }

}
