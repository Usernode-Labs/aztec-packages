use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const EXPECTED_BN254_G1: u64 = 67_108_928; // bytes, 2^20 + 1 points
const EXPECTED_BN254_G2: u64 = 128;
const EXPECTED_GRUMPKIN_G1: u64 = 16_777_216; // bytes, 2^18 points
const BN254_G1_POINTS: u32 = 1_048_577;
const GRUMPKIN_POINTS: u32 = 262_144;
const CRS_BASE_URL: &str = "https://crs.aztec.network";

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

fn read_text(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|err| {
        panic!("failed to read {}: {}", path.display(), err);
    })
}

fn repo_root() -> PathBuf {
    // crates/aztec-barretenberg-sys-rs -> crates -> repo root
    PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn bb_cpp_dir() -> PathBuf {
    repo_root().join("barretenberg/cpp")
}

fn default_build_dir(repo_root: &Path) -> PathBuf {
    let mac = repo_root.join("barretenberg/cpp/build-macos");
    if mac.exists() {
        mac
    } else {
        repo_root.join("barretenberg/cpp/build")
    }
}

fn build_dir_for_compilers(repo_root: &Path, cc: Option<&str>, cxx: Option<&str>) -> PathBuf {
    // If no explicit compilers provided, keep existing default behavior
    if cc.is_none() && cxx.is_none() {
        return default_build_dir(repo_root);
    }

    // Derive a deterministic build directory name based on the selected compilers
    fn slug(p: &str) -> String {
        let name = Path::new(p)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(p);
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

fn infer_llvm_tool_from_compiler(compiler: &str, tool_name: &str) -> Option<String> {
    let compiler_path = Path::new(compiler);
    let dir = compiler_path.parent()?;
    let candidate = dir.join(tool_name);
    if candidate.exists() {
        return Some(candidate.to_string_lossy().into_owned());
    }
    None
}

fn built_lib_present(lib_dir: &Path) -> bool {
    lib_dir.join("libbb-external.a").exists() && lib_dir.join("libbb_rust_api.a").exists()
}

fn relwithdebinfo_flags(language: &str) -> &'static str {
    match language {
        "C" | "CXX" => "-O2 -g -DNDEBUG",
        _ => panic!(
            "unsupported language for RelWithDebInfo flags: {}",
            language
        ),
    }
}

fn validate_relwithdebinfo_flags(build_dir: &Path) {
    let cache_path = build_dir.join("CMakeCache.txt");
    let cache = read_text(&cache_path);

    for (var, expected) in [
        ("CMAKE_C_FLAGS_RELWITHDEBINFO", relwithdebinfo_flags("C")),
        (
            "CMAKE_CXX_FLAGS_RELWITHDEBINFO",
            relwithdebinfo_flags("CXX"),
        ),
    ] {
        let prefix = format!("{var}:STRING=");
        let actual = cache
            .lines()
            .find_map(|line| line.strip_prefix(&prefix))
            .unwrap_or_else(|| panic!("missing {} in {}", var, cache_path.display()));
        if actual != expected {
            panic!(
                "{} in {} was {:?}, expected {:?}",
                var,
                cache_path.display(),
                actual,
                expected
            );
        }
    }
}

fn target_triple() -> String {
    // Prefer explicit TARGET if provided (captures ios/android variants)
    if let Ok(t) = env::var("TARGET") {
        match t.as_str() {
            "x86_64-unknown-linux-gnu"
            | "aarch64-unknown-linux-gnu"
            | "x86_64-linux-android"
            | "aarch64-apple-darwin"
            | "aarch64-apple-ios-sim"
            | "aarch64-apple-ios"
            | "aarch64-linux-android" => return t,
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
        ("x86_64", "android") => "x86_64-linux-android".to_string(),
        ("aarch64", "android") => "aarch64-linux-android".to_string(),
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
    format!("v{}", v)
}

fn ensure_parent_dir(path: &Path) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
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
        "wget" => Command::new("wget").arg("-qO").arg(dest).arg(url).status(),
        _ => return Ok(false),
    }
    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("spawn {}: {}", cmd, e)))?;
    Ok(status.success())
}

fn download(url: &str, dest: &Path) -> io::Result<()> {
    if cmd_exists("curl") {
        if download_with("curl", url, dest)? {
            return Ok(());
        }
    }
    if cmd_exists("wget") {
        if download_with("wget", url, dest)? {
            return Ok(());
        }
    }
    Err(io::Error::new(
        io::ErrorKind::Other,
        format!("failed to download {} (need curl or wget)", url),
    ))
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
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "tar extraction failed",
        ));
    }
    Ok(())
}

struct Prebuilt {
    root: PathBuf,
    lib: PathBuf,
}

struct IncludePaths {
    include: PathBuf,
    msgpack: PathBuf,
}

fn prebuilt_cache_dir() -> PathBuf {
    // Default cache under repo_root/target/bb-prebuilt
    if let Some(custom) = env::var_os("BB_PREBUILT_CACHE_DIR") {
        return PathBuf::from(custom);
    }
    repo_root().join("target/bb-prebuilt")
}

fn default_base_url() -> String {
    if let Ok(val) = env::var("BB_PREBUILT_BASE_URL") {
        if !val.is_empty() {
            return val;
        }
    }
    "https://github.com/Usernode-Labs/aztec-packages/releases".to_string()
}

// No default_prebuilt_version: we always use the crate's own version (CARGO_PKG_VERSION)

fn fetch_prebuilt(version_tag: &str, target: &str) -> io::Result<Prebuilt> {
    let base_url = default_base_url();
    let cache_root = prebuilt_cache_dir().join(version_tag).join(target);
    let lib_dir = cache_root.join("lib");
    if built_lib_present(&lib_dir) && prebuilt_headers_present(&cache_root) {
        return Ok(Prebuilt {
            root: cache_root,
            lib: lib_dir,
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
    let pb = Prebuilt {
        root: cache_root,
        lib: lib_dir,
    };
    if !built_lib_present(&pb.lib) {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "prebuilt archive missing lib/libbb-external.a or lib/libbb_rust_api.a",
        ));
    }
    if !prebuilt_headers_present(&pb.root) {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "prebuilt archive missing Barretenberg headers or msgpack public headers",
        ));
    }
    Ok(pb)
}

fn prebuilt_headers_present(root: &Path) -> bool {
    root.join("include/barretenberg").is_dir()
        && root.join("include/msgpack.hpp").is_file()
        && root.join("include-deps/msgpack/msgpack.hpp").is_file()
        && root.join("include-deps/msgpack/msgpack").is_dir()
}

fn prebuilt_root_from_lib_dir(lib_dir: &Path) -> Option<PathBuf> {
    let root = lib_dir.parent()?;
    if root.join("include").exists() || root.join("include-deps").exists() {
        Some(root.to_path_buf())
    } else {
        None
    }
}

fn prebuilt_include_paths(root: &Path) -> IncludePaths {
    IncludePaths {
        include: root.join("include"),
        msgpack: root.join("include-deps/msgpack"),
    }
}

fn local_include_paths(repo_root: &Path, build_dir: &Path) -> IncludePaths {
    IncludePaths {
        include: repo_root.join("barretenberg/cpp/src"),
        msgpack: build_dir.join("_deps/msgpack-c/src/msgpack-c/include"),
    }
}

fn emit_include_metadata(paths: &IncludePaths) {
    let joined = env::join_paths([&paths.include, &paths.msgpack])
        .expect("failed to join Barretenberg include paths");
    let include_flags = format!(
        "-I{} -I{}",
        paths.include.display(),
        paths.msgpack.display()
    );
    let cxxflags = format!(
        "-DMSGPACK_NO_BOOST -DMSGPACK_USE_STD_VARIANT_ADAPTOR {}",
        include_flags
    );

    // Cargo exposes these as DEP_AZTEC_BARRETENBERG_* to immediate dependents
    // because this crate declares links = "aztec_barretenberg".
    println!("cargo:include={}", paths.include.display());
    println!("cargo:include_deps_msgpack={}", paths.msgpack.display());
    println!("cargo:include_paths={}", joined.to_string_lossy());
    println!("cargo:include_flags={}", include_flags);
    println!("cargo:cxxflags={}", cxxflags);
    println!(
        "cargo:warning=Barretenberg include paths: {}, {}",
        paths.include.display(),
        paths.msgpack.display()
    );
}

fn crs_url(path: &str, override_var: &str) -> String {
    if let Ok(val) = env::var(override_var) {
        if !val.is_empty() {
            return val;
        }
    }
    format!("{}/{}", CRS_BASE_URL, path)
}

fn download_crs_file(
    url: &str,
    dest: &Path,
    expected_len: u64,
    range_end: Option<u64>,
) -> io::Result<()> {
    ensure_parent_dir(dest)?;
    if let Ok(md) = fs::metadata(dest) {
        if md.len() == expected_len {
            return Ok(());
        }
    }
    println!("cargo:warning=Downloading CRS from {}", url);
    if let Some(end) = range_end {
        // Use curl range to avoid fetching the full gigantic file.
        let status = Command::new("curl")
            .arg("-fL")
            .arg("-r")
            .arg(format!("0-{}", end))
            .arg(url)
            .arg("-o")
            .arg(dest)
            .status()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("spawn curl: {}", e)))?;
        if !status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("curl range download failed for {}", url),
            ));
        }
    } else {
        download(url, dest)?;
    }
    let len = fs::metadata(dest)?.len();
    if len != expected_len {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "CRS download {} had length {} (expected {})",
                dest.display(),
                len,
                expected_len
            ),
        ));
    }
    Ok(())
}

fn ensure_crs_downloaded(out_dir: &Path) -> io::Result<()> {
    let crs_dir = out_dir.join("bb-crs");
    fs::create_dir_all(&crs_dir)?;
    let g1_url = crs_url("g1.dat", "BB_CRS_URL_BN254_G1");
    let g2_url = crs_url("g2.dat", "BB_CRS_URL_BN254_G2");
    let grumpkin_url = crs_url("grumpkin_g1.dat", "BB_CRS_URL_GRUMPKIN_G1");

    let g1_path = crs_dir.join("bn254_g1.dat");
    let g2_path = crs_dir.join("bn254_g2.dat");
    let grumpkin_path = crs_dir.join("grumpkin_g1.flat.dat");

    download_crs_file(
        &g1_url,
        &g1_path,
        EXPECTED_BN254_G1,
        Some(EXPECTED_BN254_G1 - 1),
    )?;
    download_crs_file(&g2_url, &g2_path, EXPECTED_BN254_G2, None)?;
    download_crs_file(
        &grumpkin_url,
        &grumpkin_path,
        EXPECTED_GRUMPKIN_G1,
        Some(EXPECTED_GRUMPKIN_G1 - 1),
    )?;

    Ok(())
}

fn emit_embedded_crs_module(out_dir: &Path) -> io::Result<()> {
    let module = out_dir.join("crs_embedded.rs");
    let mut f = fs::File::create(&module)?;
    writeln!(
        f,
        "pub const BN254_G1: &[u8] = include_bytes!(concat!(env!(\"OUT_DIR\"), \"/bb-crs/bn254_g1.dat\"));"
    )?;
    writeln!(
        f,
        "pub const BN254_G2: &[u8] = include_bytes!(concat!(env!(\"OUT_DIR\"), \"/bb-crs/bn254_g2.dat\"));"
    )?;
    writeln!(
        f,
        "pub const GRUMPKIN_G1: &[u8] = include_bytes!(concat!(env!(\"OUT_DIR\"), \"/bb-crs/grumpkin_g1.flat.dat\"));"
    )?;
    writeln!(f, "pub const BN254_G1_POINTS: u32 = {};", BN254_G1_POINTS)?;
    writeln!(f, "pub const GRUMPKIN_POINTS: u32 = {};", GRUMPKIN_POINTS)?;
    Ok(())
}

fn ensure_barretenberg_built(build_dir: &Path) {
    let cpp = bb_cpp_dir();
    if !cpp.exists() {
        panic!(
            "barretenberg/cpp not found under repo root: {}",
            cpp.display()
        );
    }

    println!(
        "cargo:warning=Configuring Barretenberg in {}",
        build_dir.display()
    );
    let mut cfg = Command::new("cmake");
    cfg.current_dir(&cpp)
        .arg("-S")
        .arg(".")
        .arg("-B")
        .arg(build_dir)
        .arg("-DCMAKE_BUILD_TYPE=RelWithDebInfo")
        .arg(format!(
            "-DCMAKE_C_FLAGS_RELWITHDEBINFO={}",
            relwithdebinfo_flags("C")
        ))
        .arg(format!(
            "-DCMAKE_CXX_FLAGS_RELWITHDEBINFO={}",
            relwithdebinfo_flags("CXX")
        ))
        .arg("-DCMAKE_POSITION_INDEPENDENT_CODE=ON")
        .arg("-DDISABLE_AZTEC_VM=ON")
        .arg("-DENABLE_TRACY=OFF")
        .arg("-DBB_BUILD_TRANSLATOR_VM=ON")
        .arg("-DBB_ENABLE_BENCH=OFF")
        .arg("-DBB_ENABLE_TESTS=OFF");

    // Honor CC/CXX if set by forwarding to CMake to avoid cached compiler choices
    if let Ok(cc) = env::var("CC") {
        if !cc.is_empty() {
            cfg.arg(format!("-DCMAKE_C_COMPILER={}", cc));
        }
    }
    if let Ok(cxx) = env::var("CXX") {
        if !cxx.is_empty() {
            cfg.arg(format!("-DCMAKE_CXX_COMPILER={}", cxx));
        }
    }
    if let Ok(ar) = env::var("AR") {
        if !ar.is_empty() {
            cfg.arg(format!("-DCMAKE_AR={}", ar));
        }
    } else if let Ok(cxx) = env::var("CXX") {
        if !cxx.is_empty() {
            if let Some(inferred_ar) = infer_llvm_tool_from_compiler(&cxx, "llvm-ar") {
                cfg.arg(format!("-DCMAKE_AR={}", inferred_ar));
            }
        }
    }
    if let Ok(ranlib) = env::var("RANLIB") {
        if !ranlib.is_empty() {
            cfg.arg(format!("-DCMAKE_RANLIB={}", ranlib));
        }
    } else if let Ok(cxx) = env::var("CXX") {
        if !cxx.is_empty() {
            if let Some(inferred_ranlib) = infer_llvm_tool_from_compiler(&cxx, "llvm-ranlib") {
                cfg.arg(format!("-DCMAKE_RANLIB={}", inferred_ranlib));
            }
        }
    }

    if cmd_exists("ninja") {
        cfg.arg("-GNinja");
    }
    run(cfg);
    validate_relwithdebinfo_flags(build_dir);

    println!(
        "cargo:warning=Building Barretenberg targets (bb-external, bb_rust_api)
  …"
    );
    let mut build = Command::new("cmake");
    build
        .current_dir(&cpp)
        .arg("--build")
        .arg(build_dir)
        .arg("--target")
        .arg("bb-external")
        .arg("--target")
        .arg("bb_rust_api");
    run(build);

    let lib_dir = build_dir.join("lib");
    if !built_lib_present(&lib_dir) {
        panic!(
            "Barretenberg built, but static libs not found in {}",
            lib_dir.display()
        );
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
    println!("cargo:rerun-if-env-changed=BB_CRS_URL_BN254_G1");
    println!("cargo:rerun-if-env-changed=BB_CRS_URL_BN254_G2");
    println!("cargo:rerun-if-env-changed=BB_CRS_URL_GRUMPKIN_G1");
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=CXX");

    // Basic paths
    let repo_root = repo_root();
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR set by cargo"));

    // Resolve build/lib dirs; allow env overrides
    let env_bb_build = env::var_os("BB_BUILD_DIR").map(PathBuf::from);
    let env_bb_lib = env::var_os("BB_LIB_DIR").map(PathBuf::from);

    let env_cc = env::var("CC").ok();
    let env_cxx = env::var("CXX").ok();

    // Resolve prebuilt usage decision
    let use_prebuilt = env::var("BB_USE_PREBUILT")
        .ok()
        .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
        .unwrap_or(true);
    let allow_fallback = env::var("BB_PREBUILT_ALLOW_BUILD_FALLBACK")
        .ok()
        .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let bb_build_dir = env_bb_build.clone().unwrap_or_else(|| {
        build_dir_for_compilers(&repo_root, env_cc.as_deref(), env_cxx.as_deref())
    });
    let mut bb_lib_dir = env_bb_lib
        .clone()
        .map(|p| p)
        .unwrap_or_else(|| bb_build_dir.join("lib"));

    let mut using_downloaded_prebuilt = false;
    let mut prebuilt_root = env_bb_lib.as_deref().and_then(prebuilt_root_from_lib_dir);
    if env_bb_lib.is_some() {
        if !bb_lib_dir.exists() {
            panic!(
                "BB_LIB_DIR was set to {:?} but it does not exist",
                bb_lib_dir
            );
        }
        if let Some(root) = prebuilt_root.as_deref() {
            if !prebuilt_headers_present(root) {
                panic!(
                    "BB_LIB_DIR appears to point at a prebuilt package under {}, but include/include-deps/msgpack are incomplete",
                    root.display()
                );
            }
        }
        println!(
            "cargo:warning=Using BB_LIB_DIR={} (no build)",
            bb_lib_dir.display()
        );
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
                    prebuilt_root = Some(pb.root.clone());
                    using_downloaded_prebuilt = true;
                    println!(
                        "cargo:warning=Using prebuilt Barretenberg {} for {}",
                        ver, triple
                    );
                }
                Err(e) => {
                    if allow_fallback {
                        println!(
                            "cargo:warning=Prebuilt unavailable ({}); falling back to local build",
                            e
                        );
                    } else {
                        panic!("Failed to fetch prebuilt ({}). Set BB_PREBUILT_ALLOW_BUILD_FALLBACK=1 to build locally or set BB_LIB_DIR.", e);
                    }
                }
            }
        }
    }

    let use_local_build = env_bb_lib.is_none() && !using_downloaded_prebuilt;

    // When this crate owns the local BB build, always re-run configure+build so stale
    // CMake caches cannot silently drop RelWithDebInfo optimization flags.
    if use_local_build {
        println!(
            "cargo:warning=Ensuring local Barretenberg build at {}",
            bb_build_dir.display()
        );
        ensure_barretenberg_built(&bb_build_dir);
        bb_lib_dir = bb_build_dir.join("lib");
    } else if !built_lib_present(&bb_lib_dir) {
        if allow_fallback {
            println!(
                "cargo:warning=Barretenberg libs not found at {}; building locally…",
                bb_lib_dir.display()
            );
            ensure_barretenberg_built(&bb_build_dir);
            bb_lib_dir = bb_build_dir.join("lib");
            prebuilt_root = None;
        } else {
            panic!("Barretenberg libs not available and fallback disabled. Provide prebuilt (BB_USE_PREBUILT=1) or set BB_PREBUILT_ALLOW_BUILD_FALLBACK=1.");
        }
    }

    let local_metadata_build_dir = env_bb_lib
        .as_deref()
        .and_then(|p| p.parent())
        .filter(|p| p.join("_deps").exists())
        .unwrap_or(&bb_build_dir);
    let include_paths = prebuilt_root
        .as_deref()
        .map(prebuilt_include_paths)
        .unwrap_or_else(|| local_include_paths(&repo_root, local_metadata_build_dir));
    emit_include_metadata(&include_paths);

    // Rebuild if static archives change (or shim source if we build locally)
    println!(
        "cargo:rerun-if-changed={}",
        bb_lib_dir.join("libbb-external.a").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        bb_lib_dir.join("libbb_rust_api.a").display()
    );

    // bb_rust_api must come from the same Barretenberg build (or prebuilt package) as libbb-external.
    // Building a local shim against a different Barretenberg archive is unsafe (ABI/allocator mismatches).
    let shim_archive = bb_lib_dir.join("libbb_rust_api.a");

    if !shim_archive.exists() {
        panic!(
            "libbb_rust_api.a not found in {}. Provide a BB_LIB_DIR containing it, or enable local build fallback (BB_PREBUILT_ALLOW_BUILD_FALLBACK=1).",
            bb_lib_dir.display()
        );
    }
    if using_downloaded_prebuilt {
        println!(
            "cargo:warning=Using downloaded prebuilt bb_rust_api from {}",
            shim_archive.display()
        );
    } else {
        println!(
            "cargo:warning=Using local CMake-built bb_rust_api from {}",
            shim_archive.display()
        );
    }
    println!("cargo:rustc-link-lib=static=bb_rust_api");

    // Download CRS assets and generate the embedded module consumed via include_bytes!.
    ensure_crs_downloaded(&out_dir)
        .expect("failed to download CRS assets for embedded initialization");
    emit_embedded_crs_module(&out_dir).expect("failed to write embedded CRS module");

    // Link against the all-in-one static archive produced by 4.2.0 and the Usernode shim.
    println!("cargo:rustc-link-search=native={}", bb_lib_dir.display());
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    println!("cargo:rustc-link-lib=static=bb-external");

    // Math + pthread everywhere
    println!("cargo:rustc-link-lib=dylib=m");
    println!("cargo:rustc-link-lib=dylib=pthread");

    // Platform-specific C++ runtime
    if target_os == "macos" || target_os == "ios" {
        println!("cargo:rustc-link-lib=dylib=c++"); // libc++ on Apple (macOS/iOS)
    } else if target_os == "android" {
        // Android NDK's libc++
        println!("cargo:rustc-link-lib=dylib=c++_shared");
    } else {
        // Link libstdc++/libgcc dynamically on Linux (ensures symbols resolved)
        println!("cargo:rustc-link-lib=dylib=stdc++");
        println!("cargo:rustc-link-lib=dylib=gcc_s");
        println!("cargo:rustc-link-lib=dylib=dl");
    }
}
