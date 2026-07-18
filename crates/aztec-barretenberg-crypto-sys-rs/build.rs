use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const CRYPTO_EXTERNAL_ARCHIVE: &str = "libbb-crypto-external.a";
const CRYPTO_SHIM_ARCHIVE: &str = "libbb_rust_crypto_api.a";

fn cmd_exists(name: &str) -> bool {
    Command::new(name)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn run(mut command: Command) {
    let status = command.status().expect("failed to spawn command");
    if !status.success() {
        panic!("command failed: {command:?}");
    }
}

fn read_text(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| {
        panic!("failed to read {}: {error}", path.display());
    })
}

fn repo_root() -> PathBuf {
    PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set"))
        .parent()
        .expect("crate parent")
        .parent()
        .expect("repository root")
        .to_path_buf()
}

fn default_build_dir(repo_root: &Path) -> PathBuf {
    let mac = repo_root.join("barretenberg/cpp/build-macos");
    if mac.exists() {
        mac
    } else {
        repo_root.join("barretenberg/cpp/build")
    }
}

fn compiler_slug(compiler: &str) -> String {
    let name = Path::new(compiler)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(compiler);
    name.chars()
        .map(|value| {
            if value.is_ascii_alphanumeric() {
                value
            } else {
                '-'
            }
        })
        .collect()
}

fn build_dir_for_compilers(repo_root: &Path, cc: Option<&str>, cxx: Option<&str>) -> PathBuf {
    if cc.is_none() && cxx.is_none() {
        return default_build_dir(repo_root);
    }

    repo_root.join("barretenberg/cpp").join(format!(
        "build-rs-{}-{}",
        cc.map(compiler_slug)
            .unwrap_or_else(|| "default".to_owned()),
        cxx.map(compiler_slug)
            .unwrap_or_else(|| "default".to_owned())
    ))
}

fn infer_llvm_tool_from_compiler(compiler: &str, tool_name: &str) -> Option<String> {
    let candidate = Path::new(compiler).parent()?.join(tool_name);
    candidate
        .exists()
        .then(|| candidate.to_string_lossy().into_owned())
}

fn crypto_archives_present(lib_dir: &Path) -> bool {
    lib_dir.join(CRYPTO_EXTERNAL_ARCHIVE).is_file() && lib_dir.join(CRYPTO_SHIM_ARCHIVE).is_file()
}

fn validate_relwithdebinfo_flags(build_dir: &Path) {
    let cache_path = build_dir.join("CMakeCache.txt");
    let cache = read_text(&cache_path);
    for variable in [
        "CMAKE_C_FLAGS_RELWITHDEBINFO",
        "CMAKE_CXX_FLAGS_RELWITHDEBINFO",
    ] {
        let prefix = format!("{variable}:STRING=");
        let actual = cache
            .lines()
            .find_map(|line| line.strip_prefix(&prefix))
            .unwrap_or_else(|| panic!("missing {variable} in {}", cache_path.display()));
        assert_eq!(
            actual,
            "-O2 -g -DNDEBUG",
            "unexpected {variable} in {}",
            cache_path.display()
        );
    }
}

fn target_triple() -> String {
    if let Ok(target) = env::var("TARGET") {
        match target.as_str() {
            "x86_64-unknown-linux-gnu"
            | "aarch64-unknown-linux-gnu"
            | "x86_64-linux-android"
            | "aarch64-apple-darwin"
            | "aarch64-apple-ios-sim"
            | "aarch64-apple-ios"
            | "aarch64-linux-android" => return target,
            _ => {}
        }
    }

    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    match (arch.as_str(), os.as_str()) {
        ("x86_64", "linux") => "x86_64-unknown-linux-gnu".to_owned(),
        ("aarch64", "linux") => "aarch64-unknown-linux-gnu".to_owned(),
        ("aarch64", "macos") => "aarch64-apple-darwin".to_owned(),
        ("aarch64", "ios") => "aarch64-apple-ios-sim".to_owned(),
        ("x86_64", "android") => "x86_64-linux-android".to_owned(),
        ("aarch64", "android") => "aarch64-linux-android".to_owned(),
        _ => String::new(),
    }
}

fn crate_version_tag() -> String {
    format!(
        "v{}",
        env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION set")
    )
}

fn prebuilt_cache_dir() -> PathBuf {
    env::var_os("BB_PREBUILT_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo_root().join("target/bb-prebuilt"))
}

fn prebuilt_base_url() -> String {
    env::var("BB_PREBUILT_BASE_URL")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "https://github.com/Usernode-Labs/aztec-packages/releases".to_owned())
}

fn ensure_parent(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn download_with(command: &str, url: &str, destination: &Path) -> io::Result<bool> {
    ensure_parent(destination)?;
    let status = match command {
        "curl" => Command::new("curl")
            .arg("-fL")
            .arg(url)
            .arg("-o")
            .arg(destination)
            .status(),
        "wget" => Command::new("wget")
            .arg("-qO")
            .arg(destination)
            .arg(url)
            .status(),
        _ => return Ok(false),
    }?;
    Ok(status.success())
}

fn download(url: &str, destination: &Path) -> io::Result<()> {
    if cmd_exists("curl") && download_with("curl", url, destination)? {
        return Ok(());
    }
    if cmd_exists("wget") && download_with("wget", url, destination)? {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "failed to download {url} (need curl or wget)"
    )))
}

fn extract_tar_gz(archive: &Path, destination: &Path) -> io::Result<()> {
    fs::create_dir_all(destination)?;
    let status = Command::new("tar")
        .arg("-xzf")
        .arg(archive)
        .arg("-C")
        .arg(destination)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other("tar extraction failed"))
    }
}

fn fetch_prebuilt(version: &str, target: &str) -> io::Result<PathBuf> {
    let root = prebuilt_cache_dir().join(version).join(target);
    let lib_dir = root.join("lib");
    if crypto_archives_present(&lib_dir) {
        return Ok(lib_dir);
    }

    fs::create_dir_all(&root)?;
    let asset = format!("barretenberg-crypto-{version}-{target}.tar.gz");
    let url = format!("{}/download/{version}/{asset}", prebuilt_base_url());
    let archive = root.join(&asset);
    println!("cargo:warning=Downloading prebuilt Barretenberg crypto: {url}");
    download(&url, &archive)?;
    extract_tar_gz(&archive, &root)?;
    if crypto_archives_present(&lib_dir) {
        Ok(lib_dir)
    } else {
        Err(io::Error::other(format!(
            "prebuilt archive missing {CRYPTO_EXTERNAL_ARCHIVE} or {CRYPTO_SHIM_ARCHIVE}"
        )))
    }
}

fn configure_and_build(repo_root: &Path, build_dir: &Path) {
    let cpp = repo_root.join("barretenberg/cpp");
    let mut configure = Command::new("cmake");
    configure
        .current_dir(&cpp)
        .arg("-S")
        .arg(".")
        .arg("-B")
        .arg(build_dir)
        .arg("-DCMAKE_BUILD_TYPE=RelWithDebInfo")
        .arg("-DCMAKE_C_FLAGS_RELWITHDEBINFO=-O2 -g -DNDEBUG")
        .arg("-DCMAKE_CXX_FLAGS_RELWITHDEBINFO=-O2 -g -DNDEBUG")
        .arg("-DCMAKE_POSITION_INDEPENDENT_CODE=ON")
        .arg("-DDISABLE_AZTEC_VM=ON")
        .arg("-DENABLE_TRACY=OFF")
        .arg("-DBB_BUILD_TRANSLATOR_VM=ON")
        .arg("-DBB_BUILD_NODEJS_MODULE=OFF")
        .arg("-DBB_ENABLE_BENCH=OFF")
        .arg("-DBB_ENABLE_TESTS=OFF");

    for (environment, cmake) in [
        ("CC", "CMAKE_C_COMPILER"),
        ("CXX", "CMAKE_CXX_COMPILER"),
        ("AR", "CMAKE_AR"),
        ("RANLIB", "CMAKE_RANLIB"),
    ] {
        if let Ok(value) = env::var(environment) {
            if !value.is_empty() {
                configure.arg(format!("-D{cmake}={value}"));
            }
        }
    }

    if env::var_os("AR").is_none() {
        if let Ok(cxx) = env::var("CXX") {
            if let Some(ar) = infer_llvm_tool_from_compiler(&cxx, "llvm-ar") {
                configure.arg(format!("-DCMAKE_AR={ar}"));
            }
        }
    }
    if env::var_os("RANLIB").is_none() {
        if let Ok(cxx) = env::var("CXX") {
            if let Some(ranlib) = infer_llvm_tool_from_compiler(&cxx, "llvm-ranlib") {
                configure.arg(format!("-DCMAKE_RANLIB={ranlib}"));
            }
        }
    }
    if cmd_exists("ninja") {
        configure.arg("-GNinja");
    }
    run(configure);
    validate_relwithdebinfo_flags(build_dir);

    let mut build = Command::new("cmake");
    build
        .current_dir(&cpp)
        .arg("--build")
        .arg(build_dir)
        .arg("--target")
        .arg("bb-crypto-external")
        .arg("--target")
        .arg("bb_rust_crypto_api");
    run(build);
}

fn emit_platform_links() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    println!("cargo:rustc-link-lib=dylib=m");
    println!("cargo:rustc-link-lib=dylib=pthread");
    if target_os == "macos" || target_os == "ios" {
        println!("cargo:rustc-link-lib=dylib=c++");
    } else if target_os == "android" {
        println!("cargo:rustc-link-lib=dylib=c++_shared");
    } else {
        println!("cargo:rustc-link-lib=dylib=stdc++");
        println!("cargo:rustc-link-lib=dylib=gcc_s");
        println!("cargo:rustc-link-lib=dylib=dl");
    }
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    for variable in [
        "BB_BUILD_DIR",
        "BB_LIB_DIR",
        "BB_USE_PREBUILT",
        "BB_PREBUILT_VERSION",
        "BB_PREBUILT_BASE_URL",
        "BB_PREBUILT_ALLOW_BUILD_FALLBACK",
        "BB_PREBUILT_CACHE_DIR",
        "CC",
        "CXX",
        "AR",
        "RANLIB",
    ] {
        println!("cargo:rerun-if-env-changed={variable}");
    }

    let repo_root = repo_root();
    let cc = env::var("CC").ok();
    let cxx = env::var("CXX").ok();
    let build_dir = env::var_os("BB_BUILD_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| build_dir_for_compilers(&repo_root, cc.as_deref(), cxx.as_deref()));
    let explicit_lib_dir = env::var_os("BB_LIB_DIR").map(PathBuf::from);
    let use_prebuilt = env::var("BB_USE_PREBUILT")
        .ok()
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(true);
    let allow_fallback = env::var("BB_PREBUILT_ALLOW_BUILD_FALLBACK")
        .ok()
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let (lib_dir, archive_source) = if let Some(lib_dir) = explicit_lib_dir {
        if !crypto_archives_present(&lib_dir) {
            panic!(
                "BB_LIB_DIR={} is missing split Barretenberg crypto archives; full consumers must extract both crypto and prover assets into the same directory",
                lib_dir.display()
            );
        }
        (lib_dir, "explicit")
    } else if use_prebuilt {
        let version = env::var("BB_PREBUILT_VERSION").unwrap_or_else(|_| crate_version_tag());
        let target = target_triple();
        if target.is_empty() {
            if !allow_fallback {
                panic!("no Barretenberg crypto prebuilt for this target and fallback is disabled");
            }
            configure_and_build(&repo_root, &build_dir);
            (build_dir.join("lib"), "local")
        } else {
            match fetch_prebuilt(&version, &target) {
                Ok(lib_dir) => (lib_dir, "prebuilt"),
                Err(error) if allow_fallback => {
                    println!(
                        "cargo:warning=Crypto prebuilt unavailable ({error}); building locally"
                    );
                    configure_and_build(&repo_root, &build_dir);
                    (build_dir.join("lib"), "local")
                }
                Err(error) => panic!(
                    "failed to fetch Barretenberg crypto prebuilt ({error}); set BB_PREBUILT_ALLOW_BUILD_FALLBACK=1 to build locally"
                ),
            }
        }
    } else {
        configure_and_build(&repo_root, &build_dir);
        (build_dir.join("lib"), "local")
    };

    if !crypto_archives_present(&lib_dir) {
        panic!(
            "split Barretenberg crypto archives not found in {}",
            lib_dir.display()
        );
    }
    println!(
        "cargo:rerun-if-changed={}",
        lib_dir.join(CRYPTO_EXTERNAL_ARCHIVE).display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        lib_dir.join(CRYPTO_SHIM_ARCHIVE).display()
    );
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=bb_rust_crypto_api");
    println!("cargo:rustc-link-lib=static=bb-crypto-external");
    println!("cargo:lib_dir={}", lib_dir.display());
    println!("cargo:archive_source={archive_source}");
    emit_platform_links();
}
