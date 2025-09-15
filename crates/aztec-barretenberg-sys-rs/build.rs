use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    // Compile shim and link against prebuilt barretenberg static library.
    let crate_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let repo_root = crate_dir.parent().unwrap().parent().unwrap();
    let bb_cpp_src = repo_root.join("barretenberg/cpp/src");
    // Allow overriding build and lib dirs via env for external/prebuilt setups
    let bb_build_dir = std::env::var_os("BB_BUILD_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo_root.join("barretenberg/cpp/build"));
    let bb_lib_dir = std::env::var_os("BB_LIB_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| bb_build_dir.join("lib"));
    // Ensure we rebuild if the shim changes.
    println!(
        "cargo:rerun-if-changed={}",
        bb_cpp_src.join("bb_rust_api.cpp").display()
    );
    // Also rerun if the prebuilt static archive changes (to relink against latest C++ code).
    println!(
        "cargo:rerun-if-changed={}",
        bb_lib_dir.join("libbarretenberg.a").display()
    );
    assert!(bb_lib_dir.exists(), "Expected prebuilt barretenberg at {:?}", bb_lib_dir);

    let mut cc_build = cc::Build::new();
    cc_build
        .cpp(true)
        .flag("-std=c++20")
        .flag("-fPIC")
        .flag("-Wno-error")
        .flag_if_supported("-Wno-unused-parameter")
        // Enable ASan for shim if requested via env SANITIZE=address
        .flag_if_supported(if env::var("SANITIZE").ok().as_deref() == Some("address") { "-fsanitize=address" } else { "" })
        .flag_if_supported(if env::var("SANITIZE").ok().as_deref() == Some("address") { "-fno-omit-frame-pointer" } else { "" })
        .include(&bb_cpp_src)
        .include(bb_build_dir.join("_deps/msgpack-c/src/msgpack-c/include"))
        .include(bb_build_dir.join("_deps/tracy-src/public"))
        .file(bb_cpp_src.join("bb_rust_api.cpp"));
    cc_build.compile("bb_rust_api");

    println!("cargo:rustc-link-search=native={}", bb_lib_dir.display());
    // Group static libs to resolve circular deps in C++ archives
    println!("cargo:rustc-link-arg=-Wl,--start-group");
    println!("cargo:rustc-link-lib=static=barretenberg");
    println!("cargo:rustc-link-lib=static=env");
    // Additional components referenced directly from the shim
    println!("cargo:rustc-link-lib=static=crypto_pedersen_commitment");
    println!("cargo:rustc-link-lib=static=crypto_pedersen_hash");
    println!("cargo:rustc-link-lib=static=crypto_poseidon2");
    println!("cargo:rustc-link-lib=static=ecc");
    println!("cargo:rustc-link-lib=static=crypto_schnorr");
    println!("cargo:rustc-link-arg=-Wl,--end-group");
    // If ASan is requested, link the sanitizer runtime
    if env::var("SANITIZE").ok().as_deref() == Some("address") {
        println!("cargo:rustc-link-lib=asan");
    }
    // Math lib
    println!("cargo:rustc-link-lib=dylib=m");
    // Standard dependencies
    println!("cargo:rustc-link-lib=dylib=stdc++");
    println!("cargo:rustc-link-lib=dylib=pthread");
    println!("cargo:rustc-link-lib=dylib=dl");
}
