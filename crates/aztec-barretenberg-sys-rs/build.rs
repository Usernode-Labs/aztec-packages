use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    // Compile shim and link against prebuilt barretenberg static library.
    let crate_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let repo_root = crate_dir.parent().unwrap().parent().unwrap();
    let bb_cpp_src = repo_root.join("barretenberg/cpp/src");
    let bb_lib_dir = repo_root.join("barretenberg/cpp/build/lib");
    // Ensure we rebuild if the shim changes.
    println!(
        "cargo:rerun-if-changed={}",
        bb_cpp_src.join("bb_rust_api.cpp").display()
    );
    assert!(bb_lib_dir.exists(), "Expected prebuilt barretenberg at {:?}", bb_lib_dir);

    cc::Build::new()
        .cpp(true)
        .flag("-std=c++20")
        .flag("-fPIC")
        .flag("-Wno-error")
        .flag_if_supported("-Wno-unused-parameter")
        .include(&bb_cpp_src)
        .include(repo_root.join("barretenberg/cpp/build/_deps/msgpack-c/src/msgpack-c/include"))
        .include(repo_root.join("barretenberg/cpp/build/_deps/tracy-src/public"))
        .file(bb_cpp_src.join("bb_rust_api.cpp"))
        .compile("bb_rust_api");

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
    // Math lib
    println!("cargo:rustc-link-lib=dylib=m");
    // Standard dependencies
    println!("cargo:rustc-link-lib=dylib=stdc++");
    println!("cargo:rustc-link-lib=dylib=pthread");
    println!("cargo:rustc-link-lib=dylib=dl");
}
