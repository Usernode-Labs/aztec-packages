use aztec_barretenberg_rs as bb;

#[test]
fn link_and_init_crs() {
    // This should succeed even with an empty path; bb will try net CRS or no-op.
    let _ = bb::set_crs_path("");
}

