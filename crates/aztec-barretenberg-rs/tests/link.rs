use aztec_barretenberg_rs as bb;

#[test]
fn link_and_init_crs() {
    bb::init_embedded_crs().expect("init CRS");
}
