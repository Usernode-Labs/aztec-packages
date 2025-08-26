// Trivial circuit to generate ACIR bytecode + witness
fn main() {
    // Simple constraints without inputs to avoid Prover.toml
    let x: Field = 3;
    let y: Field = 5;
    assert(x + y == 8);
    assert(x * 2 == x + x);
}
