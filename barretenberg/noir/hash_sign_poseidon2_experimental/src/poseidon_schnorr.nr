use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar, multi_scalar_mul};

// Minimal Poseidon2 sponge wrapper using the exposed permutation.
// Mirrors stdlib Poseidon2::hash for fixed-length inputs.
comptime global RATE: u32 = 3; // Poseidon2 sponge rate (capacity=1)

fn poseidon2_hash_fields<let N: u32>(input: [Field; N]) -> Field {
    // Initialize state with domain iv = (in_len << 64) + (out_len-1), here out_len=1
    let two_pow_64 = 18446744073709551616;
    let iv: Field = (N as Field) * two_pow_64;
    let mut state: [Field; 4] = [0; 4];
    state[RATE] = iv;
    // Local cache emulation
    let mut cache: [Field; RATE] = [0; RATE];
    let mut cache_size: u32 = 0;

    // Absorb all inputs (match C++ sponge absorb semantics)
    for i in 0..N {
        if cache_size == RATE {
            // compress current full cache
            for j in 0..RATE { state[j] += cache[j]; }
            state = std::hash::poseidon2_permutation(state, 4);
            // start new cache with current input
            for j in 0..RATE { cache[j] = 0; }
            cache[0] = input[i];
            cache_size = 1;
        } else {
            cache[cache_size] = input[i];
            cache_size += 1;
        }
    }
    // Squeeze: one duplex with zero-padded cache
    for j in 0..RATE {
        if j < cache_size { state[j] += cache[j]; }
    }
    state = std::hash::poseidon2_permutation(state, 4);
    state[0]
}

// Convert 32 bytes from signature (big-endian) into EmbeddedCurveScalar limbs (lo/hi as 128-bit each)
fn scalar_from_32(bytes: [u8; 32]) -> EmbeddedCurveScalar {
    let mut v: Field = 1;
    let mut lo: Field = 0;
    let mut hi: Field = 0;
    for i in 0..16 {
        lo = lo + (bytes[31 - i] as Field) * v;
        hi = hi + (bytes[15 - i] as Field) * v;
        v = v * 256;
    }
    EmbeddedCurveScalar::new(lo, hi)
}

// Compute challenge c = Poseidon2([R.x, Pk.x, Pk.y] || message_bytes)
fn compute_challenge(message: [u8; 256], R: EmbeddedCurvePoint, Pk: EmbeddedCurvePoint) -> [u8; 32] {
    // Construct field array: [R.x, Pk.x, Pk.y] followed by 8 field chunks of the 256-byte message (big-endian)
    let mut fields: [Field; 3 + 8] = [0; 3 + 8];
    fields[0] = R.x;
    fields[1] = Pk.x;
    fields[2] = Pk.y;
    for k in 0..8 {
        let mut acc: Field = 0;
        for j in 0..32 {
            let b = message[k * 32 + j] as Field;
            acc = acc * 256 + b;
        }
        fields[3 + k] = acc;
    }
    let c_f = poseidon2_hash_fields(fields);
    c_f.to_be_bytes()
}

pub fn challenge_for_inputs(message: [u8; 256], public_key: EmbeddedCurvePoint, signature: [u8; 64]) -> [u8; 32] {
    let mut s_bytes: [u8; 32] = [0; 32];
    let mut e_bytes: [u8; 32] = [0; 32];
    for i in 0..32 { s_bytes[i] = signature[i]; }
    for i in 0..32 { e_bytes[i] = signature[32 + i]; }
    let sig_s = scalar_from_32(s_bytes);
    let sig_e = scalar_from_32(e_bytes);
    let g1 = EmbeddedCurvePoint { x: 1, y: 17631683881184975370165255887551781615748388533673675138860, is_infinite: false };
    let reduced_sig_e = normalize_signature(sig_e);
    let R = multi_scalar_mul([g1, public_key], [sig_s, reduced_sig_e]);
    compute_challenge(message, R, public_key)
}

pub fn rx_for_inputs(_message: [u8; 256], public_key: EmbeddedCurvePoint, signature: [u8; 64]) -> Field {
    let mut s_bytes: [u8; 32] = [0; 32];
    let mut e_bytes: [u8; 32] = [0; 32];
    for i in 0..32 { s_bytes[i] = signature[i]; }
    for i in 0..32 { e_bytes[i] = signature[32 + i]; }
    let sig_s = scalar_from_32(s_bytes);
    let sig_e = scalar_from_32(e_bytes);
    let g1 = EmbeddedCurvePoint { x: 1, y: 17631683881184975370165255887551781615748388533673675138860, is_infinite: false };
    let reduced_sig_e = normalize_signature(sig_e);
    let R = multi_scalar_mul([g1, public_key], [sig_s, reduced_sig_e]);
    R.x
}

pub fn verify_signature(public_key: EmbeddedCurvePoint, signature: [u8; 64], message: [u8; 256]) -> bool {
    // Parse s and e from signature (each 32 bytes)
    let mut s_bytes: [u8; 32] = [0; 32];
    let mut e_bytes: [u8; 32] = [0; 32];
    for i in 0..32 { s_bytes[i] = signature[i]; }
    for i in 0..32 { e_bytes[i] = signature[32 + i]; }

    let sig_s = scalar_from_32(s_bytes);
    let sig_e = scalar_from_32(e_bytes);

    // Basic key checks
    let mut is_ok = (public_key.y * public_key.y == public_key.x * public_key.x * public_key.x - 17)
        & (!public_key.is_infinite);

    if ((sig_s.lo != 0) | (sig_s.hi != 0)) & ((sig_e.lo != 0) | (sig_e.hi != 0)) {
        // Reconstruct R' = s*G - e*Pk using multi-scalar mul [G, Pk] with [s, e]
        let g1 = EmbeddedCurvePoint { x: 1, y: 17631683881184975370165255887551781615748388533673675138860, is_infinite: false };
        let reduced_sig_e = normalize_signature(sig_e);
        let R = multi_scalar_mul([g1, public_key], [sig_s, reduced_sig_e]);

        // Compute Poseidon2-based challenge and compare to provided e
        let computed_e = compute_challenge(message, R, public_key);
        for i in 0..32 { is_ok &= computed_e[i] == e_bytes[i]; }
    } else {
        is_ok = false;
    }
    is_ok
}

// Helper functions copied/adapted from noir-lang/schnorr for signature normalization
unconstrained fn __gt(a: Field, b: Field) -> bool { b.lt(a) }

// the multiples of BN_P that are still less than 2^254 split into (lo, hi)
global BN_P_m: [(Field, Field); 6] = [
    (0, 0),
    (201385395114098847380338600778089168199, 64323764613183177041862057485226039389),
    (62488423307259231297302594124410124942, 128647529226366354083724114970452078779),
    (263873818421358078677641194902499293141, 192971293839549531125586172455678118168),
    (124976846614518462594605188248820249884, 257295058452732708167448229940904157558),
    (326362241728617309974943789026909418083, 321618823065915885209310287426130196947),
];
global TWO_POW_128: Field = 0x100000000000000000000000000000000;

unconstrained fn __get_quotient(hi: Field, lo: Field) -> u32 {
    let mut q: u32 = 0;
    let mut r_hi = hi;
    let mut r_lo = lo;
    let MODULUS = BN_P_m[1];
    for _ in 1..6 {
        let borrow = r_lo.lt(MODULUS.0);
        if borrow {
            r_lo = r_lo + TWO_POW_128;
            r_hi = r_hi - 1;
        }
        let MODULUS_hi = MODULUS.1;
        let gt_flag = !r_hi.lt(MODULUS_hi);
        if gt_flag {
            r_hi = r_hi - MODULUS.1;
            r_lo = r_lo - MODULUS.0;
            if TWO_POW_128.lt(r_lo) | TWO_POW_128.lt(r_hi) { break; }
            q += 1;
        }
    }
    q
}

fn normalize_signature(sig_e: EmbeddedCurveScalar) -> EmbeddedCurveScalar {
    let mut hi = sig_e.hi;
    let mut lo = sig_e.lo;
    // Safety: __get_quotient is a low-level arithmetic helper expected to be pure and
    // side-effect free for valid hi/lo; inputs are derived from field elements.
    let q = unsafe { __get_quotient(hi, lo) };
    let MODULUSmq = (BN_P_m[q].0, BN_P_m[q].1);
    let MODULUS = BN_P_m[1];
    // Safety: __gt compares two field limbs; used only for conditional subtract.
    let borrow = unsafe { __gt(MODULUSmq.0, lo) };
    let rlo = lo - MODULUSmq.0 + borrow as Field * TWO_POW_128;
    let rhi = hi - borrow as Field - MODULUSmq.1;
    rlo.assert_max_bit_size::<128>();
    rhi.assert_max_bit_size::<128>();
    // Safety: __gt is used for a constant-time comparison between limbs.
    let borrow2 = unsafe { __gt(rlo, MODULUS.0) };
    let rplo = MODULUS.0 - rlo + borrow2 as Field * TWO_POW_128;
    let rphi = MODULUS.1 - rhi - borrow2 as Field;
    rplo.assert_max_bit_size::<128>();
    rphi.assert_max_bit_size::<128>();
    EmbeddedCurveScalar::new(rlo, rhi)
}

// ========= Micro-tests for hashing parity =========

#[test]
fn test_poseidon2_sponge_fixed_64_bytes() {
    // bytes = 0..63, chunk into 2 fields BE, expect barretenberg value
    let mut bytes: [u8; 64] = [0; 64];
    for i in 0..64 { bytes[i] = i as u8; }
    let mut fields: [Field; 2] = [0; 2];
    for k in 0..2 {
        let mut acc: Field = 0;
        for j in 0..32 {
            acc = acc * 256 + bytes[k * 32 + j] as Field;
        }
        fields[k] = acc;
    }
    let h = poseidon2_hash_fields(fields);
    assert(h == 0x01d37d944b6372e66ba176f5eb16c373fbf906edd439befbc24c279a2ae144ef);
}

#[test]
fn test_pedersen_triplet_fixed() {
    // f1=0x42, f2=0xaa, f3=0x123, expect output from test vectors
    let f1: Field = 0x42;
    let f2: Field = 0xaa;
    let f3: Field = 0x123;
    let ped = std::hash::pedersen_hash([f1,f2,f3]);
    assert(ped == 0x0baba390d6faae1c400e0b8fb0b0ecccc927aff3ae4fb69325ae527189af325b);
}

#[test]
fn test_challenge_from_ped_and_zeros() {
    // pedersen digest from (f1,f2,f3) above as Field, then Poseidon2 over [ped_bytes || 256 zeros]
    let ped: Field = 0x0baba390d6faae1c400e0b8fb0b0ecccc927aff3ae4fb69325ae527189af325b;
    let ped_bytes: [u8; 32] = ped.to_be_bytes();
    let mut preimage: [u8; 288] = [0; 288];
    for i in 0..32 { preimage[i] = ped_bytes[i]; }
    let mut fields: [Field; 9] = [0; 9];
    for k in 0..9 {
        let mut acc: Field = 0;
        for j in 0..32 {
            acc = acc * 256 + preimage[k * 32 + j] as Field;
        }
        fields[k] = acc;
    }
    let h = poseidon2_hash_fields(fields);
    assert(h == 0x2ef482ab317ba8bfaffa87c83845709b8872a01f70408bab023b5a19892b3316);
}
