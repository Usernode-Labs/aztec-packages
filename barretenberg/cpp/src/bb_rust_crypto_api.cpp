#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "bb_rust_api_internal.hpp"

#include "barretenberg/crypto/blake2s/blake2s.hpp"
#include "barretenberg/crypto/hmac/hmac.hpp"
#include "barretenberg/crypto/pedersen_hash/pedersen.hpp"
#include "barretenberg/crypto/poseidon2/poseidon2.hpp"
#include "barretenberg/crypto/poseidon2/poseidon2_params.hpp"
#include "barretenberg/crypto/poseidon2/poseidon2_permutation.hpp"
#include "barretenberg/ecc/curves/grumpkin/grumpkin.hpp"

extern "C" {

static inline uint256_t be32_to_uint256(const uint8_t in_be[32])
{
    uint64_t limbs[4];
    be32_to_le_limbs(in_be, limbs);
    return uint256_t(limbs[0], limbs[1], limbs[2], limbs[3]);
}

static inline void uint256_to_be32(const uint256_t& value, uint8_t out_be[32])
{
    le_limbs_to_be32(value.data, out_be);
}

static inline bb::grumpkin::g1::affine_element grumpkin_affine_from_xy(const uint8_t* xbe, const uint8_t* ybe)
{
    uint64_t xl[4];
    uint64_t yl[4];
    be32_to_le_limbs(xbe, xl);
    be32_to_le_limbs(ybe, yl);
    bb::grumpkin::fq x(xl[0], xl[1], xl[2], xl[3]);
    bb::grumpkin::fq y(yl[0], yl[1], yl[2], yl[3]);
    return bb::grumpkin::g1::affine_element(x.to_montgomery_form(), y.to_montgomery_form());
}

// Poseidon2 permutation over BN254 Fr; len must be 4.
int bb_poseidon2_permutation_bn254(const uint8_t* inputs_be, size_t element_count, uint8_t** out_be, size_t* out_len)
{
    try {
        if (element_count != 4) {
            return 2;
        }
        using Params = bb::crypto::Poseidon2Bn254ScalarFieldParams;
        bb::fr state[4];
        for (size_t i = 0; i < 4; ++i) {
            uint64_t limbs[4];
            be32_to_le_limbs(inputs_be + i * 32, limbs);
            bb::fr v(limbs[0], limbs[1], limbs[2], limbs[3]);
            state[i] = v.to_montgomery_form();
        }
        using PP = bb::crypto::Poseidon2Permutation<Params>;
        typename PP::State s{ state[0], state[1], state[2], state[3] };
        auto out_state = PP::permutation(s);
        std::vector<uint8_t> out;
        out.resize(4 * 32);
        for (size_t i = 0; i < 4; ++i) {
            auto norm = out_state[i].from_montgomery_form();
            le_limbs_to_be32(norm.data, out.data() + i * 32);
        }
        if (out_be)
            *out_be = bb_malloc_copy(out);
        if (out_len)
            *out_len = out.size();
        return 0;
    } catch (...) {
        return 1;
    }
}

int bb_grumpkin_ec_add(const uint8_t pk1_x_be[32],
                       const uint8_t pk1_y_be[32],
                       const uint8_t pk2_x_be[32],
                       const uint8_t pk2_y_be[32],
                       uint8_t out_x_be[32],
                       uint8_t out_y_be[32])
{
    try {
        auto A = grumpkin_affine_from_xy(pk1_x_be, pk1_y_be);
        auto B = grumpkin_affine_from_xy(pk2_x_be, pk2_y_be);
        if (!A.on_curve() || !B.on_curve() || A.is_point_at_infinity() || B.is_point_at_infinity()) {
            return 2;
        }
        bb::grumpkin::g1::element eA(A);
        bb::grumpkin::g1::element eB(B);
        auto S = eA + eB;
        bb::grumpkin::g1::affine_element R(S);
        if (R.is_point_at_infinity()) {
            std::fill(out_x_be, out_x_be + 32, 0);
            std::fill(out_y_be, out_y_be + 32, 0);
            return 0;
        }
        auto nx = R.x.from_montgomery_form();
        auto ny = R.y.from_montgomery_form();
        le_limbs_to_be32(nx.data, out_x_be);
        le_limbs_to_be32(ny.data, out_y_be);
        return 0;
    } catch (...) {
        return 1;
    }
}

int bb_grumpkin_compress(const uint8_t pk_x_be[32], const uint8_t pk_y_be[32], uint8_t out_comp_be[32])
{
    try {
        auto P = grumpkin_affine_from_xy(pk_x_be, pk_y_be);
        if (!P.on_curve() || P.is_point_at_infinity()) {
            return 2;
        }
        uint256_t compressed(P.x);
        if (uint256_t(P.y).get_bit(0)) {
            compressed.data[3] |= bb::group_elements::UINT256_TOP_LIMB_MSB;
        }
        uint256_to_be32(compressed, out_comp_be);
        return 0;
    } catch (...) {
        return 1;
    }
}

int bb_grumpkin_decompress(const uint8_t comp_be[32], uint8_t out_x_be[32], uint8_t out_y_be[32])
{
    try {
        auto compressed = be32_to_uint256(comp_be);
        auto P = bb::grumpkin::g1::affine_element::from_compressed(compressed);
        if (!P.on_curve() || P.is_point_at_infinity()) {
            return 2;
        }
        auto nx = P.x.from_montgomery_form();
        auto ny = P.y.from_montgomery_form();
        le_limbs_to_be32(nx.data, out_x_be);
        le_limbs_to_be32(ny.data, out_y_be);
        return 0;
    } catch (...) {
        return 1;
    }
}

// Multi-scalar multiplication on grumpkin: sum_i (scalar_i * P_i)
// Inputs:
//  - xs_be, ys_be: n_points * 32 bytes big-endian field elements (grumpkin fq) for point coordinates
//  - inf_flags: n_points bytes, 0 = finite, 1 = point at infinity
//  - scalars_lo_be, scalars_hi_be: n_points * 16 bytes big-endian limbs for the low/high 128 bits of the scalar
// Output:
//  - out_x_be, out_y_be: 32-byte big-endian coordinates of result (0,0) if infinity
//  - out_infinite: set to 1 if result is infinity, 0 otherwise
int bb_grumpkin_msm(const uint8_t* xs_be,
                    const uint8_t* ys_be,
                    const uint8_t* inf_flags,
                    size_t n_points,
                    const uint8_t* scalars_lo_be,
                    const uint8_t* scalars_hi_be,
                    uint8_t out_x_be[32],
                    uint8_t out_y_be[32],
                    uint8_t* out_infinite)
{
    try {
        bb::grumpkin::g1::element acc = bb::grumpkin::g1::element::zero();
        for (size_t i = 0; i < n_points; ++i) {
            bool is_inf = inf_flags[i] != 0;
            bb::grumpkin::g1::affine_element P;
            if (is_inf) {
                P = bb::grumpkin::g1::affine_element::infinity();
            } else {
                uint64_t xl[4], yl[4];
                be32_to_le_limbs(xs_be + i * 32, xl);
                be32_to_le_limbs(ys_be + i * 32, yl);
                bb::grumpkin::fq x(xl[0], xl[1], xl[2], xl[3]);
                bb::grumpkin::fq y(yl[0], yl[1], yl[2], yl[3]);
                P = bb::grumpkin::g1::affine_element(x.to_montgomery_form(), y.to_montgomery_form());
                if (!P.on_curve()) {
                    return 2;
                }
            }

            // Combine high and low 128-bit limbs (big-endian) into 32 bytes
            uint8_t scalar_be[32];
            std::memcpy(scalar_be, scalars_hi_be + i * 16, 16);
            std::memcpy(scalar_be + 16, scalars_lo_be + i * 16, 16);

            // Reduce to grumpkin::fr
            // Interpret as big-endian integer modulo r
            // barretenberg fr has constructor from 4 limbs (little-endian 64-bit limbs)
            // Convert 32-be into 4 le64 limbs
            uint64_t fr_limbs[4] = { 0, 0, 0, 0 };
            // scalar_be is big-endian; convert to 4 little-endian 64-bit limbs
            for (size_t limb = 0; limb < 4; ++limb) {
                uint64_t v = 0;
                for (size_t j = 0; j < 8; ++j) {
                    v = (v << 8) | scalar_be[limb * 8 + j];
                }
                // limbs are big-endian order in scalar_be; reverse into little-endian order
                fr_limbs[3 - limb] = v;
            }
            bb::grumpkin::fr s(fr_limbs[0], fr_limbs[1], fr_limbs[2], fr_limbs[3]);
            s = s.to_montgomery_form();

            bb::grumpkin::g1::element eP(P);
            bb::grumpkin::g1::element term = eP * s;
            acc = acc + term;
        }

        bb::grumpkin::g1::affine_element R(acc);
        if (R.is_point_at_infinity()) {
            if (out_infinite)
                *out_infinite = 1;
            std::memset(out_x_be, 0, 32);
            std::memset(out_y_be, 0, 32);
        } else {
            auto nx = R.x.from_montgomery_form();
            auto ny = R.y.from_montgomery_form();
            le_limbs_to_be32(nx.data, out_x_be);
            le_limbs_to_be32(ny.data, out_y_be);
            if (out_infinite)
                *out_infinite = 0;
        }
        return 0;
    } catch (...) {
        return 1;
    }
}

// Hash-to-curve mapping for Grumpkin.
// Map a sequence of 32‑byte big-endian base-field elements to a Grumpkin point
// using a domain-separated Pedersen commit. When a native hash_to_curve is
// available, this function can delegate to it.
int bb_grumpkin_hash_to_curve(
    const uint8_t* inputs_be, size_t n_elems, uint32_t domain, uint8_t out_x_be[32], uint8_t out_y_be[32])
{
    try {
        // Domain-separated seed: BE(domain) || inputs_be (concatenated)
        const size_t len = n_elems * 32;
        std::vector<uint8_t> seed(4 + len);
        seed[0] = static_cast<uint8_t>((domain >> 24) & 0xff);
        seed[1] = static_cast<uint8_t>((domain >> 16) & 0xff);
        seed[2] = static_cast<uint8_t>((domain >> 8) & 0xff);
        seed[3] = static_cast<uint8_t>(domain & 0xff);
        if (inputs_be && len > 0) {
            std::memcpy(seed.data() + 4, inputs_be, len);
        }

        // Use native grumpkin hash_to_curve (blake3s-based, with retry via attempt counter)
        auto P = bb::grumpkin::g1::affine_element::hash_to_curve(seed);
        auto nx = P.x.from_montgomery_form();
        auto ny = P.y.from_montgomery_form();
        le_limbs_to_be32(nx.data, out_x_be);
        le_limbs_to_be32(ny.data, out_y_be);
        return 0;
    } catch (...) {
        return 1;
    }
}

void bb_free(uint8_t* ptr)
{
    std::free(ptr);
}

} // extern "C"

namespace {

using GrumpkinAffine = bb::grumpkin::g1::affine_element;

std::array<uint8_t, 32> legacy_schnorr_blake2s_challenge(const uint8_t* msg,
                                                         size_t msg_len,
                                                         const GrumpkinAffine& public_key,
                                                         const GrumpkinAffine& nonce)
{
    // Keep the pre-v5 Usernode Schnorr challenge exactly as it was:
    // Blake2s(serialize(Pedersen(R.x, public_key.x, public_key.y)) || message).
    // Barretenberg v5 changed its native Schnorr protocol to Poseidon2 over a
    // field element, which is intentionally not wire-compatible with this API.
    auto compressed_keys = bb::crypto::pedersen_hash::hash({ nonce.x, public_key.x, public_key.y });
    std::vector<uint8_t> challenge_input(32);
    decltype(compressed_keys)::serialize_to_buffer(compressed_keys, challenge_input.data());
    if (msg_len != 0) {
        challenge_input.insert(challenge_input.end(), msg, msg + msg_len);
    }
    return bb::crypto::blake2s(challenge_input);
}

} // namespace

extern "C" {
int bb_grumpkin_derive_pubkey(const uint8_t sk32[32], uint8_t out_x_be[32], uint8_t out_y_be[32])
{
    try {
        uint64_t sl[4];
        be32_to_le_limbs(sk32, sl);
        bb::grumpkin::fr sk(sl[0], sl[1], sl[2], sl[3]);
        sk = sk.to_montgomery_form();
        bb::grumpkin::g1::affine_element pk =
            bb::grumpkin::g1::element(bb::grumpkin::g1::one).mul_const_time(sk).to_affine_const_time();
        auto nx = pk.x.from_montgomery_form();
        auto ny = pk.y.from_montgomery_form();
        le_limbs_to_be32(nx.data, out_x_be);
        le_limbs_to_be32(ny.data, out_y_be);
        return 0;
    } catch (...) {
        return 1;
    }
}

int bb_schnorr_blake2s_sign(const uint8_t* msg, size_t msg_len, const uint8_t* sk32, uint8_t sig64_out[64])
{
    try {
        if ((msg == nullptr && msg_len != 0) || sk32 == nullptr || sig64_out == nullptr) {
            return 2;
        }
        uint64_t sl[4];
        be32_to_le_limbs(sk32, sl);
        bb::grumpkin::fr sk(sl[0], sl[1], sl[2], sl[3]);
        sk = sk.to_montgomery_form();
        GrumpkinAffine public_key =
            bb::grumpkin::g1::element(bb::grumpkin::g1::one).mul_const_time(sk).to_affine_const_time();

        bb::grumpkin::fr nonce_scalar = bb::grumpkin::fr::random_element();
        GrumpkinAffine nonce =
            bb::grumpkin::g1::element(bb::grumpkin::g1::one).mul_const_time(nonce_scalar).to_affine_const_time();
        auto challenge_bytes = legacy_schnorr_blake2s_challenge(msg, msg_len, public_key, nonce);
        bb::grumpkin::fr challenge = bb::grumpkin::fr::serialize_from_buffer(challenge_bytes.data());
        bb::grumpkin::fr response = nonce_scalar - (sk * challenge);
        bb::crypto::secure_erase_bytes(&nonce_scalar, sizeof(nonce_scalar));

        bb::grumpkin::fr::serialize_to_buffer(response, sig64_out);
        std::copy(challenge_bytes.begin(), challenge_bytes.end(), sig64_out + 32);
        return 0;
    } catch (...) {
        return 1;
    }
}

int bb_schnorr_blake2s_verify_xy(const uint8_t* msg,
                                 size_t msg_len,
                                 const uint8_t sig64[64],
                                 const uint8_t pkx32[32],
                                 const uint8_t pky32[32],
                                 bool* out_ok)
{
    try {
        if ((msg == nullptr && msg_len != 0) || sig64 == nullptr || pkx32 == nullptr || pky32 == nullptr) {
            return 2;
        }
        uint64_t xl[4], yl[4];
        be32_to_le_limbs(pkx32, xl);
        be32_to_le_limbs(pky32, yl);
        bb::grumpkin::fq x(xl[0], xl[1], xl[2], xl[3]);
        bb::grumpkin::fq y(yl[0], yl[1], yl[2], yl[3]);
        GrumpkinAffine public_key(x.to_montgomery_form(), y.to_montgomery_form());
        if (!public_key.on_curve() || public_key.is_point_at_infinity()) {
            if (out_ok != nullptr) {
                *out_ok = false;
            }
            return 0;
        }

        bb::grumpkin::fr response = bb::grumpkin::fr::serialize_from_buffer(sig64);
        bb::grumpkin::fr challenge = bb::grumpkin::fr::serialize_from_buffer(sig64 + 32);
        if (response == 0 || challenge == 0) {
            if (out_ok != nullptr) {
                *out_ok = false;
            }
            return 0;
        }

        GrumpkinAffine nonce(bb::grumpkin::g1::element(public_key) * challenge + bb::grumpkin::g1::one * response);
        bool ok = false;
        if (!nonce.is_point_at_infinity()) {
            auto expected_challenge = legacy_schnorr_blake2s_challenge(msg, msg_len, public_key, nonce);
            ok = std::equal(expected_challenge.begin(), expected_challenge.end(), sig64 + 32);
        }
        if (out_ok != nullptr) {
            *out_ok = ok;
        }
        return 0;
    } catch (...) {
        return 1;
    }
}
}
