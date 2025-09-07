#include <cstdint>
#include <cstdlib>
#include <memory>
#include <vector>
#include <filesystem>

#include "barretenberg/common/serialize.hpp"
#include "barretenberg/common/throw_or_abort.hpp"
#include "barretenberg/dsl/acir_format/acir_format.hpp"
#include "barretenberg/dsl/acir_format/acir_to_constraint_buf.hpp"
#include "barretenberg/merge/merge_mega.hpp"
#include "barretenberg/srs/global_crs.hpp"
#include "barretenberg/ultra_honk/decider_proving_key.hpp"
#include "barretenberg/stdlib_circuit_builders/mega_circuit_builder.hpp"
#include "barretenberg/honk/proof_system/types/proof.hpp"
#include "barretenberg/ultra_honk/ultra_prover.hpp"
#include "barretenberg/ultra_honk/ultra_verifier.hpp"
#include "barretenberg/crypto/poseidon2/poseidon2_permutation.hpp"
#include "barretenberg/crypto/poseidon2/poseidon2_params.hpp"
#include "barretenberg/crypto/pedersen_commitment/pedersen.hpp"
#include "barretenberg/crypto/pedersen_hash/pedersen.hpp"
#include "barretenberg/ecc/curves/grumpkin/grumpkin.hpp"
#include "barretenberg/crypto/schnorr/schnorr.hpp"
#include "barretenberg/crypto/schnorr/schnorr.tcc"
#include "barretenberg/crypto/blake2s/blake2s.hpp"

using ::to_buffer;
using ::from_buffer;

extern "C" {

// Provide malloc-backed buffer for FFI returns.
static uint8_t* bb_malloc_copy(const std::vector<uint8_t>& src)
{
    if (src.empty()) return nullptr;
    auto* out = static_cast<uint8_t*>(std::malloc(src.size()));
    if (!out) return nullptr;
    std::memcpy(out, src.data(), src.size());
    return out;
}

void bb_set_crs_path(const char* path_cstr)
{
    try {
        std::filesystem::path p(path_cstr ? path_cstr : "");
        bb::srs::init_net_crs_factory(p);
    } catch (...) {
        // swallow; FFI caller can attempt again
    }
}

int bb_acir_sizes(const uint8_t* acir, size_t acir_len, uint32_t* out_total, uint32_t* out_subgroup)
{
    try {
        fprintf(stderr, "[bb] acir_sizes: enter (acir_len=%zu)\n", acir_len);
        std::vector<uint8_t> acir_vec(acir, acir + acir_len);
        const acir_format::ProgramMetadata metadata{ .honk_recursion = 1 };
        acir_format::AcirProgram program{ acir_format::circuit_buf_to_acir_format(std::move(acir_vec)) };
        fprintf(stderr, "[bb] acir_sizes: constraints: poseidon2=%zu, msm=%zu, ec_add=%zu\n",
                program.constraints.poseidon2_constraints.size(),
                program.constraints.multi_scalar_mul_constraints.size(),
                program.constraints.ec_add_constraints.size());
        auto builder = acir_format::create_circuit<bb::MegaCircuitBuilder>(program, metadata);
        fprintf(stderr, "[bb] acir_sizes: builder created\n");
        builder.finalize_circuit(true);
        fprintf(stderr, "[bb] acir_sizes: builder finalized\n");
        const uint32_t total = static_cast<uint32_t>(builder.get_finalized_total_circuit_size());
        const uint32_t subgroup = static_cast<uint32_t>(
            builder.get_circuit_subgroup_size(builder.get_finalized_total_circuit_size()));
        if (out_total) *out_total = total;
        if (out_subgroup) *out_subgroup = subgroup;
        fprintf(stderr, "[bb] acir_sizes: exit (total=%u subgroup=%u)\n", total, subgroup);
        return 0;
    } catch (const std::exception& e) {
        fprintf(stderr, "[bb][ERR] acir_sizes exception: %s\n", e.what());
        return 1;
    } catch (...) {
        fprintf(stderr, "[bb][ERR] acir_sizes unknown exception\n");
        return 1;
    }
}

int bb_mh_write_vk(const uint8_t* acir, size_t acir_len, uint8_t** out_vk, size_t* out_vk_len)
{
    try {
        fprintf(stderr, "[bb] write_vk: enter (acir_len=%zu)\n", acir_len);
        std::vector<uint8_t> acir_vec(acir, acir + acir_len);
        const acir_format::ProgramMetadata metadata{ .honk_recursion = 1 };
        acir_format::AcirProgram program{ acir_format::circuit_buf_to_acir_format(std::move(acir_vec)) };
        fprintf(stderr, "[bb] write_vk: constraints: poseidon2=%zu, msm=%zu, ec_add=%zu\n",
                program.constraints.poseidon2_constraints.size(),
                program.constraints.multi_scalar_mul_constraints.size(),
                program.constraints.ec_add_constraints.size());
        auto builder = acir_format::create_circuit<bb::MegaCircuitBuilder>(program, metadata);
        fprintf(stderr, "[bb] write_vk: builder created\n");

        using DeciderProvingKey = bb::DeciderProvingKey_<bb::MegaFlavor>;
        using VerificationKey = bb::MegaFlavor::VerificationKey;
        DeciderProvingKey proving_key(builder);
        fprintf(stderr, "[bb] write_vk: proving_key built\n");
        VerificationKey vk(proving_key.get_precomputed());
        auto buf = to_buffer(vk);
        if (out_vk) *out_vk = bb_malloc_copy(buf);
        if (out_vk_len) *out_vk_len = buf.size();
        fprintf(stderr, "[bb] write_vk: exit (vk_len=%zu)\n", buf.size());
        return 0;
    } catch (const std::exception& e) {
        fprintf(stderr, "[bb][ERR] write_vk exception: %s\n", e.what());
        return 1;
    } catch (...) {
        fprintf(stderr, "[bb][ERR] write_vk unknown exception\n");
        return 1;
    }
}

int bb_mh_prove(const uint8_t* acir,
                size_t acir_len,
                const uint8_t* witness,
                size_t witness_len,
                uint8_t** out_proof,
                size_t* out_proof_len,
                uint8_t** out_vk,
                size_t* out_vk_len)
{
    try {
        fprintf(stderr, "[bb] prove: enter (acir_len=%zu witness_len=%zu)\n", acir_len, witness_len);
        std::vector<uint8_t> acir_vec(acir, acir + acir_len);
        std::vector<uint8_t> wit_vec(witness, witness + witness_len);
        const acir_format::ProgramMetadata metadata{ .honk_recursion = 1 };
        acir_format::AcirProgram program{ acir_format::circuit_buf_to_acir_format(std::move(acir_vec)),
                                          acir_format::witness_buf_to_witness_data(std::move(wit_vec)) };
        fprintf(stderr, "[bb] prove: constraints: poseidon2=%zu, msm=%zu, ec_add=%zu\n",
                program.constraints.poseidon2_constraints.size(),
                program.constraints.multi_scalar_mul_constraints.size(),
                program.constraints.ec_add_constraints.size());
        auto builder = acir_format::create_circuit<bb::MegaCircuitBuilder>(program, metadata);
        fprintf(stderr, "[bb] prove: builder created\n");
        using DeciderProvingKey = bb::DeciderProvingKey_<bb::MegaFlavor>;
        using VerificationKey = bb::MegaFlavor::VerificationKey;
        auto proving_key = std::make_shared<DeciderProvingKey>(builder);
        fprintf(stderr, "[bb] prove: proving_key built\n");
        auto verification_key = std::make_shared<VerificationKey>(proving_key->get_precomputed());
        fprintf(stderr, "[bb] prove: verification_key built\n");
        bb::UltraProver_<bb::MegaFlavor> prover{ proving_key, verification_key };
        fprintf(stderr, "[bb] prove: calling construct_proof...\n");
        auto proof = prover.construct_proof();
        fprintf(stderr, "[bb] prove: construct_proof OK\n");
        auto proof_buf = to_buffer<true>(proof);
        auto vk_buf = to_buffer(*verification_key);
        if (out_proof) *out_proof = bb_malloc_copy(proof_buf);
        if (out_proof_len) *out_proof_len = proof_buf.size();
        if (out_vk) *out_vk = bb_malloc_copy(vk_buf);
        if (out_vk_len) *out_vk_len = vk_buf.size();
        fprintf(stderr, "[bb] prove: exit (proof_len=%zu vk_len=%zu)\n", proof_buf.size(), vk_buf.size());
        return 0;
    } catch (const std::exception& e) {
        fprintf(stderr, "[bb][ERR] prove exception: %s\n", e.what());
        return 1;
    } catch (...) {
        fprintf(stderr, "[bb][ERR] prove unknown exception\n");
        return 1;
    }
}

int bb_mh_verify(const uint8_t* proof,
                 size_t proof_len,
                 const uint8_t* vk,
                 size_t vk_len,
                 bool* out_ok)
{
    try {
        std::vector<uint8_t> proof_bytes(proof, proof + proof_len);
        std::vector<uint8_t> vk_bytes(vk, vk + vk_len);
        auto proof_obj = from_buffer<bb::HonkProof>(proof_bytes);
        auto vk_raw = from_buffer<bb::MegaFlavor::VerificationKey>(vk_bytes);
        auto verification_key = std::make_shared<bb::MegaFlavor::VerificationKey>(vk_raw);
        bb::MegaVerifier verifier{ verification_key };
        bool ok = verifier.template verify_proof<bb::DefaultIO>(proof_obj).result;
        if (out_ok) *out_ok = ok;
        return 0;
    } catch (...) {
        return 1;
    }
}

int bb_merge_mega(const uint8_t* proof_a,
                  size_t len_a,
                  const uint8_t* vk_a,
                  size_t len_vk_a,
                  const uint8_t* proof_b,
                  size_t len_b,
                  const uint8_t* vk_b,
                  size_t len_vk_b,
                  uint8_t** out_merged_proof,
                  size_t* out_merged_proof_len,
                  uint8_t** out_merged_vk,
                  size_t* out_merged_vk_len)
{
    try {
        std::vector<uint8_t> pa(proof_a, proof_a + len_a);
        std::vector<uint8_t> pb(proof_b, proof_b + len_b);
        std::vector<uint8_t> vka(vk_a, vk_a + len_vk_a);
        std::vector<uint8_t> vkb(vk_b, vk_b + len_vk_b);
        auto res = bb::merge_mega::merge(pa, vka, pb, vkb);
        if (out_merged_proof) *out_merged_proof = bb_malloc_copy(res.merged_proof_bytes);
        if (out_merged_proof_len) *out_merged_proof_len = res.merged_proof_bytes.size();
        if (out_merged_vk) *out_merged_vk = bb_malloc_copy(res.merged_vk_bytes);
        if (out_merged_vk_len) *out_merged_vk_len = res.merged_vk_bytes.size();
        return 0;
    } catch (...) {
        return 1;
    }
}

// Helpers to convert 32-byte big-endian to field limbs (little-endian limb ordering) and back
static inline void be32_to_le_limbs(const uint8_t* in_be, uint64_t out_le[4])
{
    for (size_t i = 0; i < 4; ++i) {
        size_t off = 24 - i * 8;
        uint64_t limb = 0;
        for (size_t j = 0; j < 8; ++j) {
            limb = (limb << 8) | in_be[off + j];
        }
        out_le[i] = limb;
    }
}

static inline void le_limbs_to_be32(const uint64_t in_le[4], uint8_t* out_be)
{
    for (size_t i = 0; i < 4; ++i) {
        uint64_t limb = in_le[3 - i]; // highest limb first
        for (size_t j = 0; j < 8; ++j) {
            out_be[i * 8 + (7 - j)] = static_cast<uint8_t>(limb & 0xff);
            limb >>= 8;
        }
    }
}

// Poseidon2 permutation over BN254 Fr; len must be 4.
int bb_poseidon2_permutation_bn254(const uint8_t* inputs_be, size_t element_count, uint8_t** out_be, size_t* out_len)
{
    try {
        if (element_count != 4) {
            return 2;
        }
        using Params = bb::crypto::Poseidon2Bn254ScalarFieldParams;
        using Perm = bb::crypto::Poseidon2Permutation<Params>;
        bb::fr state[4];
        for (size_t i = 0; i < 4; ++i) {
            uint64_t limbs[4];
            be32_to_le_limbs(inputs_be + i * 32, limbs);
            bb::fr v(limbs[0], limbs[1], limbs[2], limbs[3]);
            state[i] = v.to_montgomery_form();
        }
        typename Perm::State s{ state[0], state[1], state[2], state[3] };
        auto out_state = Perm::permutation(s);
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

int bb_schnorr_poseidon2_verify_xy(const uint8_t* msg,
                                   size_t msg_len,
                                   const uint8_t sig64[64],
                                   const uint8_t pkx32[32],
                                   const uint8_t pky32[32],
                                   bool* out_ok)
{
    try {
        std::string message(reinterpret_cast<const char*>(msg), msg_len);
        uint64_t xl[4];
        uint64_t yl[4];
        be32_to_le_limbs(pkx32, xl);
        be32_to_le_limbs(pky32, yl);
        bb::grumpkin::fq x(xl[0], xl[1], xl[2], xl[3]);
        bb::grumpkin::fq y(yl[0], yl[1], yl[2], yl[3]);
        bb::grumpkin::g1::affine_element pubk(x.to_montgomery_form(), y.to_montgomery_form());
        std::array<uint8_t, 32> s_arr;
        std::array<uint8_t, 32> e_arr;
        std::copy(sig64, sig64 + 32, s_arr.begin());
        std::copy(sig64 + 32, sig64 + 64, e_arr.begin());
        bb::crypto::schnorr_signature sig{ s_arr, e_arr };
        bool ok = bb::crypto::schnorr_verify_signature<bb::crypto::Poseidon2Hasher, bb::grumpkin::fq, bb::grumpkin::fr, bb::grumpkin::g1>(
            message, pubk, sig);
        if (out_ok)
            *out_ok = ok;
        return 0;
    } catch (...) {
        return 1;
    }
}

// Pedersen commitment on grumpkin: inputs reduced into fq
int bb_pedersen_commit_grumpkin(
    const uint8_t* inputs_be,
    size_t n_elems,
    uint32_t domain,
    uint8_t out_x_be[32],
    uint8_t out_y_be[32])
{
    try {
        std::vector<bb::grumpkin::fq> inputs;
        inputs.reserve(n_elems);
        for (size_t i = 0; i < n_elems; ++i) {
            uint64_t limbs[4];
            be32_to_le_limbs(inputs_be + i * 32, limbs);
            bb::grumpkin::fq v(limbs[0], limbs[1], limbs[2], limbs[3]);
            inputs.push_back(v.to_montgomery_form());
        }
        auto P = bb::crypto::pedersen_commitment::commit_native(inputs, static_cast<size_t>(domain));
        auto nx = P.x.from_montgomery_form();
        auto ny = P.y.from_montgomery_form();
        le_limbs_to_be32(nx.data, out_x_be);
        le_limbs_to_be32(ny.data, out_y_be);
        return 0;
    } catch (...) {
        return 1;
    }
}

int bb_pedersen_hash_grumpkin(
    const uint8_t* inputs_be,
    size_t n_elems,
    uint32_t domain,
    uint8_t out_be[32])
{
    try {
        std::vector<bb::grumpkin::fq> inputs;
        inputs.reserve(n_elems);
        for (size_t i = 0; i < n_elems; ++i) {
            uint64_t limbs[4];
            be32_to_le_limbs(inputs_be + i * 32, limbs);
            bb::grumpkin::fq v(limbs[0], limbs[1], limbs[2], limbs[3]);
            inputs.push_back(v.to_montgomery_form());
        }
        auto h = bb::crypto::pedersen_hash::hash(inputs, static_cast<size_t>(domain));
        auto nh = h.from_montgomery_form();
        le_limbs_to_be32(nh.data, out_be);
        return 0;
    } catch (...) {
        return 1;
    }
}

int bb_grumpkin_ec_add(
    const uint8_t pk1_x_be[32],
    const uint8_t pk1_y_be[32],
    const uint8_t pk2_x_be[32],
    const uint8_t pk2_y_be[32],
    uint8_t out_x_be[32],
    uint8_t out_y_be[32])
{
    try {
        auto to_affine = [](const uint8_t* xbe, const uint8_t* ybe) {
            uint64_t xl[4], yl[4];
            be32_to_le_limbs(xbe, xl);
            be32_to_le_limbs(ybe, yl);
            bb::grumpkin::fq x(xl[0], xl[1], xl[2], xl[3]);
            bb::grumpkin::fq y(yl[0], yl[1], yl[2], yl[3]);
            return bb::grumpkin::g1::affine_element(x.to_montgomery_form(), y.to_montgomery_form());
        };
        auto A = to_affine(pk1_x_be, pk1_y_be);
        auto B = to_affine(pk2_x_be, pk2_y_be);
        bb::grumpkin::g1::element eA(A);
        bb::grumpkin::g1::element eB(B);
        auto S = eA + eB;
        bb::grumpkin::g1::affine_element R(S);
        auto nx = R.x.from_montgomery_form();
        auto ny = R.y.from_montgomery_form();
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
int bb_grumpkin_msm(
    const uint8_t* xs_be,
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
            }

            // Combine high and low 128-bit limbs (big-endian) into 32 bytes
            uint8_t scalar_be[32];
            std::memcpy(scalar_be, scalars_hi_be + i * 16, 16);
            std::memcpy(scalar_be + 16, scalars_lo_be + i * 16, 16);

            // Reduce to grumpkin::fr
            // Interpret as big-endian integer modulo r
            // barretenberg fr has constructor from 4 limbs (little-endian 64-bit limbs)
            // Convert 32-be into 4 le64 limbs
            uint64_t fr_limbs[4] = {0, 0, 0, 0};
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
            if (out_infinite) *out_infinite = 1;
            std::memset(out_x_be, 0, 32);
            std::memset(out_y_be, 0, 32);
        } else {
            auto nx = R.x.from_montgomery_form();
            auto ny = R.y.from_montgomery_form();
            le_limbs_to_be32(nx.data, out_x_be);
            le_limbs_to_be32(ny.data, out_y_be);
            if (out_infinite) *out_infinite = 0;
        }
        return 0;
    } catch (...) {
        return 1;
    }
}

// BN254 Fr ops with 32-byte big-endian I/O
static inline bb::fr fr_from_be32(const uint8_t be[32])
{
    uint64_t limbs[4];
    be32_to_le_limbs(be, limbs);
    bb::fr v(limbs[0], limbs[1], limbs[2], limbs[3]);
    return v.to_montgomery_form();
}

static inline std::vector<uint8_t> fr_to_be32(const bb::fr& a)
{
    auto norm = bb::fr(a).from_montgomery_form();
    std::vector<uint8_t> out(32);
    le_limbs_to_be32(norm.data, out.data());
    return out;
}

int bb_fr_add(const uint8_t* a32, const uint8_t* b32, uint8_t** out_ptr, size_t* out_len)
{
    try {
        auto a = fr_from_be32(a32);
        auto b = fr_from_be32(b32);
        bb::fr c = a + b;
        auto out = fr_to_be32(c);
        if (out_ptr) *out_ptr = bb_malloc_copy(out);
        if (out_len) *out_len = out.size();
        return 0;
    } catch (...) {
        return 1;
    }
}

int bb_fr_sub(const uint8_t* a32, const uint8_t* b32, uint8_t** out_ptr, size_t* out_len)
{
    try {
        auto a = fr_from_be32(a32);
        auto b = fr_from_be32(b32);
        bb::fr c = a - b;
        auto out = fr_to_be32(c);
        if (out_ptr) *out_ptr = bb_malloc_copy(out);
        if (out_len) *out_len = out.size();
        return 0;
    } catch (...) {
        return 1;
    }
}

int bb_fr_mul(const uint8_t* a32, const uint8_t* b32, uint8_t** out_ptr, size_t* out_len)
{
    try {
        auto a = fr_from_be32(a32);
        auto b = fr_from_be32(b32);
        bb::fr c = a * b;
        auto out = fr_to_be32(c);
        if (out_ptr) *out_ptr = bb_malloc_copy(out);
        if (out_len) *out_len = out.size();
        return 0;
    } catch (...) {
        return 1;
    }
}

int bb_fr_cmp(const uint8_t* a32, const uint8_t* b32)
{
    try {
        uint64_t al[4];
        uint64_t bl[4];
        be32_to_le_limbs(a32, al);
        be32_to_le_limbs(b32, bl);
        for (int i = 3; i >= 0; --i) {
            if (al[i] < bl[i]) return -1;
            if (al[i] > bl[i]) return 1;
        }
        return 0;
    } catch (...) {
        return 1;
    }
}

void bb_free(uint8_t* ptr) { std::free(ptr); }

} // extern "C"
// Simple Pedersen-bytes hasher: chunk bytes into 32-byte big-endian field elements over grumpkin::fq,
// then hash with crypto::pedersen_hash::hash(inputs, domain=0). Returns 32-byte big-endian digest.
struct PedersenBytesHasher {
    static constexpr size_t BLOCK_SIZE = 64;
    static constexpr size_t OUTPUT_SIZE = 32;
    static std::vector<uint8_t> hash(const std::vector<uint8_t>& message)
    {
        std::vector<bb::grumpkin::fq> inputs;
        if (!message.empty()) {
            size_t i = 0;
            while (i < message.size()) {
                uint8_t buf[32] = { 0 };
                size_t rem = message.size() - i;
                size_t copy = rem >= 32 ? 32 : rem;
                std::memcpy(buf + (32 - copy), &message[i], copy);
                uint64_t limbs[4];
                be32_to_le_limbs(buf, limbs);
                bb::grumpkin::fq x(limbs[0], limbs[1], limbs[2], limbs[3]);
                inputs.push_back(x.to_montgomery_form());
                i += copy;
            }
        } else {
            inputs.push_back(bb::grumpkin::fq::one());
        }
        auto h = bb::crypto::pedersen_hash::hash(inputs, 0);
        auto nh = h.from_montgomery_form();
        std::vector<uint8_t> out(32);
        le_limbs_to_be32(nh.data, out.data());
        return out;
    }
};
extern "C" {
int bb_schnorr_pedersen_sign(const uint8_t* msg,
                              size_t msg_len,
                              const uint8_t* sk32,
                              uint8_t sig64_out[64])
{
    try {
        std::string message(reinterpret_cast<const char*>(msg), msg_len);
        uint64_t sl[4];
        be32_to_le_limbs(sk32, sl);
        bb::grumpkin::fr sk(sl[0], sl[1], sl[2], sl[3]);
        sk = sk.to_montgomery_form();
        bb::grumpkin::g1::affine_element pk = bb::grumpkin::g1::one * sk;
        bb::crypto::schnorr_key_pair<bb::grumpkin::fr, bb::grumpkin::g1> kp{ sk, pk };
        auto sig = bb::crypto::schnorr_construct_signature<PedersenBytesHasher, bb::grumpkin::fq>(message, kp);
        std::memcpy(sig64_out, sig.s.data(), 32);
        std::memcpy(sig64_out + 32, sig.e.data(), 32);
        return 0;
    } catch (...) {
        return 1;
    }
}


int bb_schnorr_pedersen_verify(const uint8_t* msg,
                               size_t msg_len,
                               const uint8_t sig64[64],
                               const uint8_t pk32[32],
                               bool* out_ok)
{
    try {
        std::string message(reinterpret_cast<const char*>(msg), msg_len);
        uint64_t xl[4];
        be32_to_le_limbs(pk32, xl);
        bb::grumpkin::fq x(xl[0], xl[1], xl[2], xl[3]);
        // Recompute y from signature? We only have x; our examples provide both x and y. Provide verify_xy variant instead.
        return 2;
    } catch (...) {
        return 1;
    }
}

int bb_schnorr_pedersen_verify_xy(const uint8_t* msg,
                                  size_t msg_len,
                                  const uint8_t sig64[64],
                                  const uint8_t pkx32[32],
                                  const uint8_t pky32[32],
                                  bool* out_ok)
{
    try {
        std::string message(reinterpret_cast<const char*>(msg), msg_len);
        uint64_t xl[4], yl[4];
        be32_to_le_limbs(pkx32, xl);
        be32_to_le_limbs(pky32, yl);
        bb::grumpkin::fq x(xl[0], xl[1], xl[2], xl[3]);
        bb::grumpkin::fq y(yl[0], yl[1], yl[2], yl[3]);
        bb::grumpkin::g1::affine_element pubk(x.to_montgomery_form(), y.to_montgomery_form());
        std::array<uint8_t, 32> s_arr;
        std::array<uint8_t, 32> e_arr;
        std::copy(sig64, sig64 + 32, s_arr.begin());
        std::copy(sig64 + 32, sig64 + 64, e_arr.begin());
        bb::crypto::schnorr_signature sig{ s_arr, e_arr };
        bool ok = bb::crypto::schnorr_verify_signature<PedersenBytesHasher, bb::grumpkin::fq, bb::grumpkin::fr, bb::grumpkin::g1>(
            message, pubk, sig);
        if (out_ok)
            *out_ok = ok;
        return 0;
    } catch (...) {
        return 1;
    }
}

int bb_grumpkin_derive_pubkey(const uint8_t sk32[32], uint8_t out_x_be[32], uint8_t out_y_be[32])
{
    try {
        uint64_t sl[4];
        be32_to_le_limbs(sk32, sl);
        bb::grumpkin::fr sk(sl[0], sl[1], sl[2], sl[3]);
        sk = sk.to_montgomery_form();
        bb::grumpkin::g1::affine_element pk = bb::grumpkin::g1::one * sk;
        auto nx = pk.x.from_montgomery_form();
        auto ny = pk.y.from_montgomery_form();
        le_limbs_to_be32(nx.data, out_x_be);
        le_limbs_to_be32(ny.data, out_y_be);
        return 0;
    } catch (...) {
        return 1;
    }
}



// Blake2s prehash hasher for standard Schnorr
struct Blake2sBytesHasher {
    static constexpr size_t BLOCK_SIZE = 64;
    static constexpr size_t OUTPUT_SIZE = 32;
    static std::vector<uint8_t> hash(const std::vector<uint8_t>& message)
    {
        auto out = bb::crypto::blake2s(message);
        return std::vector<uint8_t>(out.begin(), out.end());
    }
};
extern "C" {
int bb_schnorr_blake2s_sign(const uint8_t* msg,
                             size_t msg_len,
                             const uint8_t* sk32,
                             uint8_t sig64_out[64])
{
    try {
        std::string message(reinterpret_cast<const char*>(msg), msg_len);
        uint64_t sl[4];
        be32_to_le_limbs(sk32, sl);
        bb::grumpkin::fr sk(sl[0], sl[1], sl[2], sl[3]);
        sk = sk.to_montgomery_form();
        bb::grumpkin::g1::affine_element pk = bb::grumpkin::g1::one * sk;
        bb::crypto::schnorr_key_pair<bb::grumpkin::fr, bb::grumpkin::g1> kp{ sk, pk };
        auto sig = bb::crypto::schnorr_construct_signature<Blake2sBytesHasher, bb::grumpkin::fq>(message, kp);
        std::memcpy(sig64_out, sig.s.data(), 32);
        std::memcpy(sig64_out + 32, sig.e.data(), 32);
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
        std::string message(reinterpret_cast<const char*>(msg), msg_len);
        uint64_t xl[4], yl[4];
        be32_to_le_limbs(pkx32, xl);
        be32_to_le_limbs(pky32, yl);
        bb::grumpkin::fq x(xl[0], xl[1], xl[2], xl[3]);
        bb::grumpkin::fq y(yl[0], yl[1], yl[2], yl[3]);
        bb::grumpkin::g1::affine_element pubk(x.to_montgomery_form(), y.to_montgomery_form());
        std::array<uint8_t, 32> s_arr;
        std::array<uint8_t, 32> e_arr;
        std::copy(sig64, sig64 + 32, s_arr.begin());
        std::copy(sig64 + 32, sig64 + 64, e_arr.begin());
        bb::crypto::schnorr_signature sig{ s_arr, e_arr };
        bool ok = bb::crypto::schnorr_verify_signature<Blake2sBytesHasher, bb::grumpkin::fq, bb::grumpkin::fr, bb::grumpkin::g1>(message, pubk, sig);
        if (out_ok) *out_ok = ok;
        return 0;
    } catch (...) {
        return 1;
    }
}
}

int bb_schnorr_poseidon2_sign(const uint8_t* msg,
                              size_t msg_len,
                              const uint8_t* sk32,
                              uint8_t sig64_out[64])
{
    try {
        std::string message(reinterpret_cast<const char*>(msg), msg_len);
        uint64_t sl[4];
        be32_to_le_limbs(sk32, sl);
        bb::grumpkin::fr sk(sl[0], sl[1], sl[2], sl[3]);
        sk = sk.to_montgomery_form();
        bb::grumpkin::g1::affine_element pk = bb::grumpkin::g1::one * sk;
        bb::crypto::schnorr_key_pair<bb::grumpkin::fr, bb::grumpkin::g1> kp{ sk, pk };
        auto sig = bb::crypto::schnorr_construct_signature<bb::crypto::Poseidon2Hasher, bb::grumpkin::fq>(message, kp);
        std::memcpy(sig64_out, sig.s.data(), 32);
        std::memcpy(sig64_out + 32, sig.e.data(), 32);
        return 0;
    } catch (...) {
        return 1;
    }
}
} // extern "C"
