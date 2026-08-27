#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <vector>
#include <array>
#include <algorithm>
#include <limits>
#include <stdexcept>
#include <optional>

#include "bb_rust_api_internal.hpp"

#include "barretenberg/common/serialize.hpp"
#include "barretenberg/common/throw_or_abort.hpp"
#include "barretenberg/dsl/acir_format/acir_format.hpp"
#include "barretenberg/dsl/acir_format/acir_to_constraint_buf.hpp"
#include "barretenberg/honk/proof_length.hpp"
#include "barretenberg/merge/batch_merge.hpp"
#include "barretenberg/ultra_honk/prover_instance.hpp"
#include "barretenberg/stdlib_circuit_builders/mega_circuit_builder.hpp"
#include "barretenberg/honk/proof_system/types/proof.hpp"
#include "barretenberg/ultra_honk/ultra_prover.hpp"
#include "barretenberg/flavor/ultra_zk_flavor.hpp"
#include "barretenberg/flavor/ultra_zk_recursive_flavor.hpp"
#include "barretenberg/stdlib/special_public_inputs/special_public_inputs.hpp"
#include "barretenberg/special_public_inputs/special_public_inputs.hpp"
#include "barretenberg/flavor/mega_recursive_flavor.hpp"
#include "barretenberg/stdlib_circuit_builders/mega_circuit_builder.hpp"
#include "barretenberg/ultra_honk/ultra_verifier.hpp"
#include "barretenberg/ultra_honk/oink_verifier.hpp"
#include "barretenberg/dsl/acir_format/mock_verifier_inputs.hpp"
#include "barretenberg/stdlib/hash/poseidon2/poseidon2.hpp"
#include "barretenberg/ecc/curves/bn254/g1.hpp"
#include "barretenberg/ecc/curves/bn254/g2.hpp"
#include "barretenberg/ecc/curves/grumpkin/grumpkin.hpp"
#include "barretenberg/srs/global_crs.hpp"

using ::to_buffer;
using ::from_buffer;

namespace {

enum BbStatusCode : int {
    BB_STATUS_OK = 0,
    BB_STATUS_INTERNAL = 1,
    BB_STATUS_MALFORMED_PROOF = 2,
    BB_STATUS_MALFORMED_VK = 3,
    BB_STATUS_SIZE_LIMIT = 4,
    BB_STATUS_WRONG_PROOF_TYPE = 5,
};

static constexpr size_t FR_SERIALIZED_BYTES = 32;
static constexpr size_t U32_PREFIX_BYTES = 4;
static constexpr size_t MAX_PROOF_BYTES = 16 * 1024 * 1024;
static constexpr size_t MAX_VK_BYTES = 1 * 1024 * 1024;

static inline uint32_t read_be_u32(const uint8_t* data)
{
    return (static_cast<uint32_t>(data[0]) << 24) | (static_cast<uint32_t>(data[1]) << 16) |
           (static_cast<uint32_t>(data[2]) << 8) | static_cast<uint32_t>(data[3]);
}

static inline bool checked_mul(size_t a, size_t b, size_t& out)
{
    if (a == 0 || b == 0) {
        out = 0;
        return false;
    }
    if (a > (std::numeric_limits<size_t>::max() / b)) {
        return true;
    }
    out = a * b;
    return false;
}

static inline bool checked_add(size_t a, size_t b, size_t& out)
{
    if (a > (std::numeric_limits<size_t>::max() - b)) {
        return true;
    }
    out = a + b;
    return false;
}

static size_t mega_vk_serialized_size()
{
    static const size_t VK_SIZE = to_buffer(bb::MegaFlavor::VerificationKey{}).size();
    return VK_SIZE;
}

static size_t ultra_zk_vk_serialized_size()
{
    static const size_t VK_SIZE = to_buffer(bb::UltraZKFlavor::VerificationKey{}).size();
    return VK_SIZE;
}

static int parse_honk_proof_checked(const uint8_t* proof, size_t proof_len, bb::HonkProof& out_proof)
{
    if ((proof == nullptr && proof_len != 0) || proof_len < U32_PREFIX_BYTES) {
        return BB_STATUS_MALFORMED_PROOF;
    }
    if (proof_len > MAX_PROOF_BYTES) {
        return BB_STATUS_SIZE_LIMIT;
    }

    const uint32_t n_fields = read_be_u32(proof);
    size_t payload_len = 0;
    if (checked_mul(static_cast<size_t>(n_fields), FR_SERIALIZED_BYTES, payload_len)) {
        return BB_STATUS_SIZE_LIMIT;
    }
    size_t expected_len = 0;
    if (checked_add(U32_PREFIX_BYTES, payload_len, expected_len)) {
        return BB_STATUS_SIZE_LIMIT;
    }
    if (expected_len != proof_len) {
        return BB_STATUS_MALFORMED_PROOF;
    }

    out_proof.clear();
    out_proof.reserve(n_fields);
    for (size_t i = 0; i < n_fields; ++i) {
        const uint8_t* elem = proof + U32_PREFIX_BYTES + (i * FR_SERIALIZED_BYTES);
        out_proof.emplace_back(from_buffer<bb::fr>(elem));
    }
    return BB_STATUS_OK;
}

static int parse_vk_checked(const uint8_t* vk,
                            size_t vk_len,
                            std::optional<bb::MegaFlavor::VerificationKey>& out_vk)
{
    if ((vk == nullptr && vk_len != 0) || vk_len == 0) {
        return BB_STATUS_MALFORMED_VK;
    }
    if (vk_len > MAX_VK_BYTES) {
        return BB_STATUS_SIZE_LIMIT;
    }
    if (vk_len != mega_vk_serialized_size()) {
        return BB_STATUS_MALFORMED_VK;
    }
    try {
        std::vector<uint8_t> vk_bytes(vk, vk + vk_len);
        out_vk.emplace(from_buffer<bb::MegaFlavor::VerificationKey>(vk_bytes));
        return BB_STATUS_OK;
    } catch (...) {
        return BB_STATUS_MALFORMED_VK;
    }
}

static int parse_ultra_zk_vk_checked(const uint8_t* vk,
                                     size_t vk_len,
                                     std::optional<bb::UltraZKFlavor::VerificationKey>& out_vk)
{
    if ((vk == nullptr && vk_len != 0) || vk_len == 0) {
        return BB_STATUS_MALFORMED_VK;
    }
    if (vk_len > MAX_VK_BYTES) {
        return BB_STATUS_SIZE_LIMIT;
    }
    if (vk_len != ultra_zk_vk_serialized_size()) {
        return BB_STATUS_MALFORMED_VK;
    }
    try {
        std::vector<uint8_t> vk_bytes(vk, vk + vk_len);
        out_vk.emplace(from_buffer<bb::UltraZKFlavor::VerificationKey>(vk_bytes));
        return BB_STATUS_OK;
    } catch (...) {
        return BB_STATUS_MALFORMED_VK;
    }
}

static int batch_merge_with_vks_internal(const uint8_t* proof_a,
                                          size_t len_a,
                                          const uint8_t* vk_a,
                                          size_t len_vk_a,
                                          const uint8_t* proof_b,
                                          size_t len_b,
                                          const uint8_t* vk_b,
                                          size_t len_vk_b,
                                          std::vector<uint8_t>& merged_proof_bytes,
                                          std::vector<uint8_t>* merged_vk_bytes = nullptr)
{
    bb::HonkProof proof_a_checked;
    bb::HonkProof proof_b_checked;
    std::optional<bb::MegaFlavor::VerificationKey> vk_a_checked;
    std::optional<bb::MegaFlavor::VerificationKey> vk_b_checked;

    int status = parse_honk_proof_checked(proof_a, len_a, proof_a_checked);
    if (status != BB_STATUS_OK) {
        return status;
    }
    status = parse_honk_proof_checked(proof_b, len_b, proof_b_checked);
    if (status != BB_STATUS_OK) {
        return status;
    }
    status = parse_vk_checked(vk_a, len_vk_a, vk_a_checked);
    if (status != BB_STATUS_OK) {
        return status;
    }
    status = parse_vk_checked(vk_b, len_vk_b, vk_b_checked);
    if (status != BB_STATUS_OK) {
        return status;
    }

    try {
        std::vector<uint8_t> pa(proof_a, proof_a + len_a);
        std::vector<uint8_t> pb(proof_b, proof_b + len_b);
        std::vector<uint8_t> vka(vk_a, vk_a + len_vk_a);
        std::vector<uint8_t> vkb(vk_b, vk_b + len_vk_b);
        auto res = bb::batch_merge::merge(pa, vka, pb, vkb);
        merged_proof_bytes = std::move(res.merged_proof_bytes);
        if (merged_vk_bytes != nullptr) {
            *merged_vk_bytes = std::move(res.merged_vk_bytes);
        }
        return BB_STATUS_OK;
    } catch (const std::exception& e) {
        fprintf(stderr, "[bb][shim][ERR] batch_merge exception: %s\n", e.what());
        return BB_STATUS_INTERNAL;
    } catch (...) {
        fprintf(stderr, "[bb][shim][ERR] batch_merge unknown exception\n");
        return BB_STATUS_INTERNAL;
    }
}

static int batch_merge_with_child_vk_internal(const uint8_t* proof_a,
                                               size_t len_a,
                                               const uint8_t* proof_b,
                                               size_t len_b,
                                               const std::vector<uint8_t>& child_vk,
                                               std::vector<uint8_t>& merged_proof_bytes)
{
    return batch_merge_with_vks_internal(proof_a,
                                         len_a,
                                         child_vk.data(),
                                         child_vk.size(),
                                         proof_b,
                                         len_b,
                                         child_vk.data(),
                                         child_vk.size(),
                                         merged_proof_bytes);
}

template <typename Flavor> static bool exceeds_virtual_log_n(size_t log_dyadic_size)
{
    if constexpr (Flavor::USE_PADDING) {
        return log_dyadic_size > Flavor::VIRTUAL_LOG_N;
    } else {
        return false;
    }
}

template <typename RecFlavor>
static std::vector<typename RecFlavor::FF> recursive_oink_public_inputs(
    const std::shared_ptr<typename RecFlavor::VKAndHash>& vk_and_hash,
    const std::vector<typename RecFlavor::FF>& proof_fields)
{
    auto transcript = std::make_shared<typename RecFlavor::Transcript>();
    transcript->load_proof(proof_fields);

    size_t log_n;
    if constexpr (RecFlavor::USE_PADDING) {
        log_n = static_cast<size_t>(RecFlavor::VIRTUAL_LOG_N);
    } else {
        log_n = static_cast<size_t>(vk_and_hash->vk->log_circuit_size.get_value());
    }
    const size_t num_public_inputs =
        bb::ProofLength::Honk<RecFlavor>::derive_num_public_inputs(proof_fields.size(), log_n);

    auto verifier_instance = std::make_shared<bb::VerifierInstance_<RecFlavor>>(vk_and_hash);
    bb::OinkVerifier<RecFlavor> oink_verifier{ verifier_instance, transcript, num_public_inputs };
    oink_verifier.verify();
    return verifier_instance->public_inputs;
}

} // namespace

extern "C" {

void srs_init_srs(const uint8_t* points_buf, const uint32_t* num_points_be, const uint8_t* g2_point_buf)
{
    const auto* num_points_bytes = reinterpret_cast<const uint8_t*>(num_points_be);
    const uint32_t num_points = read_be_u32(num_points_bytes);
    std::vector<bb::g1::affine_element> g1_points(num_points);
    for (uint32_t i = 0; i < num_points; ++i) {
        g1_points[i] = from_buffer<bb::g1::affine_element>(points_buf, static_cast<size_t>(i) * 64);
    }
    const auto g2_point = from_buffer<bb::g2::affine_element>(g2_point_buf);
    bb::srs::init_bn254_mem_crs_factory(g1_points, g2_point);
}

void srs_init_grumpkin_srs(const uint8_t* points_buf, const uint32_t* num_points_be)
{
    const auto* num_points_bytes = reinterpret_cast<const uint8_t*>(num_points_be);
    const uint32_t num_points = read_be_u32(num_points_bytes);
    std::vector<bb::curve::Grumpkin::AffineElement> points(num_points);
    for (uint32_t i = 0; i < num_points; ++i) {
        points[i] = from_buffer<bb::curve::Grumpkin::AffineElement>(
            points_buf, static_cast<size_t>(i) * sizeof(bb::curve::Grumpkin::AffineElement));
    }
    bb::srs::init_grumpkin_mem_crs_factory(points);
}

int bb_mega_honk_vk_from_acir(const uint8_t* acir, size_t acir_len, uint8_t** out_vk, size_t* out_vk_len)
{
    try {
        std::vector<uint8_t> acir_vec(acir, acir + acir_len);
        const acir_format::ProgramMetadata metadata{};
        acir_format::AcirProgram program{ acir_format::circuit_buf_to_acir_format(std::move(acir_vec)), {} };
        auto builder = acir_format::create_circuit<bb::MegaCircuitBuilder>(program, metadata);

        using ProverInstance = bb::ProverInstance_<bb::MegaFlavor>;
        using VerificationKey = bb::MegaFlavor::VerificationKey;
        ProverInstance prover_instance(builder);
        VerificationKey vk(prover_instance.get_precomputed());
        auto buf = to_buffer(vk);
        if (out_vk) *out_vk = bb_malloc_copy(buf);
        if (out_vk_len) *out_vk_len = buf.size();
        return 0;
    } catch (const std::exception& e) {
        fprintf(stderr, "[bb][ERR] write_vk exception: %s\n", e.what());
        return 1;
    } catch (...) {
        fprintf(stderr, "[bb][ERR] write_vk unknown exception\n");
        return 1;
    }
}

int bb_mh_circuit_metadata(const uint8_t* acir,
                           size_t acir_len,
                           uint32_t* out_log_dyadic_size,
                           uint32_t* out_max_log_dyadic_size,
                           size_t* out_num_public_inputs)
{
    try {
        std::vector<uint8_t> acir_vec(acir, acir + acir_len);
        const acir_format::ProgramMetadata metadata{};
        acir_format::AcirProgram program{ acir_format::circuit_buf_to_acir_format(std::move(acir_vec)), {} };
        auto builder = acir_format::create_circuit<bb::MegaCircuitBuilder>(program, metadata);

        using ProverInstance = bb::ProverInstance_<bb::MegaFlavor>;
        ProverInstance prover_instance(builder);

        if (out_log_dyadic_size) {
            *out_log_dyadic_size = static_cast<uint32_t>(prover_instance.log_dyadic_size());
        }
        if (out_max_log_dyadic_size) {
            *out_max_log_dyadic_size = static_cast<uint32_t>(bb::MegaFlavor::VIRTUAL_LOG_N);
        }
        if (out_num_public_inputs) {
            *out_num_public_inputs = prover_instance.num_public_inputs();
        }
        return 0;
    } catch (const std::exception& e) {
        fprintf(stderr, "[bb][ERR] circuit metadata exception: %s\n", e.what());
        return BB_STATUS_INTERNAL;
    } catch (...) {
        fprintf(stderr, "[bb][ERR] circuit metadata unknown exception\n");
        return BB_STATUS_INTERNAL;
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
        std::vector<uint8_t> acir_vec(acir, acir + acir_len);
        std::vector<uint8_t> wit_vec(witness, witness + witness_len);
        const acir_format::ProgramMetadata metadata{};
        acir_format::AcirProgram program{ acir_format::circuit_buf_to_acir_format(std::move(acir_vec)),
                                          acir_format::witness_buf_to_witness_vector(std::move(wit_vec)) };
        auto builder = acir_format::create_circuit<bb::MegaCircuitBuilder>(program, metadata);
        using ProverInstance = bb::ProverInstance_<bb::MegaFlavor>;
        using VerificationKey = bb::MegaFlavor::VerificationKey;
        auto prover_instance = std::make_shared<ProverInstance>(builder);
        const size_t log_dyadic_size = prover_instance->log_dyadic_size();
        if (exceeds_virtual_log_n<bb::MegaFlavor>(log_dyadic_size)) {
            fprintf(stderr,
                    "[bb][ERR] prove exception: MegaHonk circuit too large for current recursive proof bound "
                    "(log_n=%zu, max=%zu)\n",
                    log_dyadic_size,
                    bb::MegaFlavor::VIRTUAL_LOG_N);
            return BB_STATUS_SIZE_LIMIT;
        }
        auto verification_key = std::make_shared<VerificationKey>(prover_instance->get_precomputed());
        bb::UltraProver_<bb::MegaFlavor> prover{ prover_instance, verification_key };
        auto proof = prover.construct_proof();
        auto proof_buf = to_buffer<true>(proof);
        auto vk_buf = to_buffer(*verification_key);
        if (out_proof) *out_proof = bb_malloc_copy(proof_buf);
        if (out_proof_len) *out_proof_len = proof_buf.size();
        if (out_vk) *out_vk = bb_malloc_copy(vk_buf);
        if (out_vk_len) *out_vk_len = vk_buf.size();
        return 0;
    } catch (const std::exception& e) {
        fprintf(stderr, "[bb][ERR] prove exception: %s\n", e.what());
        return 1;
    } catch (...) {
        fprintf(stderr, "[bb][ERR] prove unknown exception\n");
        return 1;
    }
}

static int bb_mh_verify_impl(const uint8_t* proof,
                             size_t proof_len,
                             const uint8_t* vk,
                             size_t vk_len,
                             bool* out_ok,
                             bool verify_batch_merge_layout)
{
    if (out_ok) {
        *out_ok = false;
    }

    bb::HonkProof proof_obj;
    const int proof_status = parse_honk_proof_checked(proof, proof_len, proof_obj);
    if (proof_status != BB_STATUS_OK) {
        return proof_status;
    }

    std::optional<bb::MegaFlavor::VerificationKey> vk_raw;
    const int vk_status = parse_vk_checked(vk, vk_len, vk_raw);
    if (vk_status != BB_STATUS_OK) {
        return vk_status;
    }

    try {
        if (!vk_raw.has_value()) {
            return BB_STATUS_MALFORMED_VK;
        }
        auto verification_key = std::make_shared<bb::MegaFlavor::VerificationKey>(*vk_raw);
        auto vk_and_hash = std::make_shared<bb::MegaFlavor::VKAndHash>(verification_key);
        bb::MegaVerifier verifier{ vk_and_hash };
        const size_t total_pub = static_cast<size_t>(vk_raw->num_public_inputs);
        const size_t default_pub = static_cast<size_t>(bb::DefaultIO::PUBLIC_INPUTS_SIZE);
        static constexpr size_t BATCH_MERGE_BINDING_PUBLIC_INPUTS = 12;
        const size_t batch_merge_pub = BATCH_MERGE_BINDING_PUBLIC_INPUTS + default_pub;
        bool ok = false;
        // Guard against unsigned underflow in DefaultIO reconstruction.
        if (total_pub < default_pub) {
            return BB_STATUS_WRONG_PROOF_TYPE;
        }
        if (verify_batch_merge_layout && total_pub != batch_merge_pub) {
            return BB_STATUS_WRONG_PROOF_TYPE;
        }
        ok = verifier.verify_proof(proof_obj).result;
        if (out_ok) {
            *out_ok = ok;
        }
        return BB_STATUS_OK;
    } catch (const std::exception& e) {
        fprintf(stderr, "[bb][ERR] verify exception: %s\n", e.what());
        return BB_STATUS_MALFORMED_PROOF;
    } catch (...) {
        return BB_STATUS_INTERNAL;
    }
}

int bb_mh_verify_default(const uint8_t* proof,
                         size_t proof_len,
                         const uint8_t* vk,
                         size_t vk_len,
                         bool* out_ok)
{
    return bb_mh_verify_impl(proof, proof_len, vk, vk_len, out_ok, false);
}

int bb_verify_batch_merge_leaf(const uint8_t* proof, size_t proof_len, bool* out_ok)
{
    const auto& vk = bb::batch_merge::embedded_leaf_merge_vk();
    return bb_mh_verify_impl(proof, proof_len, vk.data(), vk.size(), out_ok, true);
}

int bb_verify_batch_merge(const uint8_t* proof, size_t proof_len, bool* out_ok)
{
    const auto& vk = bb::batch_merge::embedded_agg_merge_vk();
    return bb_mh_verify_impl(proof, proof_len, vk.data(), vk.size(), out_ok, true);
}

// Extract Mega proof public inputs as concatenated 32-byte big-endian field elements.
// Returns 0 on success and writes a malloc'd buffer via out_ptr/out_len.
int bb_mh_public_inputs(const uint8_t* proof,
                        size_t proof_len,
                        const uint8_t* vk,
                        size_t vk_len,
                        uint8_t** out_ptr,
                        size_t* out_len)
{
    bb::HonkProof proof_fields;
    const int proof_status = parse_honk_proof_checked(proof, proof_len, proof_fields);
    if (proof_status != BB_STATUS_OK) {
        return proof_status;
    }

    std::optional<bb::MegaFlavor::VerificationKey> vk_native;
    const int vk_status = parse_vk_checked(vk, vk_len, vk_native);
    if (vk_status != BB_STATUS_OK) {
        return vk_status;
    }

    try {
        if (!vk_native.has_value()) {
            return BB_STATUS_MALFORMED_VK;
        }
        const size_t total_pub = static_cast<size_t>(vk_native->num_public_inputs);
        using Builder = bb::MegaCircuitBuilder;
        using DefaultIO = bb::stdlib::recursion::honk::DefaultIO<Builder>;
        const size_t default_pub = static_cast<size_t>(DefaultIO::PUBLIC_INPUTS_SIZE);
        size_t inner_pub = (total_pub > default_pub) ? (total_pub - default_pub) : 0;
        if (inner_pub == 0 && total_pub > 0) {
            inner_pub = total_pub;
        }

        std::vector<uint8_t> out;
        out.reserve(inner_pub * 32);
        if (inner_pub > proof_fields.size()) {
            inner_pub = proof_fields.size();
        }
        for (size_t i = 0; i < inner_pub && i < proof_fields.size(); ++i) {
            auto be = fr_to_be32(proof_fields[i]);
            out.insert(out.end(), be.begin(), be.end());
        }

        if (out_ptr) *out_ptr = bb_malloc_copy(out);
        if (out_len) *out_len = out.size();
        return BB_STATUS_OK;
    } catch (...) {
        return BB_STATUS_INTERNAL;
    }
}

int bb_batch_merge_public_inputs_leaf(const uint8_t* proof,
                                      size_t proof_len,
                                      uint8_t** out_ptr,
                                      size_t* out_len)
{
    const auto& vk = bb::batch_merge::embedded_leaf_merge_vk();
    return bb_mh_public_inputs(proof, proof_len, vk.data(), vk.size(), out_ptr, out_len);
}

int bb_batch_merge_public_inputs(const uint8_t* proof,
                                 size_t proof_len,
                                 uint8_t** out_ptr,
                                 size_t* out_len)
{
    const auto& vk = bb::batch_merge::embedded_agg_merge_vk();
    return bb_mh_public_inputs(proof, proof_len, vk.data(), vk.size(), out_ptr, out_len);
}

int bb_batch_merge_leaf_vk(uint8_t** out_ptr, size_t* out_len)
{
    const auto& vk = bb::batch_merge::embedded_leaf_merge_vk();
    if (out_ptr) *out_ptr = bb_malloc_copy(vk);
    if (out_len) *out_len = vk.size();
    return BB_STATUS_OK;
}

int bb_batch_merge_agg_vk(uint8_t** out_ptr, size_t* out_len)
{
    const auto& vk = bb::batch_merge::embedded_agg_merge_vk();
    if (out_ptr) *out_ptr = bb_malloc_copy(vk);
    if (out_len) *out_len = vk.size();
    return BB_STATUS_OK;
}

// Compute Mega VK hash as a 32-byte big-endian field element.
int bb_mh_vk_hash(const uint8_t* vk,
                  size_t vk_len,
                  uint8_t out_be32[32])
{
    std::optional<bb::MegaFlavor::VerificationKey> vk_native;
    const int vk_status = parse_vk_checked(vk, vk_len, vk_native);
    if (vk_status != BB_STATUS_OK) {
        return vk_status;
    }

    try {
        if (!vk_native.has_value()) {
            return BB_STATUS_MALFORMED_VK;
        }
        auto h = vk_native->hash();
        auto be = fr_to_be32(h);
        std::memcpy(out_be32, be.data(), 32);
        return BB_STATUS_OK;
    } catch (...) {
        return BB_STATUS_INTERNAL;
    }
}

int bb_uhz_verify(const uint8_t* proof,
                  size_t proof_len,
                  const uint8_t* vk,
                  size_t vk_len,
                  bool* out_ok)
{
    if (out_ok) {
        *out_ok = false;
    }

    bb::HonkProof proof_obj;
    const int proof_status = parse_honk_proof_checked(proof, proof_len, proof_obj);
    if (proof_status != BB_STATUS_OK) {
        return proof_status;
    }

    std::optional<bb::UltraZKFlavor::VerificationKey> vk_raw;
    const int vk_status = parse_ultra_zk_vk_checked(vk, vk_len, vk_raw);
    if (vk_status != BB_STATUS_OK) {
        return vk_status;
    }

    try {
        if (!vk_raw.has_value()) {
            return BB_STATUS_MALFORMED_VK;
        }
        auto verification_key = std::make_shared<bb::UltraZKFlavor::VerificationKey>(*vk_raw);
        auto vk_and_hash = std::make_shared<bb::UltraZKFlavor::VKAndHash>(verification_key);
        bb::UltraZKVerifier verifier{ vk_and_hash };
        const bool ok = verifier.verify_proof(proof_obj).result;
        if (out_ok) {
            *out_ok = ok;
        }
        return BB_STATUS_OK;
    } catch (const std::exception& e) {
        fprintf(stderr, "[bb][ERR] ultra_zk verify exception: %s\n", e.what());
        return BB_STATUS_MALFORMED_PROOF;
    } catch (...) {
        return BB_STATUS_INTERNAL;
    }
}

int bb_uhz_public_inputs(const uint8_t* proof,
                         size_t proof_len,
                         const uint8_t* vk,
                         size_t vk_len,
                         uint8_t** out_ptr,
                         size_t* out_len)
{
    bb::HonkProof proof_fields;
    const int proof_status = parse_honk_proof_checked(proof, proof_len, proof_fields);
    if (proof_status != BB_STATUS_OK) {
        return proof_status;
    }

    std::optional<bb::UltraZKFlavor::VerificationKey> vk_native;
    const int vk_status = parse_ultra_zk_vk_checked(vk, vk_len, vk_native);
    if (vk_status != BB_STATUS_OK) {
        return vk_status;
    }

    try {
        if (!vk_native.has_value()) {
            return BB_STATUS_MALFORMED_VK;
        }
        const size_t total_pub = static_cast<size_t>(vk_native->num_public_inputs);
        if (total_pub > proof_fields.size()) {
            return BB_STATUS_MALFORMED_PROOF;
        }

        std::vector<uint8_t> out;
        out.reserve(total_pub * 32);
        for (size_t i = 0; i < total_pub; ++i) {
            auto be = fr_to_be32(proof_fields[i]);
            out.insert(out.end(), be.begin(), be.end());
        }

        if (out_ptr) *out_ptr = bb_malloc_copy(out);
        if (out_len) *out_len = out.size();
        return BB_STATUS_OK;
    } catch (...) {
        return BB_STATUS_INTERNAL;
    }
}

// Derive the Mega wrapper VK used to recursive-verify an UltraZK proof and expose
// the scoped nullifier (last inner public input) as the sole outer public input.
int bb_uhz_leaf_vk(const uint8_t* vk, size_t vk_len, uint8_t** out_vk, size_t* out_vk_len)
{
    std::optional<bb::UltraZKFlavor::VerificationKey> vk_native;
    const int vk_status = parse_ultra_zk_vk_checked(vk, vk_len, vk_native);
    if (vk_status != BB_STATUS_OK) {
        return vk_status;
    }

    try {
        using Builder = bb::MegaCircuitBuilder;
        using RecFlavor = bb::UltraZKRecursiveFlavor_<Builder>;
        using MockIO = bb::stdlib::recursion::honk::DefaultIO<Builder>;
        using RecVerifier = bb::UltraVerifier_<RecFlavor, MockIO>;
        using ProverInstance = bb::ProverInstance_<bb::MegaFlavor>;

        Builder builder;
        if (!vk_native.has_value()) {
            return BB_STATUS_MALFORMED_VK;
        }
        auto native_vk = std::make_shared<bb::UltraZKFlavor::VerificationKey>(*vk_native);
        auto vk_std = std::make_shared<typename RecFlavor::VerificationKey>(&builder, native_vk);
        auto vk_hash_ff = RecFlavor::FF::from_witness(&builder, native_vk->hash());
        vk_hash_ff.unset_free_witness_tag();
        auto vk_and_hash = std::make_shared<typename RecFlavor::VKAndHash>(vk_std, vk_hash_ff);

        // `create_mock_honk_proof` expects the *inner* (ACIR) public input count.
        // The vk's `num_public_inputs` includes additional barretenberg public inputs
        // contributed by the IO type (e.g. aggregation object).
        const size_t total_public_inputs = static_cast<size_t>(native_vk->num_public_inputs);
        if (total_public_inputs < MockIO::PUBLIC_INPUTS_SIZE) {
            return BB_STATUS_MALFORMED_VK;
        }
        const size_t inner_public_inputs = total_public_inputs - MockIO::PUBLIC_INPUTS_SIZE;
        bb::HonkProof mock_proof =
            acir_format::create_mock_honk_proof<bb::UltraZKFlavor, MockIO>(inner_public_inputs);
        std::vector<typename RecFlavor::FF> proof_fields_ff;
        proof_fields_ff.reserve(mock_proof.size());
        for (const auto& field : mock_proof) {
            auto proof_field_ff = RecFlavor::FF::from_witness(&builder, field);
            proof_field_ff.unset_free_witness_tag();
            proof_fields_ff.emplace_back(proof_field_ff);
        }

        auto public_inputs = recursive_oink_public_inputs<RecFlavor>(vk_and_hash, proof_fields_ff);
        if (public_inputs.empty()) {
            return BB_STATUS_MALFORMED_VK;
        }
        bb::unset_free_witness_tags<true>(public_inputs);
        // Semantic leaf statement: a single commitment to all UltraZK public inputs.
        // Downstream aggregation expects one semantic public input plus DefaultIO pairing points.
        auto leaf_commitment = bb::stdlib::poseidon2<Builder>::hash(public_inputs);
        leaf_commitment.set_public();

        RecVerifier verifier{ vk_and_hash };
        typename RecVerifier::Proof stdlib_proof(proof_fields_ff);
        auto output = verifier.verify_proof(stdlib_proof);

        // Propagate the recursion accumulator (pairing points) as DefaultIO public inputs,
        // so the wrapped Mega proof is compatible with downstream recursive aggregation.
        MockIO out_io;
        out_io.pairing_inputs = output.points_accumulator;
        out_io.set_public();

        builder.finalize_circuit();
        auto prover_instance = std::make_shared<ProverInstance>(builder);
        auto wrapped_vk = std::make_shared<bb::MegaFlavor::VerificationKey>(prover_instance->get_precomputed());
        auto wrapped_vk_bytes = to_buffer(*wrapped_vk);
        if (out_vk) {
            *out_vk = bb_malloc_copy(wrapped_vk_bytes);
        }
        if (out_vk_len) {
            *out_vk_len = wrapped_vk_bytes.size();
        }
        return BB_STATUS_OK;
    } catch (const std::exception& e) {
        fprintf(stderr, "[bb][ERR] ultra_zk leaf vk exception: %s\n", e.what());
        return BB_STATUS_INTERNAL;
    } catch (...) {
        return BB_STATUS_INTERNAL;
    }
}

// Wrap a concrete UltraZK proof into a Mega proof that:
// - recursive-verifies the UltraZK proof against `vk`,
// - constrains Poseidon2(public_inputs[]) to equal `expected_leaf_be32`,
// - publishes that commitment as the sole *semantic* outer public input, plus DefaultIO
//   pairing-point public inputs required for recursive aggregation.
int bb_uhz_leaf_wrap(const uint8_t* proof,
                     size_t proof_len,
                     const uint8_t* vk,
                     size_t vk_len,
                     const uint8_t expected_leaf_be32[32],
                     uint8_t** out_wrapped_proof,
                     size_t* out_wrapped_proof_len,
                     uint8_t** out_wrapped_vk,
                     size_t* out_wrapped_vk_len)
{
    if (expected_leaf_be32 == nullptr) {
        return BB_STATUS_MALFORMED_PROOF;
    }

    bb::HonkProof inner_proof;
    const int proof_status = parse_honk_proof_checked(proof, proof_len, inner_proof);
    if (proof_status != BB_STATUS_OK) {
        return proof_status;
    }

    std::optional<bb::UltraZKFlavor::VerificationKey> vk_native;
    const int vk_status = parse_ultra_zk_vk_checked(vk, vk_len, vk_native);
    if (vk_status != BB_STATUS_OK) {
        return vk_status;
    }

    try {
        using Builder = bb::MegaCircuitBuilder;
        using RecFlavor = bb::UltraZKRecursiveFlavor_<Builder>;
        using OutIO = bb::stdlib::recursion::honk::DefaultIO<Builder>;
        using RecVerifier = bb::UltraVerifier_<RecFlavor, OutIO>;
        using ProverInstance = bb::ProverInstance_<bb::MegaFlavor>;

        Builder builder;
        if (!vk_native.has_value()) {
            return BB_STATUS_MALFORMED_VK;
        }
        auto native_vk = std::make_shared<bb::UltraZKFlavor::VerificationKey>(*vk_native);
        auto vk_std = std::make_shared<typename RecFlavor::VerificationKey>(&builder, native_vk);
        auto vk_hash_ff = RecFlavor::FF::from_witness(&builder, native_vk->hash());
        vk_hash_ff.unset_free_witness_tag();
        auto vk_and_hash = std::make_shared<typename RecFlavor::VKAndHash>(vk_std, vk_hash_ff);

        std::vector<typename RecFlavor::FF> proof_fields_ff;
        proof_fields_ff.reserve(inner_proof.size());
        for (const auto& field : inner_proof) {
            auto proof_field_ff = RecFlavor::FF::from_witness(&builder, field);
            proof_field_ff.unset_free_witness_tag();
            proof_fields_ff.emplace_back(proof_field_ff);
        }

        auto public_inputs = recursive_oink_public_inputs<RecFlavor>(vk_and_hash, proof_fields_ff);
        if (public_inputs.empty()) {
            return BB_STATUS_MALFORMED_PROOF;
        }
        bb::unset_free_witness_tags<true>(public_inputs);
        auto expected_leaf_native = fr_from_be32(expected_leaf_be32);
        auto expected_leaf_ff = RecFlavor::FF::from_witness(&builder, expected_leaf_native);
        expected_leaf_ff.unset_free_witness_tag();
        auto leaf_commitment = bb::stdlib::poseidon2<Builder>::hash(public_inputs);
        leaf_commitment.assert_equal(expected_leaf_ff);
        leaf_commitment.set_public();

        RecVerifier verifier{ vk_and_hash };
        typename RecVerifier::Proof stdlib_proof(proof_fields_ff);
        auto output = verifier.verify_proof(stdlib_proof);

        // Propagate the recursion accumulator (pairing points) as DefaultIO public inputs,
        // so the wrapped Mega proof is compatible with downstream recursive aggregation.
        OutIO out_io;
        out_io.pairing_inputs = output.points_accumulator;
        out_io.set_public();

        builder.finalize_circuit();
        auto prover_instance = std::make_shared<ProverInstance>(builder);
        auto wrapped_vk = std::make_shared<bb::MegaFlavor::VerificationKey>(prover_instance->get_precomputed());
        bb::UltraProver_<bb::MegaFlavor> prover{ prover_instance, wrapped_vk };
        auto wrapped_proof = prover.construct_proof();

        auto wrapped_proof_bytes = to_buffer<true>(wrapped_proof);
        auto wrapped_vk_bytes = to_buffer(*wrapped_vk);
        if (out_wrapped_proof) {
            *out_wrapped_proof = bb_malloc_copy(wrapped_proof_bytes);
        }
        if (out_wrapped_proof_len) {
            *out_wrapped_proof_len = wrapped_proof_bytes.size();
        }
        if (out_wrapped_vk) {
            *out_wrapped_vk = bb_malloc_copy(wrapped_vk_bytes);
        }
        if (out_wrapped_vk_len) {
            *out_wrapped_vk_len = wrapped_vk_bytes.size();
        }
        return BB_STATUS_OK;
    } catch (const std::exception& e) {
        fprintf(stderr, "[bb][ERR] ultra_zk leaf wrap exception: %s\n", e.what());
        return BB_STATUS_INTERNAL;
    } catch (...) {
        return BB_STATUS_INTERNAL;
    }
}

int bb_batch_merge_leaf(const uint8_t* proof_a,
                        size_t len_a,
                        const uint8_t* vk_a,
                        size_t len_vk_a,
                        const uint8_t* proof_b,
                        size_t len_b,
                        const uint8_t* vk_b,
                        size_t len_vk_b,
                        uint8_t** out_merged_proof,
                        size_t* out_merged_proof_len)
{
    std::vector<uint8_t> merged_proof_bytes;
    const int status = batch_merge_with_vks_internal(proof_a,
                                                     len_a,
                                                     vk_a,
                                                     len_vk_a,
                                                     proof_b,
                                                     len_b,
                                                     vk_b,
                                                     len_vk_b,
                                                     merged_proof_bytes);
    if (status != BB_STATUS_OK) {
        return status;
    }

    if (out_merged_proof) *out_merged_proof = bb_malloc_copy(merged_proof_bytes);
    if (out_merged_proof_len) *out_merged_proof_len = merged_proof_bytes.size();
    return BB_STATUS_OK;
}

int bb_batch_merge_leaf_with_vk(const uint8_t* proof_a,
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
    std::vector<uint8_t> merged_proof_bytes;
    std::vector<uint8_t> merged_vk_bytes;
    const int status = batch_merge_with_vks_internal(proof_a,
                                                     len_a,
                                                     vk_a,
                                                     len_vk_a,
                                                     proof_b,
                                                     len_b,
                                                     vk_b,
                                                     len_vk_b,
                                                     merged_proof_bytes,
                                                     &merged_vk_bytes);
    if (status != BB_STATUS_OK) {
        return status;
    }

    if (out_merged_proof) *out_merged_proof = bb_malloc_copy(merged_proof_bytes);
    if (out_merged_proof_len) *out_merged_proof_len = merged_proof_bytes.size();
    if (out_merged_vk) *out_merged_vk = bb_malloc_copy(merged_vk_bytes);
    if (out_merged_vk_len) *out_merged_vk_len = merged_vk_bytes.size();
    return BB_STATUS_OK;
}

int bb_batch_merge_from_leaf_merges(const uint8_t* proof_a,
                                    size_t len_a,
                                    const uint8_t* proof_b,
                                    size_t len_b,
                                    uint8_t** out_merged_proof,
                                    size_t* out_merged_proof_len)
{
    const auto& child_vk = bb::batch_merge::embedded_leaf_merge_vk();
    std::vector<uint8_t> merged_proof_bytes;
    const int status =
        batch_merge_with_child_vk_internal(proof_a, len_a, proof_b, len_b, child_vk, merged_proof_bytes);
    if (status != BB_STATUS_OK) {
        return status;
    }

    if (out_merged_proof) *out_merged_proof = bb_malloc_copy(merged_proof_bytes);
    if (out_merged_proof_len) *out_merged_proof_len = merged_proof_bytes.size();
    return BB_STATUS_OK;
}

int bb_batch_merge_from_leaf_merges_with_vk(const uint8_t* proof_a,
                                            size_t len_a,
                                            const uint8_t* proof_b,
                                            size_t len_b,
                                            uint8_t** out_merged_proof,
                                            size_t* out_merged_proof_len,
                                            uint8_t** out_merged_vk,
                                            size_t* out_merged_vk_len)
{
    const auto& child_vk = bb::batch_merge::embedded_leaf_merge_vk();
    std::vector<uint8_t> merged_proof_bytes;
    std::vector<uint8_t> merged_vk_bytes;
    const int status =
        batch_merge_with_vks_internal(proof_a,
                                      len_a,
                                      child_vk.data(),
                                      child_vk.size(),
                                      proof_b,
                                      len_b,
                                      child_vk.data(),
                                      child_vk.size(),
                                      merged_proof_bytes,
                                      &merged_vk_bytes);
    if (status != BB_STATUS_OK) {
        return status;
    }

    if (out_merged_proof) *out_merged_proof = bb_malloc_copy(merged_proof_bytes);
    if (out_merged_proof_len) *out_merged_proof_len = merged_proof_bytes.size();
    if (out_merged_vk) *out_merged_vk = bb_malloc_copy(merged_vk_bytes);
    if (out_merged_vk_len) *out_merged_vk_len = merged_vk_bytes.size();
    return BB_STATUS_OK;
}

int bb_batch_merge(const uint8_t* proof_a,
                   size_t len_a,
                   const uint8_t* proof_b,
                   size_t len_b,
                   uint8_t** out_merged_proof,
                   size_t* out_merged_proof_len)
{
    const auto& child_vk = bb::batch_merge::embedded_agg_merge_vk();
    std::vector<uint8_t> merged_proof_bytes;
    const int status =
        batch_merge_with_child_vk_internal(proof_a, len_a, proof_b, len_b, child_vk, merged_proof_bytes);
    if (status != BB_STATUS_OK) {
        return status;
    }

    if (out_merged_proof) *out_merged_proof = bb_malloc_copy(merged_proof_bytes);
    if (out_merged_proof_len) *out_merged_proof_len = merged_proof_bytes.size();
    return BB_STATUS_OK;
}

int bb_batch_merge_with_vk(const uint8_t* proof_a,
                           size_t len_a,
                           const uint8_t* proof_b,
                           size_t len_b,
                           uint8_t** out_merged_proof,
                           size_t* out_merged_proof_len,
                           uint8_t** out_merged_vk,
                           size_t* out_merged_vk_len)
{
    const auto& child_vk = bb::batch_merge::embedded_agg_merge_vk();
    std::vector<uint8_t> merged_proof_bytes;
    std::vector<uint8_t> merged_vk_bytes;
    const int status =
        batch_merge_with_vks_internal(proof_a,
                                      len_a,
                                      child_vk.data(),
                                      child_vk.size(),
                                      proof_b,
                                      len_b,
                                      child_vk.data(),
                                      child_vk.size(),
                                      merged_proof_bytes,
                                      &merged_vk_bytes);
    if (status != BB_STATUS_OK) {
        return status;
    }

    if (out_merged_proof) *out_merged_proof = bb_malloc_copy(merged_proof_bytes);
    if (out_merged_proof_len) *out_merged_proof_len = merged_proof_bytes.size();
    if (out_merged_vk) *out_merged_vk = bb_malloc_copy(merged_vk_bytes);
    if (out_merged_vk_len) *out_merged_vk_len = merged_vk_bytes.size();
    return BB_STATUS_OK;
}

} // extern "C"
