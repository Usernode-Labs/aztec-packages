#include <cstdint>
#include <cstdlib>
#include <memory>
#include <vector>
#include <filesystem>
#include <array>
#include <unordered_map>
#include <mutex>
#include <algorithm>
#include <type_traits>

#ifndef BB_ENABLE_INPLACE_REFRESH
#define BB_ENABLE_INPLACE_REFRESH 0
#endif
#include <optional>
#include <stdexcept>

#include "barretenberg/common/serialize.hpp"
#include "barretenberg/common/throw_or_abort.hpp"
#include "barretenberg/dsl/acir_format/acir_format.hpp"
#include "barretenberg/dsl/acir_format/acir_to_constraint_buf.hpp"
#include "barretenberg/merge/merge_mega.hpp"
#include "barretenberg/merge/batch_merge_h2.hpp"
#include "barretenberg/srs/global_crs.hpp"
#include "barretenberg/ultra_honk/decider_proving_key.hpp"
#include "barretenberg/stdlib_circuit_builders/mega_circuit_builder.hpp"
#include "barretenberg/honk/proof_system/types/proof.hpp"
#include "barretenberg/ultra_honk/ultra_prover.hpp"
#include "barretenberg/stdlib/special_public_inputs/special_public_inputs.hpp"
#include "barretenberg/special_public_inputs/special_public_inputs.hpp"
#include "barretenberg/stdlib/honk_verifier/oink_recursive_verifier.hpp"
#include "barretenberg/flavor/mega_recursive_flavor.hpp"
#include "barretenberg/stdlib_circuit_builders/mega_circuit_builder.hpp"
#include "barretenberg/ultra_honk/ultra_verifier.hpp"
#include "barretenberg/ultra_honk/oink_verifier.hpp"
#include "barretenberg/crypto/poseidon2/poseidon2_permutation.hpp"
#include "barretenberg/crypto/poseidon2/poseidon2_params.hpp"
#include "barretenberg/crypto/poseidon2/poseidon2.hpp"
#include "barretenberg/crypto/pedersen_commitment/pedersen.hpp"
#include "barretenberg/crypto/pedersen_hash/pedersen.hpp"
#include "barretenberg/ecc/curves/grumpkin/grumpkin.hpp"
#include "barretenberg/crypto/schnorr/schnorr.hpp"
#include "barretenberg/crypto/schnorr/schnorr.tcc"
#include "barretenberg/crypto/blake2s/blake2s.hpp"

using ::to_buffer;
using ::from_buffer;

// Local helper for BN254 fr -> 32-byte big-endian without depending on C-linkage symbols
static inline void le_limbs_to_be32_local(const uint64_t in_le[4], uint8_t* out_be)
{
    for (size_t i = 0; i < 4; ++i) {
        uint64_t limb = in_le[3 - i];
        for (size_t j = 0; j < 8; ++j) {
            out_be[i * 8 + (7 - j)] = static_cast<uint8_t>(limb & 0xff);
            limb >>= 8;
        }
    }
}

static inline std::array<uint8_t, 32> fr_to_be32_local(const bb::fr& a)
{
    auto norm = bb::fr(a).from_montgomery_form();
    std::array<uint8_t, 32> out{};
    le_limbs_to_be32_local(norm.data, out.data());
    return out;
}

namespace {

struct KeyId {
    std::array<uint8_t, 32> bytes{};
    bool operator==(const KeyId&) const = default;
};

struct KeyIdHash {
    size_t operator()(const KeyId& key) const noexcept
    {
        size_t acc = 0;
        for (auto byte : key.bytes) {
            acc = (acc * 131) ^ static_cast<size_t>(byte);
        }
        return acc;
    }
};

struct MegaKeyEntry {
    std::shared_ptr<bb::DeciderProvingKey_<bb::MegaFlavor>> proving_key;
    std::shared_ptr<bb::MegaFlavor::VerificationKey> verification_key;
    std::vector<uint8_t> acir_bytes; // to recreate builders for witness refresh
};

struct MegaKeyCache {
    std::unordered_map<KeyId, MegaKeyEntry, KeyIdHash> map;
    std::mutex mutex;
};

MegaKeyCache& mega_cache()
{
    static MegaKeyCache cache;
    return cache;
}

KeyId key_id_from_field(const bb::fr& h)
{
    KeyId id;
    auto be = fr_to_be32_local(h);
    std::copy(be.begin(), be.end(), id.bytes.begin());
    return id;
}

KeyId cache_mega_keys(const std::shared_ptr<bb::DeciderProvingKey_<bb::MegaFlavor>>& proving_key,
                      const std::shared_ptr<bb::MegaFlavor::VerificationKey>& verification_key,
                      std::vector<uint8_t> acir_bytes)
{
    auto id = key_id_from_field(verification_key->hash());
    auto& cache = mega_cache();
    {
        std::lock_guard<std::mutex> lock(cache.mutex);
        cache.map[id] = MegaKeyEntry{ proving_key, verification_key, std::move(acir_bytes) };
    }
    return id;
}

std::optional<MegaKeyEntry> get_cached_mega_keys(const KeyId& id)
{
    auto& cache = mega_cache();
    std::lock_guard<std::mutex> lock(cache.mutex);
    auto it = cache.map.find(id);
    if (it == cache.map.end()) {
        return std::nullopt;
    }
    return it->second;
}

MegaKeyEntry require_cached_mega_keys(const KeyId& id)
{
    auto maybe_entry = get_cached_mega_keys(id);
    if (!maybe_entry.has_value()) {
        throw std::runtime_error("mega key id not found");
    }
    return *maybe_entry;
}

} // namespace

extern "C" {

static constexpr size_t MEGA_KEY_ID_SIZE = 32;
// Forward declare helper for BN254 fr -> 32-byte big-endian used by multiple shims below
static inline std::vector<uint8_t> fr_to_be32(const bb::fr& a);

static inline KeyId key_id_from_bytes(const uint8_t* data, size_t len)
{
    if (len != MEGA_KEY_ID_SIZE) {
        throw std::invalid_argument("key id must be 32 bytes");
    }
    KeyId id;
    std::copy(data, data + MEGA_KEY_ID_SIZE, id.bytes.begin());
    return id;
}

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
        std::vector<uint8_t> acir_vec(acir, acir + acir_len);
        const acir_format::ProgramMetadata metadata{ .honk_recursion = 1 };
        acir_format::AcirProgram program{ acir_format::circuit_buf_to_acir_format(std::move(acir_vec)) };
        auto builder = acir_format::create_circuit<bb::MegaCircuitBuilder>(program, metadata);
        builder.finalize_circuit(true);
        const uint32_t total = static_cast<uint32_t>(builder.get_finalized_total_circuit_size());
        const uint32_t subgroup = static_cast<uint32_t>(
            builder.get_circuit_subgroup_size(builder.get_finalized_total_circuit_size()));
        if (out_total) *out_total = total;
        if (out_subgroup) *out_subgroup = subgroup;
        return 0;
    } catch (const std::exception& e) {
        fprintf(stderr, "[bb][ERR] acir_sizes exception: %s\n", e.what());
        return 1;
    } catch (...) {
        fprintf(stderr, "[bb][ERR] acir_sizes unknown exception\n");
        return 1;
    }
}

// Internal helper: refresh witness-dependent polynomials in a cached proving key from a fresh builder
#if BB_ENABLE_INPLACE_REFRESH
static void mh_refresh_witness_polynomials(bb::MegaCircuitBuilder& builder,
                                           bb::DeciderProvingKey_<bb::MegaFlavor>& pk)
{
    builder.blocks.compute_offsets(pk.get_is_structured());

    auto wires = pk.polynomials.get_wires();
    using WireField = typename std::remove_reference_t<decltype(wires[0])>::FF;
    std::array<WireField*, bb::MegaCircuitBuilder::NUM_WIRES> wire_ptrs{};
    std::array<size_t, bb::MegaCircuitBuilder::NUM_WIRES> wire_start{};
    for (size_t w = 0; w < bb::MegaCircuitBuilder::NUM_WIRES; ++w) {
        wire_ptrs[w] = wires[w].data();
        wire_start[w] = wires[w].start_index();
    }

    const auto& variables = builder.get_variables();
    const auto& real_var_index = builder.real_variable_index;

    size_t final_active_wire_idx = 0;
    for (auto& block : builder.blocks.get()) {
        const uint32_t offset = block.trace_offset();
        const uint32_t block_size = static_cast<uint32_t>(block.size());
        if (block_size == 0) {
            continue;
        }
        final_active_wire_idx = offset + block_size - 1;
        for (size_t w = 0; w < bb::MegaCircuitBuilder::NUM_WIRES; ++w) {
            auto* dest = wire_ptrs[w];
            if (!dest) {
                continue;
            }
            const size_t start = wire_start[w];
            for (uint32_t row = 0; row < block_size; ++row) {
                const uint32_t var_idx = block.wires[w][row];
                const ptrdiff_t dst_index = static_cast<ptrdiff_t>(offset + row) - static_cast<ptrdiff_t>(start);
                BB_ASSERT_GTE(dst_index, 0);
                dest[dst_index] = variables[real_var_index[var_idx]];
            }
        }
    }
    pk.set_final_active_wire_idx(final_active_wire_idx);

    const size_t wire_idx_offset = bb::MegaFlavor::has_zero_row ? 1 : 0;
    const size_t num_ecc_ops = builder.blocks.ecc_op.size();
    auto ecc_wires = pk.polynomials.get_ecc_op_wires();
    for (size_t wire_i = 0; wire_i < ecc_wires.size(); ++wire_i) {
        for (size_t i = 0; i < num_ecc_ops; ++i) {
            ecc_wires[wire_i].at(i) = wires[wire_i][i + wire_idx_offset];
        }
    }
    for (size_t i = 0; i < num_ecc_ops; ++i) {
        pk.polynomials.lagrange_ecc_op.at(i) = 1;
    }

    if constexpr (bb::HasDataBus<bb::MegaFlavor>) {
        const auto& calldata = builder.get_calldata();
        const auto& secondary_calldata = builder.get_secondary_calldata();
        const auto& return_data = builder.get_return_data();

        for (size_t idx = 0; idx < calldata.size(); ++idx) {
            pk.polynomials.calldata.at(idx) = builder.get_variable(calldata[idx]);
            pk.polynomials.calldata_read_counts.at(idx) = calldata.get_read_count(idx);
            pk.polynomials.calldata_read_tags.at(idx) = pk.polynomials.calldata_read_counts[idx] > 0 ? 1 : 0;
        }
        for (size_t idx = 0; idx < secondary_calldata.size(); ++idx) {
            pk.polynomials.secondary_calldata.at(idx) = builder.get_variable(secondary_calldata[idx]);
            pk.polynomials.secondary_calldata_read_counts.at(idx) = secondary_calldata.get_read_count(idx);
            pk.polynomials.secondary_calldata_read_tags.at(idx) =
                pk.polynomials.secondary_calldata_read_counts[idx] > 0 ? 1 : 0;
        }
        for (size_t idx = 0; idx < return_data.size(); ++idx) {
            pk.polynomials.return_data.at(idx) = builder.get_variable(return_data[idx]);
            pk.polynomials.return_data_read_counts.at(idx) = return_data.get_read_count(idx);
            pk.polynomials.return_data_read_tags.at(idx) = pk.polynomials.return_data_read_counts[idx] > 0 ? 1 : 0;
        }
    }

    const uint32_t ram_rom_offset = builder.blocks.memory.trace_offset();
    pk.memory_read_records.clear();
    pk.memory_read_records.reserve(builder.memory_read_records.size());
    for (auto idx : builder.memory_read_records) {
        pk.memory_read_records.emplace_back(idx + ram_rom_offset);
    }
    pk.memory_write_records.clear();
    pk.memory_write_records.reserve(builder.memory_write_records.size());
    for (auto idx : builder.memory_write_records) {
        pk.memory_write_records.emplace_back(idx + ram_rom_offset);
    }

    pk.public_inputs.clear();
    size_t npi = pk.get_metadata().num_public_inputs;
    for (size_t i = 0; i < npi; ++i) {
        size_t idx = i + pk.pub_inputs_offset();
        pk.public_inputs.emplace_back(pk.polynomials.w_r[idx]);
    }

    pk.polynomials.set_shifted();
    pk.polynomials.lagrange_first.at(0) = 1;
    pk.polynomials.lagrange_last.at(pk.get_final_active_wire_idx()) = 1;

    auto zero_poly = [](auto& poly) {
        using Poly = std::remove_reference_t<decltype(poly)>;
        using Field = typename Poly::FF;
        Field* begin = poly.data();
        if (!begin) {
            return;
        }
        Field* end = begin + (poly.end_index() - poly.start_index());
        std::fill(begin, end, Field());
    };

    zero_poly(pk.polynomials.lookup_inverses);
    zero_poly(pk.polynomials.lookup_read_counts);
    zero_poly(pk.polynomials.lookup_read_tags);
    if constexpr (bb::HasDataBus<bb::MegaFlavor>) {
        zero_poly(pk.polynomials.calldata_inverses);
        zero_poly(pk.polynomials.secondary_calldata_inverses);
        zero_poly(pk.polynomials.return_data_inverses);
    }
    zero_poly(pk.polynomials.z_perm);

    auto& rc = pk.polynomials.lookup_read_counts;
    auto& rt = pk.polynomials.lookup_read_tags;
    construct_lookup_read_counts<bb::MegaFlavor>(rc, rt, builder, pk.dyadic_size());
}
#endif

int bb_acir_compile_mega_honk(const uint8_t* acir, size_t acir_len, uint8_t out_key_id[MEGA_KEY_ID_SIZE])
{
    try {
        std::vector<uint8_t> acir_vec(acir, acir + acir_len);
        const acir_format::ProgramMetadata metadata{ .honk_recursion = 1 };
        acir_format::AcirProgram program{ acir_format::circuit_buf_to_acir_format(std::move(acir_vec)) };
        auto builder = acir_format::create_circuit<bb::MegaCircuitBuilder>(program, metadata);
        using DeciderProvingKey = bb::DeciderProvingKey_<bb::MegaFlavor>;
        auto proving_key = std::make_shared<DeciderProvingKey>(builder);
        auto verification_key = std::make_shared<bb::MegaFlavor::VerificationKey>(proving_key->get_precomputed());
        // Recreate acir bytes from program (we no longer have the original vector after move)
        // Instead, use the input buffer directly
        std::vector<uint8_t> acir_copy(acir, acir + acir_len);
        auto id = cache_mega_keys(proving_key, verification_key, std::move(acir_copy));
        std::copy(id.bytes.begin(), id.bytes.end(), out_key_id);
        return 0;
    } catch (const std::exception& e) {
        fprintf(stderr, "[bb][ERR] compile_mega exception: %s\n", e.what());
        return 1;
    } catch (...) {
        fprintf(stderr, "[bb][ERR] compile_mega unknown exception\n");
        return 1;
    }
}

int bb_mh_write_vk(const uint8_t* acir, size_t acir_len, uint8_t** out_vk, size_t* out_vk_len)
{
    try {
        std::vector<uint8_t> acir_vec(acir, acir + acir_len);
        const acir_format::ProgramMetadata metadata{ .honk_recursion = 1 };
        acir_format::AcirProgram program{ acir_format::circuit_buf_to_acir_format(std::move(acir_vec)) };
        auto builder = acir_format::create_circuit<bb::MegaCircuitBuilder>(program, metadata);

        using DeciderProvingKey = bb::DeciderProvingKey_<bb::MegaFlavor>;
        using VerificationKey = bb::MegaFlavor::VerificationKey;
        DeciderProvingKey proving_key(builder);
        VerificationKey vk(proving_key.get_precomputed());
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
        const acir_format::ProgramMetadata metadata{ .honk_recursion = 1 };
        acir_format::AcirProgram program{ acir_format::circuit_buf_to_acir_format(std::move(acir_vec)),
                                          acir_format::witness_buf_to_witness_data(std::move(wit_vec)) };
        auto builder = acir_format::create_circuit<bb::MegaCircuitBuilder>(program, metadata);
        using DeciderProvingKey = bb::DeciderProvingKey_<bb::MegaFlavor>;
        using VerificationKey = bb::MegaFlavor::VerificationKey;
        auto proving_key = std::make_shared<DeciderProvingKey>(builder);
        auto verification_key = std::make_shared<VerificationKey>(proving_key->get_precomputed());
        bb::UltraProver_<bb::MegaFlavor> prover{ proving_key, verification_key };
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

// Prove using a cached compile-only Mega proving key identified by key_id.
// Rebuilds a builder from cached ACIR + provided witness, refreshes witness polynomials in the proving key,
// constructs the proof, and returns serialized proof bytes.
int bb_mh_prove_with_id(const uint8_t key_id[MEGA_KEY_ID_SIZE],
                        const uint8_t* witness,
                        size_t witness_len,
                        uint8_t** out_proof,
                        size_t* out_proof_len)
{
    try {
        auto id = key_id_from_bytes(key_id, MEGA_KEY_ID_SIZE);
        auto entry = require_cached_mega_keys(id);
        // Recreate builder with witness
        std::vector<uint8_t> acir_copy = entry.acir_bytes;
        std::vector<uint8_t> wit_vec(witness, witness + witness_len);
        const acir_format::ProgramMetadata metadata{ .honk_recursion = 1 };
        acir_format::AcirProgram program{ acir_format::circuit_buf_to_acir_format(std::move(acir_copy)),
                                          acir_format::witness_buf_to_witness_data(std::move(wit_vec)) };
        auto builder = acir_format::create_circuit<bb::MegaCircuitBuilder>(program, metadata);

        using DeciderProvingKey = bb::DeciderProvingKey_<bb::MegaFlavor>;
        using VerificationKey = bb::MegaFlavor::VerificationKey;

        std::shared_ptr<DeciderProvingKey> proving_key;

#if BB_ENABLE_INPLACE_REFRESH
        std::shared_ptr<DeciderProvingKey> tmp_pk_for_diff;
        [[maybe_unused]] const bool use_refresh = []() {
            const char* e = std::getenv("BB_REFRESH_IN_PLACE");
            return e && std::string(e) == "1";
        }();

        if (use_refresh) {
            mh_refresh_witness_polynomials(builder, *entry.proving_key);

            const bool use_deep_copy = []() {
                const char* e = std::getenv("BB_REFRESH_DEEP_COPY");
                return (!e) || std::string(e) == "1";
            }();
            const bool log_proof_diff = []() {
                const char* e = std::getenv("BB_LOG_PROOF_DIFF");
                return e && std::string(e) == "1";
            }();

            const bool need_tmp_pk = use_deep_copy || log_proof_diff;
            std::shared_ptr<DeciderProvingKey> tmp_pk;
            if (need_tmp_pk) {
                tmp_pk = std::make_shared<DeciderProvingKey>(builder);
            }
            if (log_proof_diff && tmp_pk) {
                tmp_pk_for_diff = tmp_pk;
            }

            if (use_deep_copy && tmp_pk) {
                auto copy_polys = [](auto dst, const auto& src) {
                    for (size_t i = 0; i < dst.size(); ++i) {
                        dst[i] = src[i];
                    }
                };
                copy_polys(entry.proving_key->polynomials.get_sigmas(), tmp_pk->polynomials.get_sigmas());
                copy_polys(entry.proving_key->polynomials.get_ids(), tmp_pk->polynomials.get_ids());
                copy_polys(entry.proving_key->polynomials.get_gate_selectors(), tmp_pk->polynomials.get_gate_selectors());
                copy_polys(entry.proving_key->polynomials.get_non_gate_selectors(),
                           tmp_pk->polynomials.get_non_gate_selectors());
                entry.proving_key->polynomials.lagrange_first = tmp_pk->polynomials.lagrange_first;
                entry.proving_key->polynomials.lagrange_last = tmp_pk->polynomials.lagrange_last;
                entry.proving_key->polynomials.lagrange_ecc_op = tmp_pk->polynomials.lagrange_ecc_op;
                entry.proving_key->polynomials.databus_id = tmp_pk->polynomials.databus_id;

                copy_polys(entry.proving_key->polynomials.get_wires(), tmp_pk->polynomials.get_wires());
                copy_polys(entry.proving_key->polynomials.get_ecc_op_wires(), tmp_pk->polynomials.get_ecc_op_wires());
                if constexpr (bb::HasDataBus<bb::MegaFlavor>) {
                    entry.proving_key->polynomials.calldata = tmp_pk->polynomials.calldata;
                    entry.proving_key->polynomials.calldata_read_counts = tmp_pk->polynomials.calldata_read_counts;
                    entry.proving_key->polynomials.calldata_read_tags = tmp_pk->polynomials.calldata_read_tags;
                    entry.proving_key->polynomials.secondary_calldata = tmp_pk->polynomials.secondary_calldata;
                    entry.proving_key->polynomials.secondary_calldata_read_counts =
                        tmp_pk->polynomials.secondary_calldata_read_counts;
                    entry.proving_key->polynomials.secondary_calldata_read_tags =
                        tmp_pk->polynomials.secondary_calldata_read_tags;
                    entry.proving_key->polynomials.return_data = tmp_pk->polynomials.return_data;
                    entry.proving_key->polynomials.return_data_read_counts = tmp_pk->polynomials.return_data_read_counts;
                    entry.proving_key->polynomials.return_data_read_tags = tmp_pk->polynomials.return_data_read_tags;
                    entry.proving_key->polynomials.calldata_inverses = tmp_pk->polynomials.calldata_inverses;
                    entry.proving_key->polynomials.secondary_calldata_inverses =
                        tmp_pk->polynomials.secondary_calldata_inverses;
                    entry.proving_key->polynomials.return_data_inverses = tmp_pk->polynomials.return_data_inverses;
                }
                entry.proving_key->public_inputs = tmp_pk->public_inputs;
                entry.proving_key->memory_read_records = tmp_pk->memory_read_records;
                entry.proving_key->memory_write_records = tmp_pk->memory_write_records;
                entry.proving_key->polynomials.lookup_read_counts = tmp_pk->polynomials.lookup_read_counts;
                entry.proving_key->polynomials.lookup_read_tags = tmp_pk->polynomials.lookup_read_tags;
                entry.proving_key->polynomials.set_shifted();
            }

            entry.proving_key->commitment_key = bb::MegaFlavor::CommitmentKey();
            entry.proving_key->is_complete = false;
            entry.proving_key->gate_challenges.assign(entry.proving_key->gate_challenges.size(), bb::fr(0));
            entry.proving_key->target_sum = bb::fr(0);
            entry.proving_key->alphas = typename bb::MegaFlavor::SubrelationSeparators{};
            entry.proving_key->relation_parameters = bb::RelationParameters<bb::fr>{};

            if (use_deep_copy && tmp_pk) {
                auto refreshed_vk = std::make_shared<VerificationKey>(entry.proving_key->get_precomputed());
                entry.verification_key = refreshed_vk;
            }

            const bool use_tmp_for_prove = []() {
                const char* e = std::getenv("BB_REFRESH_TMP_PROVE");
                return e && std::string(e) == "1";
            }();
            if (!use_deep_copy && use_tmp_for_prove && tmp_pk) {
                proving_key = tmp_pk;
            } else {
                proving_key = entry.proving_key;
            }
        } else
#endif
        {
            proving_key = std::make_shared<DeciderProvingKey>(builder);
            auto verification_key = std::make_shared<VerificationKey>(proving_key->get_precomputed());
            auto id_now = key_id_from_field(verification_key->hash());
            if (!(id_now == id)) {
                throw std::runtime_error("prove_with_id: VK hash mismatch for cached ID");
            }
            entry.verification_key = verification_key;
        }

        bb::UltraProver_<bb::MegaFlavor> prover{ proving_key, entry.verification_key };
        auto proof = prover.construct_proof();
        auto proof_buf = to_buffer<true>(proof);

#if BB_ENABLE_INPLACE_REFRESH
        if (tmp_pk_for_diff) {
            try {
                bb::UltraProver_<bb::MegaFlavor> prover_tmp{ tmp_pk_for_diff, entry.verification_key };
                auto proof_tmp = prover_tmp.construct_proof();
                if (const char* diff = std::getenv("BB_LOG_PROOF_DIFF"); diff && std::string(diff) == "1") {
                    const size_t min_sz = std::min(proof.size(), proof_tmp.size());
                    size_t mismatches = 0;
                    for (size_t i = 0; i < min_sz; ++i) {
                        if (proof[i] != proof_tmp[i]) {
                            ++mismatches;
                            if (mismatches >= 8) {
                                break;
                            }
                        }
                    }
                }
            } catch (...) {
                // ignore diff failures in production builds
            }
        }
#endif

        if (out_proof) *out_proof = bb_malloc_copy(proof_buf);
        if (out_proof_len) *out_proof_len = proof_buf.size();
        return 0;
    } catch (const std::exception& e) {
        fprintf(stderr, "[bb][ERR] prove_with_id exception: %s\n", e.what());
        return 1;
    } catch (...) {
        fprintf(stderr, "[bb][ERR] prove_with_id unknown exception\n");
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

        // Decide IO strategy based on VK public inputs: if exactly 7, this is a merged
        // proof exposing only the binding block, so use BindingBlockIO to avoid
        // expecting DefaultIO pairing points. Otherwise, default to DefaultIO.
        using Builder = bb::MegaCircuitBuilder;
        using DefaultIO = bb::stdlib::recursion::honk::DefaultIO<Builder>;
        using BindingIO = bb::BindingBlockIO;
        const size_t total_pub = static_cast<size_t>(vk_raw.num_public_inputs);
        const size_t default_pub = static_cast<size_t>(DefaultIO::PUBLIC_INPUTS_SIZE);
        size_t inner_pub = (total_pub > default_pub) ? (total_pub - default_pub) : 0;
        if (inner_pub == 0 && total_pub > 0) {
            inner_pub = total_pub; // No DefaultIO present; treat all as inner
        }

        bool ok = false;
        if (inner_pub == BindingIO::PUBLIC_INPUTS_SIZE) {
            ok = verifier.template verify_proof<BindingIO>(proof_obj).result;
        } else {
            ok = verifier.template verify_proof<bb::DefaultIO>(proof_obj).result;
        }
        if (out_ok) *out_ok = ok;
        return 0;
    } catch (...) {
        return 1;
    }
}

// Verify using cached VK by key_id.
int bb_mh_verify_with_id(const uint8_t key_id[MEGA_KEY_ID_SIZE],
                         const uint8_t* proof,
                         size_t proof_len,
                         bool* out_ok)
{
    try {
        auto id = key_id_from_bytes(key_id, MEGA_KEY_ID_SIZE);
        auto entry = require_cached_mega_keys(id);
        std::vector<uint8_t> proof_bytes(proof, proof + proof_len);
        auto proof_obj = from_buffer<bb::HonkProof>(proof_bytes);
        bb::MegaVerifier verifier{ entry.verification_key };

        // Determine IO strategy from VK public inputs
        using Builder = bb::MegaCircuitBuilder;
        using DefaultIO = bb::stdlib::recursion::honk::DefaultIO<Builder>;
        using BindingIO = bb::BindingBlockIO;
        const size_t total_pub = static_cast<size_t>(entry.verification_key->num_public_inputs);
        const size_t default_pub = static_cast<size_t>(DefaultIO::PUBLIC_INPUTS_SIZE);
        size_t inner_pub = (total_pub > default_pub) ? (total_pub - default_pub) : 0;
        if (inner_pub == 0 && total_pub > 0) {
            inner_pub = total_pub;
        }

        bool ok = false;
        if (inner_pub == BindingIO::PUBLIC_INPUTS_SIZE) {
            ok = verifier.template verify_proof<BindingIO>(proof_obj).result;
        } else {
            ok = verifier.template verify_proof<bb::DefaultIO>(proof_obj).result;
        }
        if (out_ok) *out_ok = ok;
        return 0;
    } catch (const std::exception& e) {
        fprintf(stderr, "[bb][ERR] verify_with_id exception: %s\n", e.what());
        return 1;
    } catch (...) {
        return 1;
    }
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
    try {
        std::vector<uint8_t> proof_bytes(proof, proof + proof_len);
        std::vector<uint8_t> vk_bytes(vk, vk + vk_len);
        auto vk_native = from_buffer<bb::MegaFlavor::VerificationKey>(vk_bytes);
        const size_t total_pub = static_cast<size_t>(vk_native.num_public_inputs);
        using Builder = bb::MegaCircuitBuilder;
        using DefaultIO = bb::stdlib::recursion::honk::DefaultIO<Builder>;
        const size_t default_pub = static_cast<size_t>(DefaultIO::PUBLIC_INPUTS_SIZE);
        size_t inner_pub = (total_pub > default_pub) ? (total_pub - default_pub) : 0;
        if (inner_pub == 0 && total_pub > 0) {
            inner_pub = total_pub; // No DefaultIO present; return all PIs as inner
        }
        auto proof_fields = from_buffer<std::vector<bb::fr>>(proof_bytes);
        
        std::vector<uint8_t> out;
        out.reserve(inner_pub * 32);
        // Prefer native Oink parse to match transcript extraction order
        bool used_oink = false;
        try {
            auto proof_obj = from_buffer<bb::HonkProof>(proof_bytes);
            auto vk_ptr = std::make_shared<bb::MegaFlavor::VerificationKey>(vk_native);
            auto decider_vk = std::make_shared<bb::DeciderVerificationKey_<bb::MegaFlavor>>(vk_ptr);
            auto transcript = std::make_shared<bb::NativeTranscript>();
            transcript->load_proof(proof_obj);
            bb::OinkVerifier<bb::MegaFlavor> oink(decider_vk, transcript);
            oink.verify();
            for (size_t i = 0; i < inner_pub && i < oink.public_inputs.size(); ++i) {
                auto be = fr_to_be32(oink.public_inputs[i]);
                out.insert(out.end(), be.begin(), be.end());
            }
            used_oink = true;
        } catch (...) {
            used_oink = false;
        }
        if (!used_oink) {
            // Fallback: avoid out-of-bounds in case of malformed proof
            if (inner_pub > proof_fields.size()) {
                inner_pub = proof_fields.size();
            }
            // Fallback: best-effort head slice for inner PIs
            for (size_t i = 0; i < inner_pub && i < proof_fields.size(); ++i) {
                auto be = fr_to_be32(proof_fields[i]);
                out.insert(out.end(), be.begin(), be.end());
            }
        }
        
        if (out_ptr) *out_ptr = bb_malloc_copy(out);
        if (out_len) *out_len = out.size();
        return 0;
    } catch (...) {
        return 1;
    }
}

// Compute Mega VK hash as a 32-byte big-endian field element.
int bb_mh_vk_hash(const uint8_t* vk,
                  size_t vk_len,
                  uint8_t out_be32[32])
{
    try {
        std::vector<uint8_t> vk_bytes(vk, vk + vk_len);
        auto vk_native = from_buffer<bb::MegaFlavor::VerificationKey>(vk_bytes);
        auto h = vk_native.hash();
        auto be = fr_to_be32(h);
        std::memcpy(out_be32, be.data(), 32);
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

// Batch-merge using a dedicated circuit that computes and constrains
// parent = Poseidon2(tag=20, left, right) and publishes binding data. VK allowlist
// is expected to be enforced off-circuit via published VK hashes.
int bb_batch_merge_h2(const uint8_t* proof_a,
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
        auto res = bb::batch_merge_h2::merge(pa, vka, pb, vkb);
        if (out_merged_proof) *out_merged_proof = bb_malloc_copy(res.merged_proof_bytes);
        if (out_merged_proof_len) *out_merged_proof_len = res.merged_proof_bytes.size();
        if (out_merged_vk) *out_merged_vk = bb_malloc_copy(res.merged_vk_bytes);
        if (out_merged_vk_len) *out_merged_vk_len = res.merged_vk_bytes.size();
        return 0;
    } catch (const std::exception& e) {
        fprintf(stderr, "[bb][shim][ERR] batch_merge_h2 exception: %s\n", e.what());
        return 1;
    } catch (...) {
        fprintf(stderr, "[bb][shim][ERR] batch_merge_h2 unknown exception\n");
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

// Removed experimental Poseidon2 Schnorr verify (_xy)

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
        auto A = grumpkin_affine_from_xy(pk1_x_be, pk1_y_be);
        auto B = grumpkin_affine_from_xy(pk2_x_be, pk2_y_be);
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

int bb_grumpkin_compress(const uint8_t pk_x_be[32], const uint8_t pk_y_be[32], uint8_t out_comp_be[32])
{
    try {
        auto P = grumpkin_affine_from_xy(pk_x_be, pk_y_be);
        if (!P.on_curve() || P.is_point_at_infinity()) {
            return 2;
        }
        auto compressed = P.compress();
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

// Hash-to-curve mapping for Grumpkin.
// Map a sequence of 32‑byte big-endian base-field elements to a Grumpkin point
// using a domain-separated Pedersen commit. When a native hash_to_curve is
// available, this function can delegate to it.
int bb_grumpkin_hash_to_curve(
    const uint8_t* inputs_be,
    size_t n_elems,
    uint32_t domain,
    uint8_t out_x_be[32],
    uint8_t out_y_be[32])
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
// ----------------------------------------------------------------------------
// Grumpkin scalar field (fr) arithmetic with 32-byte big-endian I/O
// ----------------------------------------------------------------------------
extern "C" {
static inline bb::grumpkin::fr grumpkin_fr_from_be32(const uint8_t be[32])
{
    uint64_t limbs[4];
    be32_to_le_limbs(be, limbs);
    bb::grumpkin::fr v(limbs[0], limbs[1], limbs[2], limbs[3]);
    return v.to_montgomery_form();
}

static inline std::vector<uint8_t> grumpkin_fr_to_be32(const bb::grumpkin::fr& a)
{
    auto norm = bb::grumpkin::fr(a).from_montgomery_form();
    std::vector<uint8_t> out(32);
    le_limbs_to_be32(norm.data, out.data());
    return out;
}

int bb_grumpkin_fr_add(const uint8_t* a32, const uint8_t* b32, uint8_t** out_ptr, size_t* out_len)
{
    try {
        auto a = grumpkin_fr_from_be32(a32);
        auto b = grumpkin_fr_from_be32(b32);
        bb::grumpkin::fr c = a + b;
        auto out = grumpkin_fr_to_be32(c);
        if (out_ptr) *out_ptr = bb_malloc_copy(out);
        if (out_len) *out_len = out.size();
        return 0;
    } catch (...) {
        return 1;
    }
}

int bb_grumpkin_fr_sub(const uint8_t* a32, const uint8_t* b32, uint8_t** out_ptr, size_t* out_len)
{
    try {
        auto a = grumpkin_fr_from_be32(a32);
        auto b = grumpkin_fr_from_be32(b32);
        bb::grumpkin::fr c = a - b;
        auto out = grumpkin_fr_to_be32(c);
        if (out_ptr) *out_ptr = bb_malloc_copy(out);
        if (out_len) *out_len = out.size();
        return 0;
    } catch (...) {
        return 1;
    }
}

int bb_grumpkin_fr_mul(const uint8_t* a32, const uint8_t* b32, uint8_t** out_ptr, size_t* out_len)
{
    try {
        auto a = grumpkin_fr_from_be32(a32);
        auto b = grumpkin_fr_from_be32(b32);
        bb::grumpkin::fr c = a * b;
        auto out = grumpkin_fr_to_be32(c);
        if (out_ptr) *out_ptr = bb_malloc_copy(out);
        if (out_len) *out_len = out.size();
        return 0;
    } catch (...) {
        return 1;
    }
}
} 
// Removed experimental Pedersen Schnorr (sign/verify) and its hasher

extern "C" {
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

// Removed experimental Poseidon2 Schnorr sign
// Compute Poseidon2 hash over proof fields with a domain tag (as used in batch circuit binding).
extern "C" int bb_mh_proof_fields_hash(const uint8_t* proof,
                            size_t proof_len,
                            uint32_t tag,
                            uint8_t out_be32[32])
{
    try {
        std::vector<uint8_t> proof_bytes(proof, proof + proof_len);
        auto proof_fields = from_buffer<std::vector<bb::fr>>(proof_bytes);
        using Params = bb::crypto::Poseidon2Bn254ScalarFieldParams;
        // Build state = Poseidon2 hash over [tag, fields...]
        // We reuse the stdlib hash layout: tag is the first element.
        // Here we implement a simple sponge-based hash equivalent to stdlib::poseidon2::hash over a vector.
        // For consistency, we delegate to the standard hash helper used elsewhere when available.
        // For now, just fold with a simple permutation-based compression: not exposed; use Params::hash.
        // Use helper: barretenberg has crypto::Poseidon2 hasher over spans; we can use a small adapter.
        std::vector<bb::fr> inputs;
        inputs.reserve(proof_fields.size() + 1);
        inputs.emplace_back(bb::fr(uint256_t(tag)));
        inputs.insert(inputs.end(), proof_fields.begin(), proof_fields.end());
        auto digest = bb::crypto::Poseidon2<Params>::hash(inputs);
        auto be = fr_to_be32(digest);
        
        std::memcpy(out_be32, be.data(), 32);
        return 0;
    } catch (...) {
        return 1;
    }
}
