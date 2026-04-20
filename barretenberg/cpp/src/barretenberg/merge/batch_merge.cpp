#include "batch_merge.hpp"

#include "barretenberg/common/serialize.hpp"
#include "barretenberg/common/throw_or_abort.hpp"
#include "barretenberg/flavor/mega_flavor.hpp"
#include "barretenberg/flavor/mega_recursive_flavor.hpp"
#include "barretenberg/stdlib/hash/poseidon2/poseidon2.hpp"
#include "barretenberg/ultra_honk/prover_instance.hpp"
#include "barretenberg/ultra_honk/ultra_prover.hpp"
#include "barretenberg/ultra_honk/ultra_verifier.hpp"
#include "batch_merge_embedded_vks.hpp"
#include <stdexcept>

namespace bb::batch_merge {

static constexpr uint256_t BATCH_PARENT_HASH_TAG = 20;
static constexpr uint256_t BATCH_INPUTS_ROOT_TAG = 21;
static constexpr uint256_t BATCH_OUTPUTS_ROOT_TAG = 22;

MergeResult merge(const std::vector<uint8_t>& proofA_fields_buf,
                  const std::vector<uint8_t>& vkA_bytes,
                  const std::vector<uint8_t>& proofB_fields_buf,
                  const std::vector<uint8_t>& vkB_bytes)
{
    using NativeVK = bb::MegaFlavor::VerificationKey;
    using Builder = bb::MegaCircuitBuilder;
    using RecFlavor = bb::MegaRecursiveFlavor_<Builder>;
    using DefaultIO = bb::stdlib::recursion::honk::DefaultIO<Builder>;
    using RecVerifier = bb::UltraVerifier_<RecFlavor, DefaultIO>;
    using ProverInstance = bb::ProverInstance_<bb::MegaFlavor>;

    std::vector<bb::fr> proofA_fields = from_buffer<std::vector<bb::fr>>(proofA_fields_buf);
    std::vector<bb::fr> proofB_fields = from_buffer<std::vector<bb::fr>>(proofB_fields_buf);
    auto vkA_native = std::make_shared<NativeVK>(from_buffer<NativeVK>(vkA_bytes));
    auto vkB_native = std::make_shared<NativeVK>(from_buffer<NativeVK>(vkB_bytes));

    Builder builder;
    try {
        auto vkA_std = std::make_shared<typename RecFlavor::VerificationKey>(&builder, vkA_native);
        auto vkB_std = std::make_shared<typename RecFlavor::VerificationKey>(&builder, vkB_native);
        auto vkA_hash_ff = RecFlavor::FF::from_witness(&builder, vkA_native->hash());
        auto vkB_hash_ff = RecFlavor::FF::from_witness(&builder, vkB_native->hash());
        vkA_hash_ff.unset_free_witness_tag();
        vkB_hash_ff.unset_free_witness_tag();
        auto vkA_and_hash = std::make_shared<typename RecFlavor::VKAndHash>(vkA_std, vkA_hash_ff);
        auto vkB_and_hash = std::make_shared<typename RecFlavor::VKAndHash>(vkB_std, vkB_hash_ff);

        auto to_ff_local = [&](const std::vector<bb::fr>& xs) {
            std::vector<typename RecFlavor::FF> out;
            out.reserve(xs.size());
            for (auto& x : xs) {
                auto v = RecFlavor::FF::from_witness(&builder, x);
                v.unset_free_witness_tag();
                out.emplace_back(v);
            }
            return out;
        };

        auto proofA_fields_ff = to_ff_local(proofA_fields);
        auto proofB_fields_ff = to_ff_local(proofB_fields);

        if (vkA_native->num_public_inputs == 0 || proofA_fields_ff.empty()) {
            throw_or_abort("batch_merge: proof A has no public inputs");
        }
        if (vkB_native->num_public_inputs == 0 || proofB_fields_ff.empty()) {
            throw_or_abort("batch_merge: proof B has no public inputs");
        }
        if (proofA_fields_ff.size() < 5 || proofB_fields_ff.size() < 5) {
            throw_or_abort(
                "batch_merge: expected child proofs to expose batch_root/inputs_root/outputs_root/input accumulators");
        }
        auto left_batch_root = proofA_fields_ff[0];
        auto right_batch_root = proofB_fields_ff[0];
        auto left_inputs_root = proofA_fields_ff[1];
        auto right_inputs_root = proofB_fields_ff[1];
        auto left_outputs_root = proofA_fields_ff[2];
        auto right_outputs_root = proofB_fields_ff[2];
        auto left_inputs_set_accumulator_a = proofA_fields_ff[3];
        auto right_inputs_set_accumulator_a = proofB_fields_ff[3];
        auto left_inputs_set_accumulator_b = proofA_fields_ff[4];
        auto right_inputs_set_accumulator_b = proofB_fields_ff[4];

        auto parent_tag = RecFlavor::FF::from_witness(&builder, bb::fr(BATCH_PARENT_HASH_TAG));
        auto inputs_tag = RecFlavor::FF::from_witness(&builder, bb::fr(BATCH_INPUTS_ROOT_TAG));
        auto outputs_tag = RecFlavor::FF::from_witness(&builder, bb::fr(BATCH_OUTPUTS_ROOT_TAG));
        parent_tag.unset_free_witness_tag();
        inputs_tag.unset_free_witness_tag();
        outputs_tag.unset_free_witness_tag();
        auto parent = bb::stdlib::poseidon2<Builder>::hash(std::vector<RecFlavor::FF>{
            parent_tag, left_batch_root, right_batch_root, vkA_hash_ff, vkB_hash_ff
        });
        auto inputs_root = bb::stdlib::poseidon2<Builder>::hash(std::vector<RecFlavor::FF>{
            inputs_tag, left_inputs_root, right_inputs_root
        });
        auto outputs_root = bb::stdlib::poseidon2<Builder>::hash(std::vector<RecFlavor::FF>{
            outputs_tag, left_outputs_root, right_outputs_root
        });
        auto inputs_set_accumulator_a = left_inputs_set_accumulator_a + right_inputs_set_accumulator_a;
        auto inputs_set_accumulator_b = left_inputs_set_accumulator_b + right_inputs_set_accumulator_b;

        parent.set_public();
        inputs_root.set_public();
        outputs_root.set_public();
        inputs_set_accumulator_a.set_public();
        inputs_set_accumulator_b.set_public();
        vkA_hash_ff.set_public();
        vkB_hash_ff.set_public();
        left_batch_root.set_public();
        right_batch_root.set_public();

        RecVerifier verifierA{ vkA_and_hash };
        RecVerifier verifierB{ vkB_and_hash };
        typename RecVerifier::Proof stdlib_proofA(proofA_fields_ff);
        typename RecVerifier::Proof stdlib_proofB(proofB_fields_ff);

        auto outA = verifierA.verify_proof(stdlib_proofA);
        auto outB = verifierB.verify_proof(stdlib_proofB);

        auto merged_pairing_points = outA.points_accumulator;
        merged_pairing_points.aggregate(outB.points_accumulator);
        DefaultIO out_io;
        out_io.pairing_inputs = merged_pairing_points;
        out_io.set_public();

        builder.finalize_circuit(true);
        auto prover_instance = std::make_shared<ProverInstance>(builder);
        auto vk_out = std::make_shared<bb::MegaFlavor::VerificationKey>(prover_instance->get_precomputed());
        bb::UltraProver_<bb::MegaFlavor> prover{ prover_instance, vk_out };
        auto merged_proof = prover.construct_proof();
        auto merged_proof_bytes = to_buffer<true>(merged_proof);
        auto merged_vk_bytes = to_buffer(*vk_out);
        return { std::move(merged_proof_bytes), std::move(merged_vk_bytes) };
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("batch_merge: ") + e.what());
    }
}

const std::vector<uint8_t>& embedded_leaf_merge_vk()
{
    static const std::vector<uint8_t> vk(embedded_vks::BATCH_MERGE_LEAF_VK,
                                         embedded_vks::BATCH_MERGE_LEAF_VK + embedded_vks::BATCH_MERGE_LEAF_VK_SIZE);
    return vk;
}

const std::vector<uint8_t>& embedded_agg_merge_vk()
{
    static const std::vector<uint8_t> vk(embedded_vks::BATCH_MERGE_AGG_VK,
                                         embedded_vks::BATCH_MERGE_AGG_VK + embedded_vks::BATCH_MERGE_AGG_VK_SIZE);
    return vk;
}

} // namespace bb::batch_merge
