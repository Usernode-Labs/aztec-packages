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
#include <array>
#include <stdexcept>
#include <string>

namespace bb::batch_merge {

MergeResult merge(const std::vector<uint8_t>& proofA_fields_buf,
                  const std::vector<uint8_t>& vkA_bytes,
                  const std::vector<uint8_t>& proofB_fields_buf,
                  const std::vector<uint8_t>& vkB_bytes)
{
    return merge_many(std::vector<MergeInput>{
        MergeInput{ proofA_fields_buf, vkA_bytes },
        MergeInput{ proofB_fields_buf, vkB_bytes },
    });
}

MergeResult merge_many(const std::vector<MergeInput>& children)
{
    if (children.size() < MIN_MERGE_ARITY || children.size() > MAX_MERGE_ARITY) {
        throw std::runtime_error("batch_merge: unsupported merge arity");
    }

    using NativeVK = bb::MegaFlavor::VerificationKey;
    using Builder = bb::MegaCircuitBuilder;
    using RecFlavor = bb::MegaRecursiveFlavor_<Builder>;
    using DefaultIO = bb::stdlib::recursion::honk::DefaultIO<Builder>;
    using RecVerifier = bb::UltraVerifier_<RecFlavor, DefaultIO>;
    using ProverInstance = bb::ProverInstance_<bb::MegaFlavor>;

    struct PreparedChild {
        std::shared_ptr<NativeVK> native_vk;
        std::shared_ptr<typename RecFlavor::VKAndHash> vk_and_hash;
        std::vector<typename RecFlavor::FF> proof_fields_ff;
        typename RecFlavor::FF vk_hash;
        typename RecFlavor::FF batch_root;
        typename RecFlavor::FF inputs_root;
        typename RecFlavor::FF outputs_root;
        typename RecFlavor::FF inputs_set_accumulator_a;
        typename RecFlavor::FF inputs_set_accumulator_b;
        typename RecFlavor::FF count;
    };

    Builder builder;
    try {
        static constexpr size_t DEFAULT_PUBLIC_INPUTS = bb::DefaultIO::PUBLIC_INPUTS_SIZE;
        // Poseidon2 currently rejects literal circuit constants. Materialize protocol
        // constants as witnesses and fix them with equality gates so they remain
        // circuit-defined rather than caller-controlled.
        auto fixed_witness = [&](const bb::fr& value) {
            auto fixed = RecFlavor::FF(&builder, value);
            fixed.convert_constant_to_fixed_witness(&builder);
            return fixed;
        };
        auto one_count = [&]() {
            return fixed_witness(bb::fr(1));
        };
        auto publish_zero = [&]() {
            auto zero = fixed_witness(bb::fr(0));
            zero.set_public();
        };

        std::vector<PreparedChild> prepared;
        prepared.reserve(children.size());

        for (size_t i = 0; i < children.size(); ++i) {
            const auto& child = children[i];
            std::vector<bb::fr> proof_fields = from_buffer<std::vector<bb::fr>>(child.proof_fields_buf);
            auto native_vk = std::make_shared<NativeVK>(from_buffer<NativeVK>(child.vk_bytes));

            if (native_vk->num_public_inputs == 0 || proof_fields.empty()) {
                throw_or_abort("batch_merge: child proof has no public inputs");
            }
            if (proof_fields.size() < 5) {
                throw_or_abort("batch_merge: expected child proofs to expose batch_root/inputs_root/outputs_root/input accumulators");
            }

            auto vk_std = std::make_shared<typename RecFlavor::VerificationKey>(&builder, native_vk);
            auto vk_hash_ff = RecFlavor::FF::from_witness(&builder, native_vk->hash());
            vk_hash_ff.unset_free_witness_tag();
            auto vk_and_hash = std::make_shared<typename RecFlavor::VKAndHash>(vk_std, vk_hash_ff);

            std::vector<typename RecFlavor::FF> proof_fields_ff;
            proof_fields_ff.reserve(proof_fields.size());
            for (auto& field : proof_fields) {
                auto value = RecFlavor::FF::from_witness(&builder, field);
                value.unset_free_witness_tag();
                proof_fields_ff.emplace_back(value);
            }

            const size_t total_public_inputs = static_cast<size_t>(native_vk->num_public_inputs);
            if (total_public_inputs < DEFAULT_PUBLIC_INPUTS) {
                throw_or_abort("batch_merge: child proof is missing DefaultIO public inputs");
            }
            const size_t semantic_public_inputs = total_public_inputs - DEFAULT_PUBLIC_INPUTS;
            typename RecFlavor::FF count;
            if (semantic_public_inputs == LEAF_SEMANTIC_PUBLIC_INPUTS) {
                count = one_count();
            } else if (semantic_public_inputs == MERGE_SEMANTIC_PUBLIC_INPUTS) {
                if (proof_fields_ff.size() < 6) {
                    throw_or_abort("batch_merge: merge child proof has no count public input");
                }
                count = proof_fields_ff[5];
            } else {
                throw_or_abort("batch_merge: child proof has unsupported semantic public-input width");
            }

            prepared.push_back(PreparedChild{
                native_vk,
                vk_and_hash,
                std::move(proof_fields_ff),
                vk_hash_ff,
                prepared.empty() ? RecFlavor::FF() : RecFlavor::FF(),
                prepared.empty() ? RecFlavor::FF() : RecFlavor::FF(),
                prepared.empty() ? RecFlavor::FF() : RecFlavor::FF(),
                prepared.empty() ? RecFlavor::FF() : RecFlavor::FF(),
                prepared.empty() ? RecFlavor::FF() : RecFlavor::FF(),
                count,
            });
            prepared.back().batch_root = prepared.back().proof_fields_ff[0];
            prepared.back().inputs_root = prepared.back().proof_fields_ff[1];
            prepared.back().outputs_root = prepared.back().proof_fields_ff[2];
            prepared.back().inputs_set_accumulator_a = prepared.back().proof_fields_ff[3];
            prepared.back().inputs_set_accumulator_b = prepared.back().proof_fields_ff[4];
        }

        const auto parent_tag = fixed_witness(bb::fr(BATCH_PARENT_HASH_TAG));
        const auto inputs_tag = fixed_witness(bb::fr(BATCH_INPUTS_ROOT_TAG));
        const auto outputs_tag = fixed_witness(bb::fr(BATCH_OUTPUTS_ROOT_TAG));
        const auto arity_ff = fixed_witness(bb::fr(children.size()));

        std::vector<RecFlavor::FF> parent_inputs;
        parent_inputs.reserve(2 + prepared.size() * 3);
        parent_inputs.push_back(parent_tag);
        parent_inputs.push_back(arity_ff);

        std::vector<RecFlavor::FF> inputs_root_inputs;
        inputs_root_inputs.reserve(2 + prepared.size());
        inputs_root_inputs.push_back(inputs_tag);
        inputs_root_inputs.push_back(arity_ff);

        std::vector<RecFlavor::FF> outputs_root_inputs;
        outputs_root_inputs.reserve(2 + prepared.size());
        outputs_root_inputs.push_back(outputs_tag);
        outputs_root_inputs.push_back(arity_ff);

        auto parent_count = prepared[0].count;
        auto inputs_set_accumulator_a = prepared[0].inputs_set_accumulator_a;
        auto inputs_set_accumulator_b = prepared[0].inputs_set_accumulator_b;

        for (size_t i = 0; i < prepared.size(); ++i) {
            const auto& child = prepared[i];
            parent_inputs.push_back(child.batch_root);
            parent_inputs.push_back(child.vk_hash);
            parent_inputs.push_back(child.count);
            inputs_root_inputs.push_back(child.inputs_root);
            outputs_root_inputs.push_back(child.outputs_root);
            if (i > 0) {
                parent_count = parent_count + child.count;
                inputs_set_accumulator_a = inputs_set_accumulator_a + child.inputs_set_accumulator_a;
                inputs_set_accumulator_b = inputs_set_accumulator_b + child.inputs_set_accumulator_b;
            }
        }

        auto parent = bb::stdlib::poseidon2<Builder>::hash(parent_inputs);
        auto inputs_root = bb::stdlib::poseidon2<Builder>::hash(inputs_root_inputs);
        auto outputs_root = bb::stdlib::poseidon2<Builder>::hash(outputs_root_inputs);

        parent.set_public();
        inputs_root.set_public();
        outputs_root.set_public();
        inputs_set_accumulator_a.set_public();
        inputs_set_accumulator_b.set_public();
        parent_count.set_public();
        for (size_t i = 0; i < MAX_MERGE_ARITY; ++i) {
            if (i < prepared.size()) {
                auto& child = prepared[i];
                child.vk_hash.set_public();
                child.batch_root.set_public();
                child.count.set_public();
            } else {
                publish_zero();
                publish_zero();
                publish_zero();
            }
        }

        RecVerifier verifier0{ prepared[0].vk_and_hash };
        typename RecVerifier::Proof stdlib_proof0(prepared[0].proof_fields_ff);
        auto out = verifier0.verify_proof(stdlib_proof0);
        auto merged_pairing_points = out.points_accumulator;

        for (size_t i = 1; i < prepared.size(); ++i) {
            RecVerifier verifier{ prepared[i].vk_and_hash };
            typename RecVerifier::Proof stdlib_proof(prepared[i].proof_fields_ff);
            auto child_out = verifier.verify_proof(stdlib_proof);
            merged_pairing_points.aggregate(child_out.points_accumulator);
        }

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
    return embedded_leaf_merge_vk(2);
}

const std::vector<uint8_t>& embedded_agg_merge_vk()
{
    return embedded_agg_merge_vk(2);
}

const std::vector<uint8_t>& embedded_leaf_merge_vk(size_t arity)
{
    static const std::array<std::vector<uint8_t>, MAX_MERGE_ARITY - MIN_MERGE_ARITY + 1> vks = {
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_LEAF_VK_2,
                             embedded_vks::BATCH_MERGE_LEAF_VK_2 + embedded_vks::BATCH_MERGE_LEAF_VK_2_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_LEAF_VK_3,
                             embedded_vks::BATCH_MERGE_LEAF_VK_3 + embedded_vks::BATCH_MERGE_LEAF_VK_3_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_LEAF_VK_4,
                             embedded_vks::BATCH_MERGE_LEAF_VK_4 + embedded_vks::BATCH_MERGE_LEAF_VK_4_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_LEAF_VK_5,
                             embedded_vks::BATCH_MERGE_LEAF_VK_5 + embedded_vks::BATCH_MERGE_LEAF_VK_5_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_LEAF_VK_6,
                             embedded_vks::BATCH_MERGE_LEAF_VK_6 + embedded_vks::BATCH_MERGE_LEAF_VK_6_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_LEAF_VK_7,
                             embedded_vks::BATCH_MERGE_LEAF_VK_7 + embedded_vks::BATCH_MERGE_LEAF_VK_7_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_LEAF_VK_8,
                             embedded_vks::BATCH_MERGE_LEAF_VK_8 + embedded_vks::BATCH_MERGE_LEAF_VK_8_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_LEAF_VK_9,
                             embedded_vks::BATCH_MERGE_LEAF_VK_9 + embedded_vks::BATCH_MERGE_LEAF_VK_9_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_LEAF_VK_10,
                             embedded_vks::BATCH_MERGE_LEAF_VK_10 + embedded_vks::BATCH_MERGE_LEAF_VK_10_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_LEAF_VK_11,
                             embedded_vks::BATCH_MERGE_LEAF_VK_11 + embedded_vks::BATCH_MERGE_LEAF_VK_11_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_LEAF_VK_12,
                             embedded_vks::BATCH_MERGE_LEAF_VK_12 + embedded_vks::BATCH_MERGE_LEAF_VK_12_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_LEAF_VK_13,
                             embedded_vks::BATCH_MERGE_LEAF_VK_13 + embedded_vks::BATCH_MERGE_LEAF_VK_13_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_LEAF_VK_14,
                             embedded_vks::BATCH_MERGE_LEAF_VK_14 + embedded_vks::BATCH_MERGE_LEAF_VK_14_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_LEAF_VK_15,
                             embedded_vks::BATCH_MERGE_LEAF_VK_15 + embedded_vks::BATCH_MERGE_LEAF_VK_15_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_LEAF_VK_16,
                             embedded_vks::BATCH_MERGE_LEAF_VK_16 + embedded_vks::BATCH_MERGE_LEAF_VK_16_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_LEAF_VK_17,
                             embedded_vks::BATCH_MERGE_LEAF_VK_17 + embedded_vks::BATCH_MERGE_LEAF_VK_17_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_LEAF_VK_18,
                             embedded_vks::BATCH_MERGE_LEAF_VK_18 + embedded_vks::BATCH_MERGE_LEAF_VK_18_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_LEAF_VK_19,
                             embedded_vks::BATCH_MERGE_LEAF_VK_19 + embedded_vks::BATCH_MERGE_LEAF_VK_19_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_LEAF_VK_20,
                             embedded_vks::BATCH_MERGE_LEAF_VK_20 + embedded_vks::BATCH_MERGE_LEAF_VK_20_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_LEAF_VK_21,
                             embedded_vks::BATCH_MERGE_LEAF_VK_21 + embedded_vks::BATCH_MERGE_LEAF_VK_21_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_LEAF_VK_22,
                             embedded_vks::BATCH_MERGE_LEAF_VK_22 + embedded_vks::BATCH_MERGE_LEAF_VK_22_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_LEAF_VK_23,
                             embedded_vks::BATCH_MERGE_LEAF_VK_23 + embedded_vks::BATCH_MERGE_LEAF_VK_23_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_LEAF_VK_24,
                             embedded_vks::BATCH_MERGE_LEAF_VK_24 + embedded_vks::BATCH_MERGE_LEAF_VK_24_SIZE),
    };
    if (arity < MIN_MERGE_ARITY || arity > MAX_MERGE_ARITY) {
        throw std::runtime_error("batch_merge: unsupported leaf merge VK arity");
    }
    return vks[arity - MIN_MERGE_ARITY];
}

const std::vector<uint8_t>& embedded_agg_merge_vk(size_t arity)
{
    static const std::array<std::vector<uint8_t>, MAX_MERGE_ARITY - MIN_MERGE_ARITY + 1> vks = {
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_AGG_VK_2,
                             embedded_vks::BATCH_MERGE_AGG_VK_2 + embedded_vks::BATCH_MERGE_AGG_VK_2_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_AGG_VK_3,
                             embedded_vks::BATCH_MERGE_AGG_VK_3 + embedded_vks::BATCH_MERGE_AGG_VK_3_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_AGG_VK_4,
                             embedded_vks::BATCH_MERGE_AGG_VK_4 + embedded_vks::BATCH_MERGE_AGG_VK_4_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_AGG_VK_5,
                             embedded_vks::BATCH_MERGE_AGG_VK_5 + embedded_vks::BATCH_MERGE_AGG_VK_5_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_AGG_VK_6,
                             embedded_vks::BATCH_MERGE_AGG_VK_6 + embedded_vks::BATCH_MERGE_AGG_VK_6_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_AGG_VK_7,
                             embedded_vks::BATCH_MERGE_AGG_VK_7 + embedded_vks::BATCH_MERGE_AGG_VK_7_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_AGG_VK_8,
                             embedded_vks::BATCH_MERGE_AGG_VK_8 + embedded_vks::BATCH_MERGE_AGG_VK_8_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_AGG_VK_9,
                             embedded_vks::BATCH_MERGE_AGG_VK_9 + embedded_vks::BATCH_MERGE_AGG_VK_9_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_AGG_VK_10,
                             embedded_vks::BATCH_MERGE_AGG_VK_10 + embedded_vks::BATCH_MERGE_AGG_VK_10_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_AGG_VK_11,
                             embedded_vks::BATCH_MERGE_AGG_VK_11 + embedded_vks::BATCH_MERGE_AGG_VK_11_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_AGG_VK_12,
                             embedded_vks::BATCH_MERGE_AGG_VK_12 + embedded_vks::BATCH_MERGE_AGG_VK_12_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_AGG_VK_13,
                             embedded_vks::BATCH_MERGE_AGG_VK_13 + embedded_vks::BATCH_MERGE_AGG_VK_13_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_AGG_VK_14,
                             embedded_vks::BATCH_MERGE_AGG_VK_14 + embedded_vks::BATCH_MERGE_AGG_VK_14_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_AGG_VK_15,
                             embedded_vks::BATCH_MERGE_AGG_VK_15 + embedded_vks::BATCH_MERGE_AGG_VK_15_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_AGG_VK_16,
                             embedded_vks::BATCH_MERGE_AGG_VK_16 + embedded_vks::BATCH_MERGE_AGG_VK_16_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_AGG_VK_17,
                             embedded_vks::BATCH_MERGE_AGG_VK_17 + embedded_vks::BATCH_MERGE_AGG_VK_17_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_AGG_VK_18,
                             embedded_vks::BATCH_MERGE_AGG_VK_18 + embedded_vks::BATCH_MERGE_AGG_VK_18_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_AGG_VK_19,
                             embedded_vks::BATCH_MERGE_AGG_VK_19 + embedded_vks::BATCH_MERGE_AGG_VK_19_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_AGG_VK_20,
                             embedded_vks::BATCH_MERGE_AGG_VK_20 + embedded_vks::BATCH_MERGE_AGG_VK_20_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_AGG_VK_21,
                             embedded_vks::BATCH_MERGE_AGG_VK_21 + embedded_vks::BATCH_MERGE_AGG_VK_21_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_AGG_VK_22,
                             embedded_vks::BATCH_MERGE_AGG_VK_22 + embedded_vks::BATCH_MERGE_AGG_VK_22_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_AGG_VK_23,
                             embedded_vks::BATCH_MERGE_AGG_VK_23 + embedded_vks::BATCH_MERGE_AGG_VK_23_SIZE),
        std::vector<uint8_t>(embedded_vks::BATCH_MERGE_AGG_VK_24,
                             embedded_vks::BATCH_MERGE_AGG_VK_24 + embedded_vks::BATCH_MERGE_AGG_VK_24_SIZE),
    };
    if (arity < MIN_MERGE_ARITY || arity > MAX_MERGE_ARITY) {
        throw std::runtime_error("batch_merge: unsupported aggregate merge VK arity");
    }
    return vks[arity - MIN_MERGE_ARITY];
}

} // namespace bb::batch_merge
