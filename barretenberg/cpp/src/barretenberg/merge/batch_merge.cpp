#include "batch_merge.hpp"

#include "barretenberg/common/serialize.hpp"
#include "barretenberg/common/throw_or_abort.hpp"
#include "barretenberg/flavor/mega_flavor.hpp"
#include "barretenberg/flavor/mega_recursive_flavor.hpp"
#include "barretenberg/stdlib/hash/poseidon2/poseidon2.hpp"
#include "barretenberg/stdlib/honk_verifier/ultra_recursive_verifier.hpp"
#include "barretenberg/ultra_honk/decider_proving_key.hpp"
#include "barretenberg/ultra_honk/ultra_prover.hpp"
#include "batch_merge_embedded_vks.hpp"
#include <stdexcept>

namespace bb::batch_merge {

MergeResult merge(const std::vector<uint8_t>& proofA_fields_buf,
                  const std::vector<uint8_t>& vkA_bytes,
                  const std::vector<uint8_t>& proofB_fields_buf,
                  const std::vector<uint8_t>& vkB_bytes)
{
    using NativeVK = bb::MegaFlavor::VerificationKey;
    using Builder = bb::MegaCircuitBuilder;
    using RecFlavor = bb::MegaRecursiveFlavor_<Builder>;
    using RecVerifier = bb::stdlib::recursion::honk::UltraRecursiveVerifier_<RecFlavor>;

    std::vector<bb::fr> proofA_fields = from_buffer<std::vector<bb::fr>>(proofA_fields_buf);
    std::vector<bb::fr> proofB_fields = from_buffer<std::vector<bb::fr>>(proofB_fields_buf);
    auto vkA_native = from_buffer<std::shared_ptr<NativeVK>>(vkA_bytes);
    auto vkB_native = from_buffer<std::shared_ptr<NativeVK>>(vkB_bytes);

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
        auto left_leaf = proofA_fields_ff[0];
        auto right_leaf = proofB_fields_ff[0];

        auto tag = RecFlavor::FF::from_witness(&builder, bb::fr(uint256_t(20)));
        tag.unset_free_witness_tag();
        auto parent = bb::stdlib::poseidon2<Builder>::hash(
            std::vector<RecFlavor::FF>{ tag, left_leaf, right_leaf, vkA_hash_ff, vkB_hash_ff });

        parent.set_public();
        vkA_hash_ff.set_public();
        vkB_hash_ff.set_public();
        left_leaf.set_public();
        right_leaf.set_public();

        using DefaultIO = bb::stdlib::recursion::honk::DefaultIO<Builder>;
        RecVerifier verifierA{ &builder, vkA_and_hash };
        RecVerifier verifierB{ &builder, vkB_and_hash };
        typename RecVerifier::StdlibProof stdlib_proofA(proofA_fields_ff);
        typename RecVerifier::StdlibProof stdlib_proofB(proofB_fields_ff);

        auto outA = verifierA.template verify_proof<DefaultIO>(stdlib_proofA);
        auto outB = verifierB.template verify_proof<DefaultIO>(stdlib_proofB);

        bb::stdlib::recursion::PairingPoints<Builder> merged_pairing_points = outA.points_accumulator;
        merged_pairing_points.aggregate(outB.points_accumulator);
        DefaultIO out_io;
        out_io.pairing_inputs = merged_pairing_points;
        out_io.set_public();

        builder.finalize_circuit(true);
        auto pk = std::make_shared<bb::DeciderProvingKey_<bb::MegaFlavor>>(builder);
        auto vk_out = std::make_shared<bb::MegaFlavor::VerificationKey>(pk->get_precomputed());
        bb::UltraProver_<bb::MegaFlavor> prover{ pk, vk_out };
        auto merged_proof = prover.construct_proof();
        auto merged_proof_bytes = to_buffer<true>(merged_proof);
        auto merged_vk_bytes = to_buffer(vk_out);
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
