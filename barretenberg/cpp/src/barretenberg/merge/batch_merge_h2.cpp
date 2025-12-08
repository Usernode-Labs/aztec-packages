#include "batch_merge_h2.hpp"

#include "merge_mega.hpp"
#include "barretenberg/flavor/mega_flavor.hpp"
#include "barretenberg/flavor/mega_recursive_flavor.hpp"
#include "barretenberg/stdlib/honk_verifier/ultra_recursive_verifier.hpp"
#include "barretenberg/common/serialize.hpp"
#include "barretenberg/stdlib/honk_verifier/oink_recursive_verifier.hpp"
#include "barretenberg/stdlib/hash/poseidon2/poseidon2.hpp"
#include "barretenberg/ultra_honk/ultra_prover.hpp"
#include "barretenberg/ultra_honk/decider_proving_key.hpp"

namespace bb::batch_merge_h2 {

// Hard-coded allowlist entries (bn254 Fr big-endian). Populate from tools/vk_hash output.
[[maybe_unused]] static const std::array<uint8_t, 32> VK_SPEND_BE32 = {
    0x14,0xf1,0xee,0x95,0xf1,0x9f,0x73,0xa2,0x0a,0xa7,0xb7,0xc8,0x41,0x46,0xdd,0x0f,
    0x37,0xff,0x08,0xc4,0xf5,0x35,0xf8,0x4c,0x97,0x29,0x57,0x70,0xb5,0x43,0xf4,0xdb };
[[maybe_unused]] static const std::array<uint8_t, 32> VK_MERGE_BE32 = {
    0x15,0xae,0x06,0x23,0xee,0x8d,0xf0,0x7b,0xbc,0xd8,0x38,0x8a,0x81,0x77,0xf8,0xff,
    0x83,0xbb,0x8a,0xcf,0x10,0xf9,0x10,0x55,0xa1,0x9c,0x9b,0x8d,0xa6,0x05,0x2d,0x92 };

MergeResult merge(const std::vector<uint8_t>& proofA_fields_buf,
                  const std::vector<uint8_t>& vkA_bytes,
                  const std::vector<uint8_t>& proofB_fields_buf,
                  const std::vector<uint8_t>& vkB_bytes)
{
    using NativeVK = bb::MegaFlavor::VerificationKey;
    using Builder = bb::MegaCircuitBuilder;
    using RecFlavor = bb::MegaRecursiveFlavor_<Builder>;
    using RecVerifier = bb::stdlib::recursion::honk::UltraRecursiveVerifier_<RecFlavor>;

    // Deserialize inputs
    std::vector<bb::fr> proofA_fields = from_buffer<std::vector<bb::fr>>(proofA_fields_buf);
    std::vector<bb::fr> proofB_fields = from_buffer<std::vector<bb::fr>>(proofB_fields_buf);
    auto vkA_native = from_buffer<std::shared_ptr<NativeVK>>(vkA_bytes);
    auto vkB_native = from_buffer<std::shared_ptr<NativeVK>>(vkB_bytes);

    Builder builder;

    // Build stdlib VerificationKeys and hashes
    auto vkA_std = std::make_shared<typename RecFlavor::VerificationKey>(&builder, vkA_native);
    auto vkB_std = std::make_shared<typename RecFlavor::VerificationKey>(&builder, vkB_native);
    auto vkA_hash_ff = RecFlavor::FF::from_witness(&builder, vkA_native->hash());
    auto vkB_hash_ff = RecFlavor::FF::from_witness(&builder, vkB_native->hash());
    auto vkA_and_hash = std::make_shared<typename RecFlavor::VKAndHash>(vkA_std, vkA_hash_ff);
    auto vkB_and_hash = std::make_shared<typename RecFlavor::VKAndHash>(vkB_std, vkB_hash_ff);

    // Note: VK allowlist is enforced off-chain by checking the published vk hashes
    // in the binding block against a manifest/allowlist. We do not constrain the
    // VK hash set in-circuit to keep the merge circuit minimal.

    // No pre-reserved public inputs; we will publish computed binding fields directly.

    // Extract child combiners in-circuit by running a lightweight stdlib Oink parse of the Oink portion,
    // and ensure the same proof field variables are used consistently across parsing, hashing, and recursive verify.
    using StdlibOink = bb::stdlib::recursion::honk::OinkRecursiveVerifier_<RecFlavor>;
    auto to_ff_local = [&](const std::vector<bb::fr>& xs) {
        std::vector<typename RecFlavor::FF> out;
        out.reserve(xs.size());
        for (auto& x : xs) { out.emplace_back(RecFlavor::FF::from_witness(&builder, x)); }
        return out;
    };
    // Create one shared vector of stdlib field variables for each proof
    auto proofA_fields_ff = to_ff_local(proofA_fields);
    auto proofB_fields_ff = to_ff_local(proofB_fields);
    RecVerifier rec_for_oinkA{ &builder, vkA_and_hash };
    StdlibOink oinkA_parse{ &builder, rec_for_oinkA.key };
    oinkA_parse.verify_proof(proofA_fields_ff);
    RecVerifier rec_for_oinkB{ &builder, vkB_and_hash };
    StdlibOink oinkB_parse{ &builder, rec_for_oinkB.key };
    oinkB_parse.verify_proof(proofB_fields_ff);
    auto left_leaf = oinkA_parse.public_inputs[0];
    auto right_leaf = oinkB_parse.public_inputs[0];
    bb::fr left_native = left_leaf.get_value();
    bb::fr right_native = right_leaf.get_value();

    // Compute parent = Poseidon2(BATCH_TAG=20, left_leaf, right_leaf, vkA_hash, vkB_hash). This binds the merge
    // combiner to the child VK hashes in-circuit.
    auto tag = RecFlavor::FF::from_witness(&builder, bb::fr(uint256_t(20))); // domain tag as field
    auto parent = bb::stdlib::poseidon2<Builder>::hash(
        builder, std::vector<RecFlavor::FF>{ tag, left_leaf, right_leaf, vkA_hash_ff, vkB_hash_ff });
    // Also compute the native parent using crypto Poseidon2 (same as Rust hash_fields)
    bb::fr parent_native = bb::crypto::Poseidon2<bb::crypto::Poseidon2Bn254ScalarFieldParams>::hash(
        std::vector<bb::fr>{ bb::fr(uint256_t(20)), left_native, right_native, vkA_native->hash(), vkB_native->hash() });
    auto parent_expect = RecFlavor::FF::from_witness(&builder, parent_native);
    parent_expect.assert_equal(parent);

    using BindingIO = bb::stdlib::recursion::honk::BindingBlockIO<Builder>;
    BindingIO binding_block;
    binding_block.parent = parent_expect;
    binding_block.vkA_hash = vkA_hash_ff;
    binding_block.vkB_hash = vkB_hash_ff;
    binding_block.left_combiner = left_leaf;
    binding_block.right_combiner = right_leaf;
    binding_block.set_public();

    // Now run recursive verifications (these may finalize via DefaultIO internally)
    RecVerifier verifierA{ &builder, vkA_and_hash };
    RecVerifier verifierB{ &builder, vkB_and_hash };
    typename RecVerifier::StdlibProof stdlib_proofA(proofA_fields_ff);
    typename RecVerifier::StdlibProof stdlib_proofB(proofB_fields_ff);
    (void)verifierA.template verify_proof<NoopIO<Builder>>(stdlib_proofA);
    (void)verifierB.template verify_proof<NoopIO<Builder>>(stdlib_proofB);

    // Do not append DefaultIO here; we keep only inner public inputs for this circuit.

    // Finalize and build proof

    // No-op constraint; public inputs already referenced via set_public().

    // Finalize circuit and produce outer proof
    builder.finalize_circuit(true);
    auto pk = std::make_shared<bb::DeciderProvingKey_<bb::MegaFlavor>>(builder);
    auto vk_out = std::make_shared<bb::MegaFlavor::VerificationKey>(pk->get_precomputed());
    bb::UltraProver_<bb::MegaFlavor> prover{ pk, vk_out };
    auto merged_proof = prover.construct_proof();
    auto merged_proof_bytes = to_buffer<true>(merged_proof);
    auto merged_vk_bytes = to_buffer(vk_out);
    //

    return { std::move(merged_proof_bytes), std::move(merged_vk_bytes), std::vector<uint8_t>{} };
}

}
