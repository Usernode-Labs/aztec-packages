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

[[maybe_unused]] static bb::fr fr_from_be32(const std::array<uint8_t, 32>& be)
{
    auto be32_to_le_limbs = [](const uint8_t* in_be, uint64_t out_le[4]) {
        for (size_t i = 0; i < 4; ++i) {
            size_t off = 24 - i * 8;
            uint64_t limb = 0;
            for (size_t j = 0; j < 8; ++j) {
                limb = (limb << 8) | in_be[off + j];
            }
            out_le[i] = limb;
        }
    };
    uint64_t limbs[4];
    be32_to_le_limbs(be.data(), limbs);
    bb::fr v(limbs[0], limbs[1], limbs[2], limbs[3]);
    return v.to_montgomery_form();
}

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
    std::vector<bb::fr> proofA_fields = many_from_buffer<bb::fr>(proofA_fields_buf);
    std::vector<bb::fr> proofB_fields = many_from_buffer<bb::fr>(proofB_fields_buf);
    auto honkA = from_buffer<bb::HonkProof>(proofA_fields_buf);
    auto honkB = from_buffer<bb::HonkProof>(proofB_fields_buf);
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

    // Extract child combiners in-circuit by running a lightweight stdlib Oink parse of the Oink portion
    using StdlibOink = bb::stdlib::recursion::honk::OinkRecursiveVerifier_<RecFlavor>;
    // helper already declared above
    // Some environments serialize the Oink portion as a vector<fr>; parse that form for stdlib Oink consumption.
    auto oinkA_fields_native = from_buffer<std::vector<bb::fr>>(proofA_fields_buf);
    auto oinkB_fields_native = from_buffer<std::vector<bb::fr>>(proofB_fields_buf);
    auto to_ff_local = [&](const std::vector<bb::fr>& xs) {
        std::vector<typename RecFlavor::FF> out;
        out.reserve(xs.size());
        for (auto& x : xs) { out.emplace_back(RecFlavor::FF::from_witness(&builder, x)); }
        return out;
    };
    RecVerifier rec_for_oinkA{ &builder, vkA_and_hash };
    StdlibOink oinkA_parse{ &builder, rec_for_oinkA.key };
    oinkA_parse.verify_proof(to_ff_local(oinkA_fields_native));
    RecVerifier rec_for_oinkB{ &builder, vkB_and_hash };
    StdlibOink oinkB_parse{ &builder, rec_for_oinkB.key };
    oinkB_parse.verify_proof(to_ff_local(oinkB_fields_native));
    auto left_leaf = oinkA_parse.public_inputs[0];
    auto right_leaf = oinkB_parse.public_inputs[0];
    bb::fr left_native = left_leaf.get_value();
    bb::fr right_native = right_leaf.get_value();

    // Compute parent = Poseidon2(BATCH_TAG=20, left_leaf, right_leaf). This is the designated combiner that the
    // next merge level will read from this circuit's ACIR public inputs (at index 0).
    auto tag = RecFlavor::FF::from_witness(&builder, bb::fr(uint256_t(20))); // domain tag as field
    auto parent = bb::stdlib::poseidon2<Builder>::hash(builder, std::vector<RecFlavor::FF>{ tag, left_leaf, right_leaf });
    // Also compute the native parent using crypto Poseidon2 (same as Rust hash_fields)
    

    bb::fr parent_native = bb::crypto::Poseidon2<bb::crypto::Poseidon2Bn254ScalarFieldParams>::hash(
        std::vector<bb::fr>{ bb::fr(uint256_t(20)), left_native, right_native });
    //
    auto parent_expect = RecFlavor::FF::from_witness(&builder, parent_native);
    parent_expect.assert_equal(parent);

    // Also compute in-circuit hashes of child proofs (over their field encodings) to bind to public outputs
    auto hash_fields = [&](const std::vector<typename RecFlavor::FF>& xs, uint32_t tag_val) {
        std::vector<typename RecFlavor::FF> pre;
        pre.reserve(xs.size() + 1);
        pre.emplace_back(RecFlavor::FF::from_witness(&builder, bb::fr(uint256_t(tag_val))));
        pre.insert(pre.end(), xs.begin(), xs.end());
        return bb::stdlib::poseidon2<Builder>::hash(builder, pre);
    };
    // Bind each child proof to public outputs by hashing the exact field encoding consumed by recursion.
    // Domain tag 60 disambiguates proof-field hashes from other Poseidon2 usages.
    auto to_ff = [&](const std::vector<bb::fr>& xs) {
        std::vector<typename RecFlavor::FF> out;
        out.reserve(xs.size());
        for (auto& x : xs) { out.emplace_back(RecFlavor::FF::from_witness(&builder, x)); }
        return out;
    };
    auto proofA_hash = hash_fields(to_ff(proofA_fields), 60); // PROOF_TAG=60
    auto proofB_hash = hash_fields(to_ff(proofB_fields), 60);
    // Native equivalents for cross-check
    auto native_hash_from_fields = [&](const std::vector<bb::fr>& xs, uint32_t tag_val) {
        std::vector<bb::fr> pre;
        pre.reserve(xs.size() + 1);
        pre.emplace_back(bb::fr(uint256_t(tag_val)));
        pre.insert(pre.end(), xs.begin(), xs.end());
        return bb::crypto::Poseidon2<bb::crypto::Poseidon2Bn254ScalarFieldParams>::hash(pre);
    };
    bb::fr pl_native = native_hash_from_fields(proofA_fields, 60);
    bb::fr pr_native = native_hash_from_fields(proofB_fields, 60);
    auto pl_native_ff = RecFlavor::FF::from_witness(&builder, pl_native);
    auto pr_native_ff = RecFlavor::FF::from_witness(&builder, pr_native);
    proofA_hash.assert_equal(pl_native_ff);
    proofB_hash.assert_equal(pr_native_ff);
    //

    // Use the native vk hashes already constructed for recursive verification
    // (vkA_hash_ff and vkB_hash_ff)

    // Publish binding block as public inputs in canonical order and finalize boundary.
    parent_expect.set_public();
    proofA_hash.set_public();
    vkA_hash_ff.set_public();
    proofB_hash.set_public();
    vkB_hash_ff.set_public();
    left_leaf.set_public();
    right_leaf.set_public();
    builder.finalize_public_inputs();

    // Now run recursive verifications (these may finalize via DefaultIO internally)
    RecVerifier verifierA{ &builder, vkA_and_hash };
    RecVerifier verifierB{ &builder, vkB_and_hash };
    (void)verifierA.template verify_proof<NoopIO<Builder>>(bb::stdlib::Proof<Builder>(builder, honkA));
    (void)verifierB.template verify_proof<NoopIO<Builder>>(bb::stdlib::Proof<Builder>(builder, honkB));

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
