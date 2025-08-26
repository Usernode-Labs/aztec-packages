#include "merge_mega.hpp"

#include "barretenberg/flavor/mega_flavor.hpp"
#include "barretenberg/flavor/mega_recursive_flavor.hpp"
#include "barretenberg/stdlib/honk_verifier/ultra_recursive_verifier.hpp"
#include "barretenberg/ultra_honk/decider_proving_key.hpp"
#include "barretenberg/ultra_honk/ultra_prover.hpp"
#include "barretenberg/common/serialize.hpp"
#include "barretenberg/crypto/sha256/sha256.hpp"
#include "barretenberg/stdlib_circuit_builders/mega_circuit_builder.hpp"
#include <chrono>
#include <fstream>
#include <sstream>

namespace bb::merge_mega {

static size_t read_rss_mb()
{
    std::ifstream f("/proc/self/status");
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("VmRSS:", 0) == 0) {
            std::istringstream iss(line);
            std::string label; size_t kb; std::string unit;
            iss >> label >> kb >> unit;
            return kb / 1024;
        }
    }
    return 0;
}

// Helper that accepts either:
// - direct to_buffer(std::vector<fr>) encoding, or
// - a length-prefixed byte vector that itself contains to_buffer(std::vector<fr>)
// Inputs from WASM/TS are to_buffer<true>(vector<fr>) i.e., a size-prefixed vector<fr> byte array.
static std::vector<bb::fr> parse_proof_fields(const std::vector<uint8_t>& buf)
{
#if defined(__wasm__) || defined(BB_NO_EXCEPTIONS)
    return from_buffer<std::vector<bb::fr>>(buf);
#else
    std::vector<bb::fr> vec;
    try {
        vec = from_buffer<std::vector<bb::fr>>(buf);
        if (!vec.empty()) {
            return vec;
        }
    } catch (...) {
        // Fall through to raw parse.
    }
    const uint8_t* it = buf.data();
    const uint8_t* end = it + buf.size();
    while (it < end) {
        bb::fr x;
        using serialize::read;
        read(it, x);
        vec.push_back(x);
    }
    return vec;
#endif
}

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
    info("merge: parsing proof fields A bytes=", proofA_fields_buf.size(), ", B bytes=", proofB_fields_buf.size());
    info("merge: SHA256 raw A bytes:", crypto::sha256(proofA_fields_buf));
    info("merge: SHA256 raw B bytes:", crypto::sha256(proofB_fields_buf));
    std::vector<bb::fr> proofA_fields = parse_proof_fields(proofA_fields_buf);
    std::vector<bb::fr> proofB_fields = parse_proof_fields(proofB_fields_buf);
    info("merge: parsed proof fields A count=", proofA_fields.size(), ", B count=", proofB_fields.size());
    auto vkA_native = from_buffer<std::shared_ptr<NativeVK>>(vkA_bytes);
    auto vkB_native = from_buffer<std::shared_ptr<NativeVK>>(vkB_bytes);
    info("merge: vkA npi=", vkA_native->num_public_inputs, ", vkB npi=", vkB_native->num_public_inputs);
    info("merge: SHA256 vkA bytes:", crypto::sha256(vkA_bytes));
    info("merge: SHA256 vkB bytes:", crypto::sha256(vkB_bytes));
    info("merge: vkA hash:", vkA_native->hash());
    info("merge: vkB hash:", vkB_native->hash());

    Builder builder;

    // Build stdlib VerificationKeys and hashes
    auto vkA_std = std::make_shared<typename RecFlavor::VerificationKey>(&builder, vkA_native);
    auto vkB_std = std::make_shared<typename RecFlavor::VerificationKey>(&builder, vkB_native);
    auto vkA_hash_ff = RecFlavor::FF::from_witness(&builder, vkA_native->hash());
    auto vkB_hash_ff = RecFlavor::FF::from_witness(&builder, vkB_native->hash());
    auto vkA_and_hash = std::make_shared<typename RecFlavor::VKAndHash>(vkA_std, vkA_hash_ff);
    auto vkB_and_hash = std::make_shared<typename RecFlavor::VKAndHash>(vkB_std, vkB_hash_ff);

    // Construct stdlib proofs from native field vectors
    bb::stdlib::Proof<Builder> proofA(builder, proofA_fields);
    bb::stdlib::Proof<Builder> proofB(builder, proofB_fields);

    // Verify proof A
    info("merge: verifying A recursively");
    RecVerifier verifierA{ &builder, vkA_and_hash };
    auto outA = verifierA.template verify_proof<bb::stdlib::recursion::honk::DefaultIO<Builder>>(proofA);
    info("merge: verifying B recursively");
    RecVerifier verifierB{ &builder, vkB_and_hash };
    auto outB = verifierB.template verify_proof<bb::stdlib::recursion::honk::DefaultIO<Builder>>(proofB);

    // Ensure app-style pairing points are present for verification
    bb::stdlib::recursion::honk::AppIO::add_default(builder);
    // Finalize circuit
    info("merge: finalizing circuit");
    builder.finalize_circuit(true);
    size_t gates = builder.get_finalized_total_circuit_size();

    // Prove outer circuit with Mega
    auto pk = std::make_shared<bb::DeciderProvingKey_<bb::MegaFlavor>>(builder);
    auto vk_out = std::make_shared<bb::MegaFlavor::VerificationKey>(pk->get_precomputed());

    bb::UltraProver_<bb::MegaFlavor> prover{ pk, vk_out };
    auto t1 = std::chrono::high_resolution_clock::now();
    auto merged_proof = prover.construct_proof();
    auto t2 = std::chrono::high_resolution_clock::now();

    auto prove_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
    size_t rss_mb = read_rss_mb();

    // Serialize outputs
    auto merged_proof_bytes = to_buffer<true>(merged_proof);
    auto merged_vk_bytes = to_buffer(vk_out);

    std::ostringstream oss;
    oss << "{\"gates\":" << gates << ",\"prove_ms\":" << prove_ms << ",\"rss_mb\":" << rss_mb << "}";

    return { std::move(merged_proof_bytes), std::move(merged_vk_bytes), std::vector<uint8_t>{}, oss.str() };
}

MergeResult recursive_single(const std::vector<uint8_t>& proof_fields_buf, const std::vector<uint8_t>& vk_bytes)
{
    using NativeVK = bb::MegaFlavor::VerificationKey;
    using Builder = bb::MegaCircuitBuilder;
    using RecFlavor = bb::MegaRecursiveFlavor_<Builder>;
    using RecVerifier = bb::stdlib::recursion::honk::UltraRecursiveVerifier_<RecFlavor>;

    info("recursive_single: parsing inputs A bytes=", proof_fields_buf.size(), ", vk=", vk_bytes.size());
    std::vector<bb::fr> proof_fields = parse_proof_fields(proof_fields_buf);
    auto vk_native = from_buffer<std::shared_ptr<NativeVK>>(vk_bytes);

    Builder builder;
    auto vk_std = std::make_shared<typename RecFlavor::VerificationKey>(&builder, vk_native);
    auto vk_hash_ff = RecFlavor::FF::from_witness(&builder, vk_native->hash());
    auto vk_and_hash = std::make_shared<typename RecFlavor::VKAndHash>(vk_std, vk_hash_ff);

    bb::stdlib::Proof<Builder> proof(builder, proof_fields);
    info("recursive_single: verifying recursively");
    RecVerifier verifier{ &builder, vk_and_hash };
    auto out = verifier.template verify_proof<bb::stdlib::recursion::honk::DefaultIO<Builder>>(proof);

    info("recursive_single: finalizing circuit");
    builder.finalize_circuit(true);
    size_t gates = builder.get_finalized_total_circuit_size();

    auto pk = std::make_shared<bb::DeciderProvingKey_<bb::MegaFlavor>>(builder);
    auto vk_out = std::make_shared<bb::MegaFlavor::VerificationKey>(pk->get_precomputed());

    bb::UltraProver_<bb::MegaFlavor> prover{ pk, vk_out };
    auto t1 = std::chrono::high_resolution_clock::now();
    auto recursive_proof = prover.construct_proof();
    auto t2 = std::chrono::high_resolution_clock::now();

    auto prove_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
    size_t rss_mb = read_rss_mb();

    auto recursive_proof_bytes = to_buffer(recursive_proof);
    auto recursive_vk_bytes = to_buffer(vk_out);

    std::ostringstream oss;
    oss << "{\"gates\":" << gates << ",\"prove_ms\":" << prove_ms << ",\"rss_mb\":" << rss_mb << "}";

    return { std::move(recursive_proof_bytes), std::move(recursive_vk_bytes), std::vector<uint8_t>{}, oss.str() };
}

}