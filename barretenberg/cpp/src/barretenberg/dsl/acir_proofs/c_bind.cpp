// === AUDIT STATUS ===
// internal:    { status: not started, auditors: [], date: YYYY-MM-DD }
// external_1:  { status: not started, auditors: [], date: YYYY-MM-DD }
// external_2:  { status: not started, auditors: [], date: YYYY-MM-DD }
// =====================

#include "c_bind.hpp"
#include "../acir_format/acir_to_constraint_buf.hpp"
#include "barretenberg/client_ivc/client_ivc.hpp"
#include "barretenberg/client_ivc/private_execution_steps.hpp"
#include "barretenberg/common/mem.hpp"
#include "barretenberg/common/net.hpp"
#include "barretenberg/common/serialize.hpp"
#include "barretenberg/common/slab_allocator.hpp"
#include "barretenberg/common/throw_or_abort.hpp"
#include "barretenberg/common/zip_view.hpp"
#include "barretenberg/dsl/acir_format/acir_format.hpp"
#include "barretenberg/dsl/acir_format/pg_recursion_constraint.hpp"

#include "barretenberg/honk/execution_trace/mega_execution_trace.hpp"
#include "barretenberg/serialize/msgpack.hpp"
#include "barretenberg/stdlib/primitives/pairing_points.hpp"
#include "barretenberg/stdlib/special_public_inputs/special_public_inputs.hpp"
#include "barretenberg/crypto/sha256/sha256.hpp"
#include "barretenberg/solidity_helpers/utils/utils.hpp"
#include "barretenberg/merge/merge_mega.hpp"
#include "honk_contract.hpp"
#include <cstdint>
#include <memory>

WASM_EXPORT void acir_get_circuit_sizes(
    uint8_t const* acir_vec, bool const* recursive, bool const* honk_recursion, uint32_t* total, uint32_t* subgroup)
{
    const acir_format::ProgramMetadata metadata{ .recursive = *recursive,
                                                 .honk_recursion = *honk_recursion,
                                                 .size_hint = 1 << 19 };
    acir_format::AcirProgram program{ acir_format::circuit_buf_to_acir_format(
        from_buffer<std::vector<uint8_t>>(acir_vec)) };
    auto builder = acir_format::create_circuit(program, metadata);
    builder.finalize_circuit(/*ensure_nonzero=*/true);
    *total = htonl((uint32_t)builder.get_finalized_total_circuit_size());
    *subgroup = htonl((uint32_t)builder.get_circuit_subgroup_size(builder.get_finalized_total_circuit_size()));
}

WASM_EXPORT void acir_prove_and_verify_ultra_honk(uint8_t const* acir_vec, uint8_t const* witness_vec, bool* result)
{
    const acir_format::ProgramMetadata metadata{ .honk_recursion = 1 };
    acir_format::AcirProgram program{
        acir_format::circuit_buf_to_acir_format(from_buffer<std::vector<uint8_t>>(acir_vec)),
        acir_format::witness_buf_to_witness_data(from_buffer<std::vector<uint8_t>>(witness_vec))
    };

    auto builder = acir_format::create_circuit<UltraCircuitBuilder>(program, metadata);

    auto proving_key = std::make_shared<DeciderProvingKey_<UltraFlavor>>(builder);
    auto verification_key = std::make_shared<UltraFlavor::VerificationKey>(proving_key->get_precomputed());
    UltraProver prover{ proving_key, verification_key };
    auto proof = prover.construct_proof();

    UltraVerifier verifier{ verification_key };

    *result = verifier.template verify_proof<DefaultIO>(proof).result;
    info("verified: ", *result);
}

WASM_EXPORT void acir_prove_and_verify_mega_honk(uint8_t const* acir_vec, uint8_t const* witness_vec, bool* result)
{
    const acir_format::ProgramMetadata metadata{ .honk_recursion = 1 };

    acir_format::AcirProgram program{
        acir_format::circuit_buf_to_acir_format(from_buffer<std::vector<uint8_t>>(acir_vec)),
        acir_format::witness_buf_to_witness_data(from_buffer<std::vector<uint8_t>>(witness_vec))
    };

    auto builder = acir_format::create_circuit<MegaCircuitBuilder>(program, metadata);

    auto proving_key = std::make_shared<DeciderProvingKey_<MegaFlavor>>(builder);
    auto verification_key = std::make_shared<MegaFlavor::VerificationKey>(proving_key->get_precomputed());
    MegaProver prover{ proving_key, verification_key };
    auto proof = prover.construct_proof();

    MegaVerifier verifier{ verification_key };

    *result = verifier.template verify_proof<DefaultIO>(proof).result;
}

WASM_EXPORT void acir_prove_mega_honk(uint8_t const* acir_vec,
                                      uint8_t const* witness_vec,
                                      uint8_t** proof_out,
                                      uint8_t** vk_out)
{
    info("MEGAHONK_PROVE: entry");
    using DeciderProvingKey = DeciderProvingKey_<MegaFlavor>;
    using VerificationKey = MegaFlavor::VerificationKey;
    
    info("MEGAHONK_PROVE: parsing inputs");
    const acir_format::ProgramMetadata metadata{ .honk_recursion = 1 };
    acir_format::AcirProgram program{
        acir_format::circuit_buf_to_acir_format(from_buffer<std::vector<uint8_t>>(acir_vec)),
        acir_format::witness_buf_to_witness_data(from_buffer<std::vector<uint8_t>>(witness_vec))
    };
    
    info("MEGAHONK_PROVE: creating circuit builder");
    auto builder = acir_format::create_circuit<MegaCircuitBuilder>(program, metadata);
    
    info("MEGAHONK_PROVE: creating proving key");
    auto proving_key = std::make_shared<DeciderProvingKey>(builder);
    
    info("MEGAHONK_PROVE: creating verification key");
    auto verification_key = std::make_shared<VerificationKey>(proving_key->get_precomputed());
    
    info("MEGAHONK_PROVE: creating prover");
    MegaProver prover{ proving_key, verification_key };
    
    info("MEGAHONK_PROVE: constructing proof");
    auto proof = prover.construct_proof();
    info("MEGAHONK_PROVE: proof constructed, size=", proof.size());
    
    // Hash the proof as a vector<fr> (unserialized), akin to VK hashing via transcript
    {
        auto obj_hash = MegaFlavor::Transcript::hash(proof);
        info("MEGAHONK_PROVE: Proof (object) hash: ", obj_hash);
    }
    info("MEGAHONK_PROVE: serializing outputs");
    // Serialize proof with size prefix so the verifier can reconstruct the vector<fr> correctly.
    auto proof_buffer = to_buffer<true>(proof);
    // Hash the serialized proof bytes to compare against verifier-side reconstruction.
    auto proof_hash = crypto::sha256(proof_buffer);
    info("MEGAHONK_PROVE: Proof SHA256: ", proof_hash);
    auto vk_buffer = to_buffer(*verification_key);
    info("MEGAHONK_PROVE: proof buffer bytes=", proof_buffer.size(), ", vk buffer bytes=", vk_buffer.size());
    
    *proof_out = to_heap_buffer(proof_buffer);
    *vk_out = to_heap_buffer(vk_buffer);
    info("MEGAHONK_PROVE: exit ok");
}

WASM_EXPORT void acir_verify_mega_honk(uint8_t const* proof_buf, uint8_t const* vk_buf, bool* result)
{
    info("MEGAHONK_VERIFY: Function started");
    // Inputs are length-prefixed byte vectors; unwrap before decoding
    auto proof_bytes = from_buffer<std::vector<uint8_t>>(proof_buf);
    // Log the hash of the received serialized proof bytes.
    auto recv_hash = crypto::sha256(proof_bytes);
    info("MEGAHONK_VERIFY: Received Proof SHA256: ", recv_hash);
    auto proof = from_buffer<HonkProof>(proof_bytes);
    // Hash the deserialized proof object (vector<fr>)
    {
        auto obj_hash = MegaFlavor::Transcript::hash(proof);
        info("MEGAHONK_VERIFY: Proof (object) hash: ", obj_hash);
    }
    // Re-serialize and hash; should match received hash if (de)serialization is symmetric.
    auto proof_bytes_roundtrip = to_buffer(proof);
    auto roundtrip_hash = crypto::sha256(proof_bytes_roundtrip);
    info("MEGAHONK_VERIFY: Roundtrip Proof SHA256: ", roundtrip_hash);
    if (!(recv_hash == proof_bytes_roundtrip)) {
        info("MEGAHONK_VERIFY: WARNING Proof hash mismatch between received and roundtrip serialization");
    }
    info("MEGAHONK_VERIFY: Proof deserialized");
    auto vk_bytes = from_buffer<std::vector<uint8_t>>(vk_buf);
    auto vk_raw = from_buffer<MegaFlavor::VerificationKey>(vk_bytes);
    info("MEGAHONK_VERIFY: VK deserialized");
    auto verification_key = std::make_shared<MegaFlavor::VerificationKey>(vk_raw);
    MegaVerifier verifier{ verification_key };
    info("MEGAHONK_VERIFY: Verifying proof");

    // Choose IO shape based on expected public inputs to support recursion variants.
    // Default to application IO (pairing points only).
    bool ok = false;
    const size_t npi = static_cast<size_t>(verification_key->num_public_inputs);
    if (npi >= DefaultIO::PUBLIC_INPUTS_SIZE) {
        ok = verifier.template verify_proof<DefaultIO>(proof).result;
    } else {
        // If unexpected size, fall back to DefaultIO but log a warning.
        info("MEGAHONK_VERIFY: Unexpected num_public_inputs=", npi, "; falling back to DefaultIO.");
        ok = verifier.template verify_proof<DefaultIO>(proof).result;
    }
    *result = ok;
    info("MEGAHONK_VERIFY: Verification result: ", *result);
}


WASM_EXPORT void acir_write_vk_mega_honk(uint8_t const* acir_vec, uint8_t** out)
{
    info("MEGAHONK_WRITE_VK: Function started");
    using DeciderProvingKey = DeciderProvingKey_<MegaFlavor>;
    using VerificationKey = MegaFlavor::VerificationKey;

    // lambda to free the builder
    DeciderProvingKey proving_key = [&] {
        const acir_format::ProgramMetadata metadata{ .honk_recursion = 1 };
        acir_format::AcirProgram program{ acir_format::circuit_buf_to_acir_format(
            from_buffer<std::vector<uint8_t>>(acir_vec)) };
        auto builder = acir_format::create_circuit<MegaCircuitBuilder>(program, metadata);
        return DeciderProvingKey(builder);
    }();
    info("MEGAHONK_WRITE_VK: Proving key created");
    VerificationKey vk(proving_key.get_precomputed());
    info("MEGAHONK_WRITE_VK: VK created");
    auto buffer = to_buffer(vk);
    *out = to_heap_buffer(buffer);
    info("MEGAHONK_WRITE_VK: Function completed");
}

WASM_EXPORT void merge_mega(uint8_t const* proofA_fields_buf,
                            uint8_t const* vkA_buf,
                            uint8_t const* proofB_fields_buf,
                            uint8_t const* vkB_buf,
                            uint8_t** out_proof,
                            uint8_t** out_vk,
                            uint8_t** out_metrics)
{
    using namespace bb::merge_mega;
    try {
        info("merge_mega: entry");
        auto proofA = from_buffer<std::vector<uint8_t>>(proofA_fields_buf);
        auto vkA = from_buffer<std::vector<uint8_t>>(vkA_buf);
        auto proofB = from_buffer<std::vector<uint8_t>>(proofB_fields_buf);
        auto vkB = from_buffer<std::vector<uint8_t>>(vkB_buf);
        info("merge_mega: buffers sizes A:", proofA.size(), ",", vkA.size(), "; B:", proofB.size(), ",", vkB.size());
        auto sha_proofA = crypto::sha256(proofA);
        auto sha_vkA = crypto::sha256(vkA);
        auto sha_proofB = crypto::sha256(proofB);
        auto sha_vkB = crypto::sha256(vkB);
        info("merge_mega: SHA256 A proof:", sha_proofA);
        info("merge_mega: SHA256 A vk:", sha_vkA);
        info("merge_mega: SHA256 B proof:", sha_proofB);
        info("merge_mega: SHA256 B vk:", sha_vkB);

        info("merge_mega: calling merge()…");
        auto res = merge(proofA, vkA, proofB, vkB);
        info("merge_mega: merge() returned. out sizes:", res.merged_proof_bytes.size(), ",", res.merged_vk_bytes.size());
        info("merge_mega: SHA256 merged proof:", crypto::sha256(res.merged_proof_bytes));
        info("merge_mega: SHA256 merged vk:", crypto::sha256(res.merged_vk_bytes));
        // res.merged_proof_bytes is already length-prefixed vector<fr> bytes
        *out_proof = to_heap_buffer(res.merged_proof_bytes);
        *out_vk = to_heap_buffer(res.merged_vk_bytes);
        *out_metrics = to_heap_buffer(std::vector<uint8_t>(res.metrics_json.begin(), res.metrics_json.end()));
    } catch (...) {
        // Exceptions are disabled in WASM builds (-fno-exceptions). Use a generic error message.
        std::string err = std::string("merge_mega error");
        *out_proof = to_heap_buffer(std::vector<uint8_t>{});
        *out_vk = to_heap_buffer(std::vector<uint8_t>{});
        *out_metrics = to_heap_buffer(std::vector<uint8_t>(err.begin(), err.end()));
    }
}

WASM_EXPORT void recursive_mega(uint8_t const* proof_fields_buf,
                                uint8_t const* vk_buf,
                                uint8_t** out_proof,
                                uint8_t** out_vk,
                                uint8_t** out_metrics)
{
    using namespace bb::merge_mega;
    try {
        info("recursive_mega: entry");
        auto proof = from_buffer<std::vector<uint8_t>>(proof_fields_buf);
        auto vk = from_buffer<std::vector<uint8_t>>(vk_buf);
        info("recursive_mega: buffers sizes proof:", proof.size(), ", vk:", vk.size());
        auto res = recursive_single(proof, vk);
        *out_proof = to_heap_buffer(res.merged_proof_bytes);
        *out_vk = to_heap_buffer(res.merged_vk_bytes);
        *out_metrics = to_heap_buffer(std::vector<uint8_t>(res.metrics_json.begin(), res.metrics_json.end()));
    } catch (...) {
        std::string err = std::string("recursive_mega error");
        *out_proof = to_heap_buffer(std::vector<uint8_t>{});
        *out_vk = to_heap_buffer(std::vector<uint8_t>{});
        *out_metrics = to_heap_buffer(std::vector<uint8_t>(err.begin(), err.end()));
    }
}

WASM_EXPORT void bb_memory_pages(uint32_t* out_pages)
{
#if defined(__wasm__)
    uint32_t pages = __builtin_wasm_memory_size(0);
#else
    uint32_t pages = 0;
#endif
    *out_pages = htonl(pages);
}

WASM_EXPORT void acir_prove_aztec_client(uint8_t const* ivc_inputs_buf, uint8_t** out_proof, uint8_t** out_vk)
{
    auto ivc_inputs_vec = from_buffer<std::vector<uint8_t>>(ivc_inputs_buf);
    // Accumulate the entire program stack into the IVC
    auto start = std::chrono::steady_clock::now();
    PrivateExecutionSteps steps;
    steps.parse(PrivateExecutionStepRaw::parse_uncompressed(ivc_inputs_vec));
    std::shared_ptr<ClientIVC> ivc = steps.accumulate();
    auto end = std::chrono::steady_clock::now();
    auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    vinfo("time to construct and accumulate all circuits: ", diff.count());

    vinfo("calling ivc.prove ...");
    ClientIVC::Proof proof = ivc->prove();
    end = std::chrono::steady_clock::now();

    diff = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    vinfo("time to construct, accumulate, prove all circuits: ", diff.count());

    start = std::chrono::steady_clock::now();
    *out_proof = proof.to_msgpack_heap_buffer();
    end = std::chrono::steady_clock::now();
    diff = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    vinfo("time to serialize proof: ", diff.count());

    start = std::chrono::steady_clock::now();
    *out_vk = to_heap_buffer(to_buffer(ivc->get_vk()));
    end = std::chrono::steady_clock::now();
    diff = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    vinfo("time to serialize vk: ", diff.count());
}

WASM_EXPORT void acir_verify_aztec_client(uint8_t const* proof_buf, uint8_t const* vk_buf, bool* result)
{
    const auto proof = ClientIVC::Proof::from_msgpack_buffer(proof_buf);
    const auto vk = from_buffer<ClientIVC::VerificationKey>(from_buffer<std::vector<uint8_t>>(vk_buf));

    *result = ClientIVC::verify(proof, vk);
}

WASM_EXPORT void acir_prove_ultra_zk_honk(uint8_t const* acir_vec,
                                          uint8_t const* witness_vec,
                                          uint8_t const* vk_buf,
                                          uint8_t** out)
{
    // Lambda function to ensure things get freed before proving.
    UltraZKProver prover = [&] {
        const acir_format::ProgramMetadata metadata{ .honk_recursion = 1 };
        acir_format::AcirProgram program{
            acir_format::circuit_buf_to_acir_format(from_buffer<std::vector<uint8_t>>(acir_vec)),
            acir_format::witness_buf_to_witness_data(from_buffer<std::vector<uint8_t>>(witness_vec))
        };
        auto builder = acir_format::create_circuit<UltraCircuitBuilder>(program, metadata);
        auto proving_key = std::make_shared<DeciderProvingKey_<UltraZKFlavor>>(builder);
        auto verification_key =
            std::make_shared<UltraZKFlavor::VerificationKey>(from_buffer<UltraZKFlavor::VerificationKey>(vk_buf));

        return UltraZKProver(proving_key, verification_key);
    }();

    auto proof = prover.construct_proof();
    *out = to_heap_buffer(to_buffer(proof));
}

WASM_EXPORT void acir_prove_ultra_keccak_honk(uint8_t const* acir_vec,
                                              uint8_t const* witness_vec,
                                              uint8_t const* vk_buf,
                                              uint8_t** out)
{
    // Lambda function to ensure things get freed before proving.
    UltraKeccakProver prover = [&] {
        const acir_format::ProgramMetadata metadata{ .honk_recursion = 1 };
        acir_format::AcirProgram program{
            acir_format::circuit_buf_to_acir_format(from_buffer<std::vector<uint8_t>>(acir_vec)),
            acir_format::witness_buf_to_witness_data(from_buffer<std::vector<uint8_t>>(witness_vec))
        };
        auto builder = acir_format::create_circuit<UltraCircuitBuilder>(program, metadata);

        auto proving_key = std::make_shared<DeciderProvingKey_<UltraKeccakFlavor>>(builder);
        auto verification_key = std::make_shared<UltraKeccakFlavor::VerificationKey>(
            from_buffer<UltraKeccakFlavor::VerificationKey>(vk_buf));
        return UltraKeccakProver(proving_key, verification_key);
    }();
    auto proof = prover.construct_proof();
    *out = to_heap_buffer(to_buffer(proof));
}

WASM_EXPORT void acir_prove_ultra_keccak_zk_honk(uint8_t const* acir_vec,
                                                 uint8_t const* witness_vec,
                                                 uint8_t const* vk_buf,
                                                 uint8_t** out)
{
    // Lambda function to ensure things get freed before proving.
    UltraKeccakZKProver prover = [&] {
        const acir_format::ProgramMetadata metadata{ .honk_recursion = 1 };
        acir_format::AcirProgram program{
            acir_format::circuit_buf_to_acir_format(from_buffer<std::vector<uint8_t>>(acir_vec)),
            acir_format::witness_buf_to_witness_data(from_buffer<std::vector<uint8_t>>(witness_vec))
        };
        auto builder = acir_format::create_circuit<UltraCircuitBuilder>(program, metadata);

        auto proving_key = std::make_shared<DeciderProvingKey_<UltraKeccakZKFlavor>>(builder);
        auto verification_key = std::make_shared<UltraKeccakZKFlavor::VerificationKey>(
            from_buffer<UltraKeccakZKFlavor::VerificationKey>(vk_buf));
        return UltraKeccakZKProver(proving_key, verification_key);
    }();
    auto proof = prover.construct_proof();
    *out = to_heap_buffer(to_buffer(proof));
}

WASM_EXPORT void acir_prove_ultra_starknet_honk([[maybe_unused]] uint8_t const* acir_vec,
                                                [[maybe_unused]] uint8_t const* witness_vec,
                                                [[maybe_unused]] uint8_t const* vk_buf,
                                                [[maybe_unused]] uint8_t** out)
{
#ifdef STARKNET_GARAGA_FLAVORS
    // Lambda function to ensure things get freed before proving.
    UltraStarknetProver prover = [&] {
        const acir_format::ProgramMetadata metadata{ .honk_recursion = 1 };
        acir_format::AcirProgram program{
            acir_format::circuit_buf_to_acir_format(from_buffer<std::vector<uint8_t>>(acir_vec)),
            acir_format::witness_buf_to_witness_data(from_buffer<std::vector<uint8_t>>(witness_vec))
        };
        auto builder = acir_format::create_circuit<UltraCircuitBuilder>(program, metadata);

        return UltraStarknetProver(builder);
    }();
    auto proof = prover.construct_proof();
    *out = to_heap_buffer(to_buffer(proof));
#else
    throw_or_abort("bb wasm was not compiled with starknet garaga flavors!");
#endif
}

WASM_EXPORT void acir_prove_ultra_starknet_zk_honk([[maybe_unused]] uint8_t const* acir_vec,
                                                   [[maybe_unused]] uint8_t const* witness_vec,
                                                   [[maybe_unused]] uint8_t const* vk_buf,
                                                   [[maybe_unused]] uint8_t** out)
{
#ifdef STARKNET_GARAGA_FLAVORS
    // Lambda function to ensure things get freed before proving.
    UltraStarknetZKProver prover = [&] {
        const acir_format::ProgramMetadata metadata{ .honk_recursion = 1 };
        acir_format::AcirProgram program{
            acir_format::circuit_buf_to_acir_format(from_buffer<std::vector<uint8_t>>(acir_vec)),
            acir_format::witness_buf_to_witness_data(from_buffer<std::vector<uint8_t>>(witness_vec))
        };
        auto builder = acir_format::create_circuit<UltraCircuitBuilder>(program, metadata);

        return UltraStarknetZKProver(builder);
    }();
    auto proof = prover.construct_proof();
    *out = to_heap_buffer(to_buffer(proof));
#else
    throw_or_abort("bb wasm was not compiled with starknet garaga flavors!");
#endif
}

WASM_EXPORT void acir_verify_ultra_zk_honk(uint8_t const* proof_buf, uint8_t const* vk_buf, bool* result)
{
    using VerificationKey = UltraZKFlavor::VerificationKey;
    using Verifier = UltraVerifier_<UltraZKFlavor>;

    auto proof = many_from_buffer<bb::fr>(from_buffer<std::vector<uint8_t>>(proof_buf));
    auto verification_key = std::make_shared<VerificationKey>(from_buffer<VerificationKey>(vk_buf));

    Verifier verifier{ verification_key };

    *result = verifier.template verify_proof<DefaultIO>(proof).result;
}

WASM_EXPORT void acir_verify_ultra_keccak_honk(uint8_t const* proof_buf, uint8_t const* vk_buf, bool* result)
{
    using VerificationKey = UltraKeccakFlavor::VerificationKey;
    using Verifier = UltraVerifier_<UltraKeccakFlavor>;

    auto proof = many_from_buffer<uint256_t>(from_buffer<std::vector<uint8_t>>(proof_buf));
    auto verification_key = std::make_shared<VerificationKey>(from_buffer<VerificationKey>(vk_buf));

    Verifier verifier{ verification_key };

    *result = verifier.template verify_proof<DefaultIO>(proof).result;
}

WASM_EXPORT void acir_verify_ultra_keccak_zk_honk(uint8_t const* proof_buf, uint8_t const* vk_buf, bool* result)
{
    using VerificationKey = UltraKeccakZKFlavor::VerificationKey;
    using Verifier = UltraVerifier_<UltraKeccakZKFlavor>;

    auto proof = many_from_buffer<uint256_t>(from_buffer<std::vector<uint8_t>>(proof_buf));
    auto verification_key = std::make_shared<VerificationKey>(from_buffer<VerificationKey>(vk_buf));

    Verifier verifier{ verification_key };

    *result = verifier.template verify_proof<DefaultIO>(proof).result;
}

WASM_EXPORT void acir_verify_ultra_starknet_honk([[maybe_unused]] uint8_t const* proof_buf,
                                                 [[maybe_unused]] uint8_t const* vk_buf,
                                                 [[maybe_unused]] bool* result)
{
#ifdef STARKNET_GARAGA_FLAVORS
    using VerificationKey = UltraStarknetFlavor::VerificationKey;
    using Verifier = UltraVerifier_<UltraStarknetFlavor>;

    auto proof = from_buffer<std::vector<bb::fr>>(from_buffer<std::vector<uint8_t>>(proof_buf));
    auto verification_key = std::make_shared<VerificationKey>(from_buffer<VerificationKey>(vk_buf));

    Verifier verifier{ verification_key };

    *result = verifier.template verify_proof<DefaultIO>(proof).result;
    ;
#else
    throw_or_abort("bb wasm was not compiled with starknet garaga flavors!");
#endif
}

WASM_EXPORT void acir_verify_ultra_starknet_zk_honk([[maybe_unused]] uint8_t const* proof_buf,
                                                    [[maybe_unused]] uint8_t const* vk_buf,
                                                    [[maybe_unused]] bool* result)
{
#ifdef STARKNET_GARAGA_FLAVORS
    using VerificationKey = UltraStarknetZKFlavor::VerificationKey;
    using Verifier = UltraVerifier_<UltraStarknetZKFlavor>;

    auto proof = many_from_buffer<bb::fr>(from_buffer<std::vector<uint8_t>>(proof_buf));
    auto verification_key = std::make_shared<VerificationKey>(from_buffer<VerificationKey>(vk_buf));

    Verifier verifier{ verification_key };

    *result = verifier.template verify_proof<DefaultIO>(proof).result;
#else
    throw_or_abort("bb wasm was not compiled with starknet garaga flavors!");
#endif
}

WASM_EXPORT void acir_write_vk_ultra_honk(uint8_t const* acir_vec, uint8_t** out)
{
    using DeciderProvingKey = DeciderProvingKey_<UltraFlavor>;
    using VerificationKey = UltraFlavor::VerificationKey;
    // lambda to free the builder
    DeciderProvingKey proving_key = [&] {
        const acir_format::ProgramMetadata metadata{ .honk_recursion = 1 };
        acir_format::AcirProgram program{ acir_format::circuit_buf_to_acir_format(
            from_buffer<std::vector<uint8_t>>(acir_vec)) };
        auto builder = acir_format::create_circuit<UltraCircuitBuilder>(program, metadata);
        return DeciderProvingKey(builder);
    }();
    VerificationKey vk(proving_key.get_precomputed());
    vinfo("Constructed UltraHonk verification key");
    *out = to_heap_buffer(to_buffer(vk));
}

WASM_EXPORT void acir_write_vk_ultra_keccak_honk(uint8_t const* acir_vec, uint8_t** out)
{
    using DeciderProvingKey = DeciderProvingKey_<UltraKeccakFlavor>;
    using VerificationKey = UltraKeccakFlavor::VerificationKey;

    // lambda to free the builder
    DeciderProvingKey proving_key = [&] {
        const acir_format::ProgramMetadata metadata{ .honk_recursion = 1 };
        acir_format::AcirProgram program{ acir_format::circuit_buf_to_acir_format(
            from_buffer<std::vector<uint8_t>>(acir_vec)) };
        auto builder = acir_format::create_circuit<UltraCircuitBuilder>(program, metadata);
        return DeciderProvingKey(builder);
    }();
    VerificationKey vk(proving_key.get_precomputed());
    vinfo("Constructed UltraKeccakHonk verification key");
    *out = to_heap_buffer(to_buffer(vk));
}

WASM_EXPORT void acir_write_vk_ultra_keccak_zk_honk(uint8_t const* acir_vec, uint8_t** out)
{
    using DeciderProvingKey = DeciderProvingKey_<UltraKeccakZKFlavor>;
    using VerificationKey = UltraKeccakZKFlavor::VerificationKey;

    // lambda to free the builder
    DeciderProvingKey proving_key = [&] {
        const acir_format::ProgramMetadata metadata{ .honk_recursion = 1 };
        acir_format::AcirProgram program{ acir_format::circuit_buf_to_acir_format(
            from_buffer<std::vector<uint8_t>>(acir_vec)) };
        auto builder = acir_format::create_circuit<UltraCircuitBuilder>(program, metadata);
        return DeciderProvingKey(builder);
    }();
    VerificationKey vk(proving_key.get_precomputed());
    vinfo("Constructed UltraKeccakZKHonk verification key");
    *out = to_heap_buffer(to_buffer(vk));
}

WASM_EXPORT void acir_write_vk_ultra_starknet_honk([[maybe_unused]] uint8_t const* acir_vec,
                                                   [[maybe_unused]] uint8_t** out)
{
#ifdef STARKNET_GARAGA_FLAVORS
    using DeciderProvingKey = DeciderProvingKey_<UltraStarknetFlavor>;
    using VerificationKey = UltraStarknetFlavor::VerificationKey;

    // lambda to free the builder
    DeciderProvingKey proving_key = [&] {
        const acir_format::ProgramMetadata metadata{ .honk_recursion = 1 };
        acir_format::AcirProgram program{ acir_format::circuit_buf_to_acir_format(
            from_buffer<std::vector<uint8_t>>(acir_vec)) };
        auto builder = acir_format::create_circuit<UltraCircuitBuilder>(program, metadata);
        return DeciderProvingKey(builder);
    }();
    VerificationKey vk(proving_key.get_precomputed());
    vinfo("Constructed UltraStarknetHonk verification key");
    *out = to_heap_buffer(to_buffer(vk));
#else
    throw_or_abort("bb wasm was not compiled with starknet garaga flavors!");
#endif
}

WASM_EXPORT void acir_write_vk_ultra_starknet_zk_honk([[maybe_unused]] uint8_t const* acir_vec,
                                                      [[maybe_unused]] uint8_t** out)
{
#ifdef STARKNET_GARAGA_FLAVORS
    using DeciderProvingKey = DeciderProvingKey_<UltraStarknetZKFlavor>;
    using VerificationKey = UltraStarknetZKFlavor::VerificationKey;

    // lambda to free the builder
    DeciderProvingKey proving_key = [&] {
        const acir_format::ProgramMetadata metadata{ .honk_recursion = 1 };
        acir_format::AcirProgram program{ acir_format::circuit_buf_to_acir_format(
            from_buffer<std::vector<uint8_t>>(acir_vec)) };
        auto builder = acir_format::create_circuit<UltraCircuitBuilder>(program, metadata);
        return DeciderProvingKey(builder);
    }();
    VerificationKey vk(proving_key.get_precomputed());
    vinfo("Constructed UltraStarknetZKHonk verification key");
    *out = to_heap_buffer(to_buffer(vk));
#else
    throw_or_abort("bb wasm was not compiled with starknet garaga flavors!");
#endif
}

WASM_EXPORT void acir_honk_solidity_verifier(uint8_t const* proof_buf, uint8_t const* vk_buf, uint8_t** out)
{
    using VerificationKey = UltraKeccakFlavor::VerificationKey;

    auto proof = many_from_buffer<bb::fr>(from_buffer<std::vector<uint8_t>>(proof_buf));
    auto verification_key = from_buffer<VerificationKey>(vk_buf);

    auto str = get_honk_solidity_verifier(&verification_key);
    *out = to_heap_buffer(str);
}

WASM_EXPORT void acir_proof_as_fields_ultra_honk(uint8_t const* proof_buf, fr::vec_out_buf out)
{
    auto proof = many_from_buffer<bb::fr>(from_buffer<std::vector<uint8_t>>(proof_buf));
    *out = to_heap_buffer(proof);
}

WASM_EXPORT void acir_vk_as_fields_ultra_honk(uint8_t const* vk_buf, fr::vec_out_buf out_vkey)
{
    using VerificationKey = UltraFlavor::VerificationKey;

    auto verification_key = std::make_shared<VerificationKey>(from_buffer<VerificationKey>(vk_buf));
    std::vector<bb::fr> vkey_as_fields = verification_key->to_field_elements();
    *out_vkey = to_heap_buffer(vkey_as_fields);
}

WASM_EXPORT void acir_vk_as_fields_mega_honk(uint8_t const* vk_buf, fr::vec_out_buf out_vkey)
{
    using VerificationKey = MegaFlavor::VerificationKey;

    auto verification_key = std::make_shared<VerificationKey>(from_buffer<VerificationKey>(vk_buf));
    std::vector<bb::fr> vkey_as_fields = verification_key->to_field_elements();
    *out_vkey = to_heap_buffer(vkey_as_fields);
}

WASM_EXPORT void acir_gates_aztec_client(uint8_t const* ivc_inputs_buf, uint8_t** out)
{
    auto ivc_inputs_vec = from_buffer<std::vector<uint8_t>>(ivc_inputs_buf);
    // Note: we parse a stack, but only 'bytecode' needs to be set.
    auto raw_steps = PrivateExecutionStepRaw::parse_uncompressed(ivc_inputs_vec);
    std::vector<uint32_t> totals;

    TraceSettings trace_settings{ AZTEC_TRACE_STRUCTURE };
    auto ivc = std::make_shared<ClientIVC>(/*num_circuits=*/raw_steps.size(), trace_settings);
    const acir_format::ProgramMetadata metadata{ ivc };

    for (const PrivateExecutionStepRaw& step : raw_steps) {
        std::vector<uint8_t> bytecode_vec(step.bytecode.begin(), step.bytecode.end());
        const acir_format::AcirFormat constraint_system =
            acir_format::circuit_buf_to_acir_format(std::move(bytecode_vec));

        // Create an acir program from the constraint system
        acir_format::AcirProgram program{ constraint_system };

        auto builder = acir_format::create_circuit<MegaCircuitBuilder>(program);
        builder.finalize_circuit(/*ensure_nonzero=*/true);
        totals.push_back(static_cast<uint32_t>(builder.num_gates));
    }

    *out = to_heap_buffer(to_buffer(totals));
}
