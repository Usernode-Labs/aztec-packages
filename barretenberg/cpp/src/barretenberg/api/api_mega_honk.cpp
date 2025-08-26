#include "api_mega_honk.hpp"

#include "barretenberg/api/file_io.hpp"
#include "barretenberg/api/get_bytecode.hpp"
#include "barretenberg/common/throw_or_abort.hpp"
#include "barretenberg/common/serialize.hpp"
#include "barretenberg/dsl/acir_format/acir_to_constraint_buf.hpp"
#include "barretenberg/dsl/acir_proofs/honk_contract.hpp"
#include "barretenberg/stdlib_circuit_builders/mega_circuit_builder.hpp"
#include "barretenberg/ultra_honk/decider_proving_key.hpp"

namespace bb {

void MegaHonkAPI::prove(const Flags& flags,
                        const std::filesystem::path& bytecode_path,
                        const std::filesystem::path& witness_path,
                        const std::filesystem::path& /*vk_path*/,
                        const std::filesystem::path& output_dir)
{
    if (output_dir == "-") {
        throw_or_abort("Stdout output is not supported. Please specify an output directory.");
    }

    const acir_format::ProgramMetadata metadata{ .honk_recursion = 1 };
    acir_format::AcirProgram program{ acir_format::circuit_buf_to_acir_format(get_bytecode(bytecode_path)),
                                      acir_format::witness_buf_to_witness_data(get_bytecode(witness_path)) };

    auto builder = acir_format::create_circuit<MegaCircuitBuilder>(program, metadata);
    auto proving_key = std::make_shared<DeciderProvingKey_<MegaFlavor>>(builder);
    auto verification_key = std::make_shared<MegaFlavor::VerificationKey>(proving_key->get_precomputed());

    MegaProver prover{ proving_key, verification_key };
    auto proof = prover.construct_proof();

    // Write outputs according to flags.output_format (support bytes and bytes_and_fields)
    if (flags.output_format == "bytes" || flags.output_format == "bytes_and_fields") {
        write_file(output_dir / "proof", to_buffer<true>(proof));
        write_file(output_dir / "vk", to_buffer(*verification_key));
        info("Proof saved to ", output_dir / "proof");
        info("VK saved to ", output_dir / "vk");
    }
    if (flags.output_format == "fields" || flags.output_format == "bytes_and_fields") {
        // Provide a fields JSON for the proof to aid dev workflows
        std::string proof_json = field_elements_to_json(proof);
        write_file(output_dir / "proof_fields.json", { proof_json.begin(), proof_json.end() });
        info("Proof fields saved to ", output_dir / "proof_fields.json");
        // VK fields not implemented yet for Mega in CLI. (TS binding has acir_vk_as_fields_mega_honk.)
    }
}

bool MegaHonkAPI::verify(const Flags&,
                         const std::filesystem::path& /*public_inputs_path*/,
                         const std::filesystem::path& proof_path,
                         const std::filesystem::path& vk_path)
{
    auto proof_file = read_file(proof_path);
    auto vk_bytes = read_file(vk_path);
    // Parse proof directly from file (length-prefixed vector<fr>)
    auto proof = from_buffer<HonkProof>(proof_file);
    auto vk = from_buffer<std::shared_ptr<MegaFlavor::VerificationKey>>(vk_bytes);

    MegaVerifier verifier{ vk };
    return verifier.template verify_proof<DefaultIO>(proof).result;
}

void MegaHonkAPI::write_vk(const Flags& flags,
                           const std::filesystem::path& bytecode_path,
                           const std::filesystem::path& output_dir)
{
    if (output_dir == "-") {
        throw_or_abort("Stdout output is not supported. Please specify an output directory.");
    }
    const acir_format::ProgramMetadata metadata{ .honk_recursion = 1 };
    acir_format::AcirProgram program{ acir_format::circuit_buf_to_acir_format(get_bytecode(bytecode_path)) };
    auto builder = acir_format::create_circuit<MegaCircuitBuilder>(program, metadata);
    auto proving_key = std::make_shared<DeciderProvingKey_<MegaFlavor>>(builder);
    auto verification_key = std::make_shared<MegaFlavor::VerificationKey>(proving_key->get_precomputed());

    if (flags.output_format == "bytes" || flags.output_format == "bytes_and_fields") {
        write_file(output_dir / "vk", to_buffer(*verification_key));
        info("VK saved to ", output_dir / "vk");
    }
    if (flags.output_format == "fields" || flags.output_format == "bytes_and_fields") {
        // Not implementing VK fields for Mega here.
    }
}

} // namespace bb
