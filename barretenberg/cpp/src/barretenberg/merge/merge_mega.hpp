#pragma once
#include <vector>
#include <string>
#include <cstdint>

namespace bb::merge_mega {

struct MergeResult {
    std::vector<uint8_t> merged_proof_bytes;
    std::vector<uint8_t> merged_vk_bytes;
    std::vector<uint8_t> public_inputs_bytes;
    std::string metrics_json; // {"gates":...,"prove_ms":...,"rss_mb":...}
};

// Inputs are to_buffer encodings:
// - proof*_fields_buf: to_buffer(std::vector<bb::fr>) i.e., field elements of full Mega proof (public inputs + body)
// - vk*_bytes: to_buffer(MegaFlavor::VerificationKey)
MergeResult merge(const std::vector<uint8_t>& proofA_fields_buf,
                  const std::vector<uint8_t>& vkA_bytes,
                  const std::vector<uint8_t>& proofB_fields_buf,
                  const std::vector<uint8_t>& vkB_bytes);

// Construct a recursive circuit that verifies a single MegaHonk proof, then prove it with Mega.
MergeResult recursive_single(const std::vector<uint8_t>& proof_fields_buf,
                             const std::vector<uint8_t>& vk_bytes);

}