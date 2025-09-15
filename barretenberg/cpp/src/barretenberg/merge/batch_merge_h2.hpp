#pragma once
#include <vector>
#include <cstdint>

namespace bb::batch_merge_h2 {

struct MergeResult {
    std::vector<uint8_t> merged_proof_bytes;
    std::vector<uint8_t> merged_vk_bytes;
    std::vector<uint8_t> public_inputs_bytes; // expected to be 1 field (parent hash)
};

// Scaffold: batch-merge two Mega proofs into a Mega proof that will, in the
// full implementation, constrain parent = H2(left,right) as a public input.
// For now, this delegates to merge_mega::merge to keep behavior identical and
// isolates wiring behind a dedicated API.
MergeResult merge(const std::vector<uint8_t>& proofA_fields_buf,
                  const std::vector<uint8_t>& vkA_bytes,
                  const std::vector<uint8_t>& proofB_fields_buf,
                  const std::vector<uint8_t>& vkB_bytes);

}

