#pragma once
#include <vector>
#include <cstdint>

namespace bb::batch_merge_h2 {

struct MergeResult {
    std::vector<uint8_t> merged_proof_bytes;
    std::vector<uint8_t> merged_vk_bytes;
    std::vector<uint8_t> public_inputs_bytes; // expected to be 1 field (parent hash)
};

// Batch-merge two Mega proofs into a Mega proof that computes and constrains
// parent = Poseidon2(tag=20, left, right) as an inner public input, while also
// publishing proof-field hashes and VK hashes for binding. VK allowlisting is
// enforced off-circuit using the published VK hashes.
MergeResult merge(const std::vector<uint8_t>& proofA_fields_buf,
                  const std::vector<uint8_t>& vkA_bytes,
                  const std::vector<uint8_t>& proofB_fields_buf,
                  const std::vector<uint8_t>& vkB_bytes);

}
