#pragma once
#include <cstdint>
#include <vector>

namespace bb::batch_merge {

struct MergeResult {
    std::vector<uint8_t> merged_proof_bytes;
    std::vector<uint8_t> merged_vk_bytes;
};

// Batch-merge two Mega proofs into a Mega proof that computes and constrains
// parent = Poseidon2(tag=20, left, right, vkA_hash, vkB_hash) as an inner public
// input and publishes child combiners + VK hashes for binding. VK allowlisting
// is enforced off-circuit using the published VK hashes.
MergeResult merge(const std::vector<uint8_t>& proofA_fields_buf,
                  const std::vector<uint8_t>& vkA_bytes,
                  const std::vector<uint8_t>& proofB_fields_buf,
                  const std::vector<uint8_t>& vkB_bytes);

const std::vector<uint8_t>& embedded_leaf_merge_vk();
const std::vector<uint8_t>& embedded_agg_merge_vk();

} // namespace bb::batch_merge
