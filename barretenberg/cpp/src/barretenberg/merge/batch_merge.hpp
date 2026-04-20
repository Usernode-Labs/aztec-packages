#pragma once
#include <cstdint>
#include <vector>

namespace bb::batch_merge {

struct MergeResult {
    std::vector<uint8_t> merged_proof_bytes;
    std::vector<uint8_t> merged_vk_bytes;
};

// Batch-merge two Mega proofs into a Mega proof that publishes:
// - batch_root
// - inputs_root
// - outputs_root
// - two additive external-input accumulator lanes
// - binding block [vkA_hash, vkB_hash, left_batch_root, right_batch_root]
//
// The parent batch root remains
// Poseidon2(tag=20, left_batch_root, right_batch_root, vkA_hash, vkB_hash).
// VK allowlisting is enforced off-circuit using the published VK hashes.
MergeResult merge(const std::vector<uint8_t>& proofA_fields_buf,
                  const std::vector<uint8_t>& vkA_bytes,
                  const std::vector<uint8_t>& proofB_fields_buf,
                  const std::vector<uint8_t>& vkB_bytes);

const std::vector<uint8_t>& embedded_leaf_merge_vk();
const std::vector<uint8_t>& embedded_agg_merge_vk();

} // namespace bb::batch_merge
