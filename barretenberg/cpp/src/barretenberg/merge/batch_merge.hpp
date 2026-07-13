#pragma once
#include <cstdint>
#include <vector>

namespace bb::batch_merge {

struct MergeResult {
    std::vector<uint8_t> merged_proof_bytes;
    std::vector<uint8_t> merged_vk_bytes;
};

struct MergeInput {
    std::vector<uint8_t> proof_fields_buf;
    std::vector<uint8_t> vk_bytes;
};

// Batch-merge two Mega proofs with the same fixed-width circuit family used by
// the K-ary entrypoint. This convenience API publishes:
// - batch_root
// - inputs_root
// - outputs_root
// - two additive external-input accumulator lanes
// - count
// - twenty-four child binding slots [child_vk_hash, child_batch_root, child_count],
//   with unused slots set to zero.
//
// The parent batch root is
// Poseidon2(tag=20, arity, child_0_root, child_0_vk_hash, child_0_count, ...).
// VK allowlisting is enforced off-circuit using the published VK hashes.
MergeResult merge(const std::vector<uint8_t>& proofA_fields_buf,
                  const std::vector<uint8_t>& vkA_bytes,
                  const std::vector<uint8_t>& proofB_fields_buf,
                  const std::vector<uint8_t>& vkB_bytes);

// Batch-merge K Mega proofs into one Mega proof.
//
// The parent batch root is:
// Poseidon2(tag=20, arity, child_0_root, child_0_vk_hash, child_0_count, ...)
// and ordered input/output roots are:
// Poseidon2(tag=21/22, arity, child_0_root, ...)
//
// All batch merge proofs publish the same 78 semantic public inputs. The first
// six public inputs are always:
// [batch_root, inputs_root, outputs_root, input_acc_a, input_acc_b, count].
// The remaining seventy-two public inputs are twenty-four triples of
// [child_vk_hash, child_batch_root, child_count] in child order. Slots above the
// active arity are zero.
MergeResult merge_many(const std::vector<MergeInput>& children);

const std::vector<uint8_t>& embedded_leaf_merge_vk();
const std::vector<uint8_t>& embedded_agg_merge_vk();
const std::vector<uint8_t>& embedded_leaf_merge_vk(size_t arity);
const std::vector<uint8_t>& embedded_agg_merge_vk(size_t arity);

} // namespace bb::batch_merge
