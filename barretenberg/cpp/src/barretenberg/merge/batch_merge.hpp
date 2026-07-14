#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>

namespace bb::batch_merge {

inline constexpr size_t MIN_MERGE_ARITY = 2;
inline constexpr size_t MAX_MERGE_ARITY = 24;
inline constexpr uint64_t BATCH_PARENT_HASH_TAG = 20;
inline constexpr uint64_t BATCH_INPUTS_ROOT_TAG = 21;
inline constexpr uint64_t BATCH_OUTPUTS_ROOT_TAG = 22;
inline constexpr size_t LEAF_SEMANTIC_PUBLIC_INPUTS = 5;
inline constexpr size_t MERGE_PUBLIC_STATEMENT_BASE_WIDTH = 6;
inline constexpr size_t MERGE_SEMANTIC_PUBLIC_INPUTS =
    MERGE_PUBLIC_STATEMENT_BASE_WIDTH + 3 * MAX_MERGE_ARITY;

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
//
// Children must use one of two exact semantic schemas:
// - transaction leaf: five fields, representing exactly one top-level
//   transaction (its input/output cardinalities may still vary);
// - batch merge: the fixed 78-field schema above, whose count is propagated.
// New leaf proof families must normalize to the five-field transaction schema,
// or introduce an explicitly versioned merge schema instead of relying on
// public-input width heuristics.
MergeResult merge_many(const std::vector<MergeInput>& children);

const std::vector<uint8_t>& embedded_leaf_merge_vk();
const std::vector<uint8_t>& embedded_agg_merge_vk();
const std::vector<uint8_t>& embedded_leaf_merge_vk(size_t arity);
const std::vector<uint8_t>& embedded_agg_merge_vk(size_t arity);

} // namespace bb::batch_merge
