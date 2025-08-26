// === AUDIT STATUS ===
// internal:    { status: not started, auditors: [], date: YYYY-MM-DD }
// external_1:  { status: not started, auditors: [], date: YYYY-MM-DD }
// external_2:  { status: not started, auditors: [], date: YYYY-MM-DD }
// =====================

#pragma once

#include "../blake2s/blake2s.hpp"
#include "../keccak/keccak.hpp"
#include "../sha256/sha256.hpp"
#include "barretenberg/crypto/poseidon2/poseidon2.hpp"

#include "memory.h"
#include <vector>

namespace bb::crypto {
struct KeccakHasher {
    static constexpr size_t BLOCK_SIZE = 64;
    static constexpr size_t OUTPUT_SIZE = 32;
    static std::vector<uint8_t> hash(const std::vector<uint8_t>& message)
    {
        keccak256 hash_result = ethash_keccak256(&message[0], message.size());

        std::vector<uint8_t> output;
        output.resize(32);

        memcpy((void*)&output[0], (void*)&hash_result.word64s[0], 32);
        return output;
    }
};

struct Sha256Hasher {
    static constexpr size_t BLOCK_SIZE = 64;
    static constexpr size_t OUTPUT_SIZE = 32;

    template <typename B = std::vector<uint8_t>> static auto hash(const B& message) { return sha256(message); }
};

struct Blake2sHasher {
    static constexpr size_t BLOCK_SIZE = 64;
    static constexpr size_t OUTPUT_SIZE = 32;
    static auto hash(const std::vector<uint8_t>& message) { return blake2s(message); }
};

// Poseidon2-based hasher producing a 32-byte digest by hashing byte input via field-chunking.
// We interpret the message as big-endian 32-byte chunks into FF elements, zero-padding the last chunk.
struct Poseidon2Hasher {
    static constexpr size_t BLOCK_SIZE = 64;
    static constexpr size_t OUTPUT_SIZE = 32;
    static std::vector<uint8_t> hash(const std::vector<uint8_t>& message)
    {
        using FF = crypto::Poseidon2<crypto::Poseidon2Bn254ScalarFieldParams>::FF;
        std::vector<FF> inputs;
        if (!message.empty()) {
            size_t i = 0;
            while (i < message.size()) {
                uint8_t buf[32] = { 0 };
                size_t rem = message.size() - i;
                size_t copy = rem >= 32 ? 32 : rem;
                // Big-endian: place message bytes at the end of the 32-byte buffer
                memcpy(buf + (32 - copy), &message[i], copy);
                // Deserialize into field (modulo reduction inside)
                FF x = FF::serialize_from_buffer(buf);
                inputs.push_back(x);
                i += copy;
            }
        } else {
            inputs.push_back(FF::zero());
        }
        auto digest = crypto::Poseidon2<crypto::Poseidon2Bn254ScalarFieldParams>::hash(inputs);
        return to_buffer(digest);
    }
};
} // namespace bb::crypto
