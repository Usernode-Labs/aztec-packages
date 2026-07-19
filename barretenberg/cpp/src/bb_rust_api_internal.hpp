#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "barretenberg/ecc/curves/bn254/fr.hpp"

namespace {

inline void be32_to_le_limbs(const uint8_t* in_be, uint64_t out_le[4])
{
    for (size_t i = 0; i < 4; ++i) {
        size_t off = 24 - i * 8;
        uint64_t limb = 0;
        for (size_t j = 0; j < 8; ++j) {
            limb = (limb << 8) | in_be[off + j];
        }
        out_le[i] = limb;
    }
}

inline void le_limbs_to_be32(const uint64_t in_le[4], uint8_t* out_be)
{
    for (size_t i = 0; i < 4; ++i) {
        uint64_t limb = in_le[3 - i]; // highest limb first
        for (size_t j = 0; j < 8; ++j) {
            out_be[i * 8 + (7 - j)] = static_cast<uint8_t>(limb & 0xff);
            limb >>= 8;
        }
    }
}

// Provide malloc-backed buffers for FFI returns. `bb_free` releases them through
// the same process allocator, irrespective of which shim produced the buffer.
inline uint8_t* bb_malloc_copy(const std::vector<uint8_t>& src)
{
    if (src.empty()) return nullptr;
    auto* out = static_cast<uint8_t*>(std::malloc(src.size()));
    if (!out) return nullptr;
    std::memcpy(out, src.data(), src.size());
    return out;
}

// BN254 Fr helpers with 32-byte big-endian I/O.
inline bb::fr fr_from_be32(const uint8_t be[32])
{
    uint64_t limbs[4];
    be32_to_le_limbs(be, limbs);
    bb::fr v(limbs[0], limbs[1], limbs[2], limbs[3]);
    return v.to_montgomery_form();
}

inline std::vector<uint8_t> fr_to_be32(const bb::fr& a)
{
    auto norm = bb::fr(a).from_montgomery_form();
    std::vector<uint8_t> out(32);
    le_limbs_to_be32(norm.data, out.data());
    return out;
}

} // namespace
