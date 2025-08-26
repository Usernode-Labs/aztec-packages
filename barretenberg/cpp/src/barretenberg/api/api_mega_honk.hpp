#pragma once
#include "api.hpp"

namespace bb {

class MegaHonkAPI : public API {
  public:
    // Not implementing check/gates/solidity for mega in this first cut
    bool check(const Flags&, const std::filesystem::path&, const std::filesystem::path&) override { return false; }
    void prove(const Flags& flags,
               const std::filesystem::path& bytecode_path,
               const std::filesystem::path& witness_path,
               const std::filesystem::path& vk_path,
               const std::filesystem::path& output_dir);
    bool verify(const Flags& flags,
                const std::filesystem::path& public_inputs_path,
                const std::filesystem::path& proof_path,
                const std::filesystem::path& vk_path) override;
    void write_vk(const Flags& flags,
                  const std::filesystem::path& bytecode_path,
                  const std::filesystem::path& output_dir) override;
    void gates(const Flags&, const std::filesystem::path&) override {}
    void write_solidity_verifier(const Flags&, const std::filesystem::path&, const std::filesystem::path&) override {}
};

} // namespace bb
