#include "barretenberg/merge/merge_mega.hpp"
#include <iostream>
#include <filesystem>
#include <fstream>
#include <vector>

int main(int argc, char** argv)
{
    if (argc != 6) {
        std::cerr << "Usage: merge_mega_tool <proofA_fields.bin> <vkA.bin> <proofB_fields.bin> <vkB.bin> <out_dir>\n";
        return 1;
    }
    std::filesystem::path proofA_path = argv[1];
    std::filesystem::path vkA_path = argv[2];
    std::filesystem::path proofB_path = argv[3];
    std::filesystem::path vkB_path = argv[4];
    std::filesystem::path out_dir = argv[5];

    auto read_bin = [](const std::filesystem::path& p) {
        std::ifstream f(p, std::ios::binary);
        if (!f) { throw std::runtime_error("Failed to open " + p.string()); }
        std::vector<uint8_t> buf((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        return buf;
    };
    auto write_bin = [](const std::filesystem::path& p, const std::vector<uint8_t>& d) {
        std::ofstream f(p, std::ios::binary);
        if (!f) { throw std::runtime_error("Failed to write " + p.string()); }
        f.write(reinterpret_cast<const char*>(d.data()), static_cast<std::streamsize>(d.size()));
    };

    auto proofA_buf = read_bin(proofA_path);
    auto vkA_buf = read_bin(vkA_path);
    auto proofB_buf = read_bin(proofB_path);
    auto vkB_buf = read_bin(vkB_path);

    auto res = bb::merge_mega::merge(proofA_buf, vkA_buf, proofB_buf, vkB_buf);
    std::filesystem::create_directories(out_dir);
    write_bin((out_dir / "merged_proof"), res.merged_proof_bytes);
    write_bin((out_dir / "merged_vk"), res.merged_vk_bytes);
    std::string metrics = res.metrics_json + "\n";
    write_bin((out_dir / "metrics.json"), std::vector<uint8_t>(metrics.begin(), metrics.end()));
    std::cout << res.metrics_json << std::endl;
    return 0;
}