#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace procsnap {

class Sha256 {
public:
    Sha256();

    void update(const uint8_t* data, size_t len);
    void update(std::string_view data);
    [[nodiscard]] std::array<uint8_t, 32> finalize();
    [[nodiscard]] std::string finalize_hex();

    static std::string hash_bytes(const uint8_t* data, size_t len);
    static std::string hash_string(std::string_view data);
    static std::optional<std::string> hash_file(const std::string& path);

private:
    void transform(const uint8_t block[64]);

    uint32_t state_[8];
    uint64_t total_bytes_;
    uint8_t buffer_[64];
    size_t buffer_len_;
    bool finalized_;
};

}  // namespace procsnap
