#include "procsnap/sha256.hpp"

#include <cstring>
#include <fstream>

namespace procsnap {

namespace {

constexpr uint32_t kRoundConstants[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

inline uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

}  // namespace

Sha256::Sha256()
    : state_{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19},
      total_bytes_(0),
      buffer_{},
      buffer_len_(0),
      finalized_(false) {}

void Sha256::transform(const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = (static_cast<uint32_t>(block[i * 4]) << 24) |
               (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
               (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
               static_cast<uint32_t>(block[i * 4 + 3]);
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = state_[0];
    uint32_t b = state_[1];
    uint32_t c = state_[2];
    uint32_t d = state_[3];
    uint32_t e = state_[4];
    uint32_t f = state_[5];
    uint32_t g = state_[6];
    uint32_t h = state_[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + kRoundConstants[i] + w[i];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
}

void Sha256::update(const uint8_t* data, size_t len) {
    if (finalized_ || len == 0) return;
    total_bytes_ += len;

    size_t offset = 0;
    if (buffer_len_ > 0) {
        size_t take = std::min(len, size_t{64} - buffer_len_);
        std::memcpy(buffer_ + buffer_len_, data, take);
        buffer_len_ += take;
        offset += take;
        if (buffer_len_ == 64) {
            transform(buffer_);
            buffer_len_ = 0;
        }
    }

    while (offset + 64 <= len) {
        transform(data + offset);
        offset += 64;
    }

    if (offset < len) {
        buffer_len_ = len - offset;
        std::memcpy(buffer_, data + offset, buffer_len_);
    }
}

void Sha256::update(std::string_view data) {
    update(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

std::array<uint8_t, 32> Sha256::finalize() {
    if (!finalized_) {
        uint64_t total_bits = total_bytes_ * 8;
        buffer_[buffer_len_++] = 0x80;
        if (buffer_len_ > 56) {
            std::memset(buffer_ + buffer_len_, 0, 64 - buffer_len_);
            transform(buffer_);
            buffer_len_ = 0;
        }
        std::memset(buffer_ + buffer_len_, 0, 56 - buffer_len_);
        for (int i = 0; i < 8; ++i) {
            buffer_[56 + i] = static_cast<uint8_t>((total_bits >> (56 - i * 8)) & 0xFF);
        }
        transform(buffer_);
        finalized_ = true;
    }

    std::array<uint8_t, 32> digest{};
    for (int i = 0; i < 8; ++i) {
        digest[i * 4] = static_cast<uint8_t>((state_[i] >> 24) & 0xFF);
        digest[i * 4 + 1] = static_cast<uint8_t>((state_[i] >> 16) & 0xFF);
        digest[i * 4 + 2] = static_cast<uint8_t>((state_[i] >> 8) & 0xFF);
        digest[i * 4 + 3] = static_cast<uint8_t>(state_[i] & 0xFF);
    }
    return digest;
}

std::string Sha256::finalize_hex() {
    static constexpr char kHex[] = "0123456789abcdef";
    auto digest = finalize();
    std::string out;
    out.reserve(64);
    for (uint8_t b : digest) {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0x0F]);
    }
    return out;
}

std::string Sha256::hash_bytes(const uint8_t* data, size_t len) {
    Sha256 h;
    h.update(data, len);
    return h.finalize_hex();
}

std::string Sha256::hash_string(std::string_view data) {
    Sha256 h;
    h.update(data);
    return h.finalize_hex();
}

std::optional<std::string> Sha256::hash_file(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return std::nullopt;

    Sha256 h;
    uint8_t buf[65536];
    while (ifs) {
        ifs.read(reinterpret_cast<char*>(buf), sizeof(buf));
        std::streamsize n = ifs.gcount();
        if (n > 0) {
            h.update(buf, static_cast<size_t>(n));
        }
    }
    if (ifs.bad()) return std::nullopt;
    return h.finalize_hex();
}

}  // namespace procsnap
