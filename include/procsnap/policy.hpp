#pragma once

#include "procsnap/json.hpp"
#include "procsnap/models.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace procsnap {

struct CidrBlock {
    std::string raw;
    bool is_ipv6 = false;
    std::array<uint8_t, 16> network{};
    uint8_t prefix_len = 0;

    static std::optional<CidrBlock> parse(const std::string& cidr_str);
    [[nodiscard]] bool matches(const std::string& ip_str) const;
};

struct ProcessNetworkRule {
    std::string process_name;
    std::vector<CidrBlock> allowed_cidrs;
    std::vector<uint16_t> allowed_ports;
};

struct Policy {
    std::vector<std::string> trusted_hashes;
    std::vector<std::string> blocked_hashes;
    std::vector<std::string> trusted_paths;
    std::vector<CidrBlock> allowed_outbound_cidrs;
    std::vector<CidrBlock> denied_outbound_cidrs;
    std::vector<uint16_t> allowed_outbound_ports;
    std::vector<uint16_t> denied_outbound_ports;
    std::vector<ProcessNetworkRule> process_rules;
    bool default_deny_outbound = false;
    bool alert_on_unsigned = true;

    [[nodiscard]] bool is_hash_trusted(const std::string& sha256) const;
    [[nodiscard]] bool is_hash_blocked(const std::string& sha256) const;
    [[nodiscard]] bool is_path_trusted(const std::string& exe_path) const;
    [[nodiscard]] bool is_outbound_denied(const SocketInfo& sock, std::string* reason = nullptr) const;
    [[nodiscard]] bool is_outbound_allowed(const SocketInfo& sock) const;

    static Policy from_json(const json::Value& val);
    static Policy load_from_file(const std::string& path);
};

bool parse_ip_bytes(const std::string& ip_str, std::array<uint8_t, 16>& out, bool& is_ipv6);
bool is_private_or_local_ip(const std::string& ip_str);

}  // namespace procsnap
