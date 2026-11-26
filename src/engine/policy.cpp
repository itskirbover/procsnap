#include "procsnap/policy.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <stdexcept>

namespace procsnap {

namespace {

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool parse_ipv4_bytes(const std::string& ip_str, std::array<uint8_t, 16>& out) {
    out.fill(0);
    size_t pos = 0;
    for (int octet = 0; octet < 4; ++octet) {
        size_t dot = ip_str.find('.', pos);
        if (octet < 3 && dot == std::string::npos) return false;
        if (octet == 3 && dot != std::string::npos) return false;
        std::string part = (dot == std::string::npos) ? ip_str.substr(pos) : ip_str.substr(pos, dot - pos);
        if (part.empty() || part.size() > 3) return false;
        for (char c : part) {
            if (!std::isdigit(static_cast<unsigned char>(c))) return false;
        }
        int val = std::stoi(part);
        if (val < 0 || val > 255) return false;
        out[static_cast<size_t>(octet)] = static_cast<uint8_t>(val);
        pos = dot + 1;
    }
    return true;
}

bool parse_ipv6_bytes(const std::string& ip_str, std::array<uint8_t, 16>& out) {
    out.fill(0);
    std::string s = ip_str;
    // Strip zone id if present (e.g., fe80::1%eth0)
    auto pct = s.find('%');
    if (pct != std::string::npos) s.erase(pct);

    std::vector<uint16_t> left;
    std::vector<uint16_t> right;
    bool seen_double_colon = false;

    size_t pos = 0;
    if (s.rfind("::", 0) == 0) {
        seen_double_colon = true;
        pos = 2;
    }

    while (pos < s.size()) {
        size_t colon = s.find(':', pos);
        std::string group = (colon == std::string::npos) ? s.substr(pos) : s.substr(pos, colon - pos);

        // Handle IPv4-mapped IPv6 tail like ::ffff:192.168.1.1
        if (group.find('.') != std::string::npos) {
            std::array<uint8_t, 16> v4{};
            if (!parse_ipv4_bytes(group, v4)) return false;
            auto& target = seen_double_colon ? right : left;
            target.push_back(static_cast<uint16_t>((v4[0] << 8) | v4[1]));
            target.push_back(static_cast<uint16_t>((v4[2] << 8) | v4[3]));
            if (colon != std::string::npos) return false;
            break;
        }

        if (group.empty() || group.size() > 4) return false;
        for (char c : group) {
            if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
        }
        uint16_t val = static_cast<uint16_t>(std::stoul(group, nullptr, 16));
        (seen_double_colon ? right : left).push_back(val);

        if (colon == std::string::npos) break;
        if (colon + 1 < s.size() && s[colon + 1] == ':') {
            if (seen_double_colon) return false;
            seen_double_colon = true;
            pos = colon + 2;
        } else {
            pos = colon + 1;
            if (pos == s.size()) return false;
        }
    }

    if (seen_double_colon) {
        if (left.size() + right.size() > 8) return false;
        size_t zeros = 8 - left.size() - right.size();
        size_t idx = 0;
        for (uint16_t g : left) {
            out[idx * 2] = static_cast<uint8_t>(g >> 8);
            out[idx * 2 + 1] = static_cast<uint8_t>(g & 0xFF);
            ++idx;
        }
        idx += zeros;
        for (uint16_t g : right) {
            out[idx * 2] = static_cast<uint8_t>(g >> 8);
            out[idx * 2 + 1] = static_cast<uint8_t>(g & 0xFF);
            ++idx;
        }
    } else {
        if (left.size() != 8) return false;
        for (size_t i = 0; i < 8; ++i) {
            out[i * 2] = static_cast<uint8_t>(left[i] >> 8);
            out[i * 2 + 1] = static_cast<uint8_t>(left[i] & 0xFF);
        }
    }
    return true;
}

}  // namespace

bool parse_ip_bytes(const std::string& ip_str, std::array<uint8_t, 16>& out, bool& is_ipv6) {
    if (ip_str.find(':') != std::string::npos) {
        is_ipv6 = true;
        return parse_ipv6_bytes(ip_str, out);
    }
    is_ipv6 = false;
    return parse_ipv4_bytes(ip_str, out);
}

std::optional<CidrBlock> CidrBlock::parse(const std::string& cidr_str) {
    CidrBlock block;
    block.raw = cidr_str;

    auto slash = cidr_str.find('/');
    std::string ip_part = (slash == std::string::npos) ? cidr_str : cidr_str.substr(0, slash);
    if (!parse_ip_bytes(ip_part, block.network, block.is_ipv6)) {
        return std::nullopt;
    }

    uint8_t max_bits = block.is_ipv6 ? 128 : 32;
    if (slash == std::string::npos) {
        block.prefix_len = max_bits;
    } else {
        std::string pfx_str = cidr_str.substr(slash + 1);
        if (pfx_str.empty()) return std::nullopt;
        for (char c : pfx_str) {
            if (!std::isdigit(static_cast<unsigned char>(c))) return std::nullopt;
        }
        int pfx = std::stoi(pfx_str);
        if (pfx < 0 || pfx > max_bits) return std::nullopt;
        block.prefix_len = static_cast<uint8_t>(pfx);
    }

    return block;
}

bool CidrBlock::matches(const std::string& ip_str) const {
    std::array<uint8_t, 16> addr{};
    bool addr_v6 = false;
    if (!parse_ip_bytes(ip_str, addr, addr_v6)) return false;

    // Handle IPv4-mapped IPv6 (::ffff:a.b.c.d) compared against IPv4 CIDR
    if (addr_v6 && !is_ipv6) {
        bool is_v4_mapped = true;
        for (int i = 0; i < 10; ++i) {
            if (addr[static_cast<size_t>(i)] != 0) is_v4_mapped = false;
        }
        if (is_v4_mapped && addr[10] == 0xFF && addr[11] == 0xFF) {
            std::array<uint8_t, 16> v4{};
            std::memcpy(v4.data(), addr.data() + 12, 4);
            addr = v4;
            addr_v6 = false;
        }
    }

    if (addr_v6 != is_ipv6) return false;

    uint8_t full_bytes = prefix_len / 8;
    uint8_t rem_bits = prefix_len % 8;

    for (uint8_t i = 0; i < full_bytes; ++i) {
        if (addr[i] != network[i]) return false;
    }
    if (rem_bits > 0) {
        uint8_t mask = static_cast<uint8_t>(0xFFu << (8u - rem_bits));
        if ((addr[full_bytes] & mask) != (network[full_bytes] & mask)) return false;
    }
    return true;
}

bool is_private_or_local_ip(const std::string& ip_str) {
    static const std::vector<CidrBlock> kPrivateCidrs = []() {
        std::vector<CidrBlock> v;
        for (const char* c : {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                              "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8",
                              "::1/128", "::/128", "fc00::/7", "fe80::/10"}) {
            if (auto b = CidrBlock::parse(c)) v.push_back(*b);
        }
        return v;
    }();

    for (const auto& cidr : kPrivateCidrs) {
        if (cidr.matches(ip_str)) return true;
    }
    return false;
}

bool Policy::is_hash_trusted(const std::string& sha256) const {
    if (sha256.empty()) return false;
    std::string h = to_lower(sha256);
    for (const auto& t : trusted_hashes) {
        if (to_lower(t) == h) return true;
    }
    return false;
}

bool Policy::is_hash_blocked(const std::string& sha256) const {
    if (sha256.empty()) return false;
    std::string h = to_lower(sha256);
    for (const auto& b : blocked_hashes) {
        if (to_lower(b) == h) return true;
    }
    return false;
}

bool Policy::is_path_trusted(const std::string& exe_path) const {
    if (exe_path.empty()) return false;
    for (const auto& prefix : trusted_paths) {
        if (!prefix.empty() && exe_path.rfind(prefix, 0) == 0) return true;
    }
    return false;
}

bool Policy::is_outbound_denied(const SocketInfo& sock, std::string* reason) const {
    for (const auto& cidr : denied_outbound_cidrs) {
        if (cidr.matches(sock.remote_addr)) {
            if (reason) *reason = "remote IP matches denied CIDR " + cidr.raw;
            return true;
        }
    }
    for (uint16_t p : denied_outbound_ports) {
        if (sock.remote_port == p) {
            if (reason) *reason = "remote port " + std::to_string(p) + " is explicitly denied by policy";
            return true;
        }
    }
    return false;
}

bool Policy::is_outbound_allowed(const SocketInfo& sock) const {
    // Check process-specific rules first
    std::string proc_lower = to_lower(sock.process_name);
    for (const auto& rule : process_rules) {
        if (to_lower(rule.process_name) != proc_lower) continue;
        bool cidr_ok = rule.allowed_cidrs.empty();
        for (const auto& c : rule.allowed_cidrs) {
            if (c.matches(sock.remote_addr)) {
                cidr_ok = true;
                break;
            }
        }
        bool port_ok = rule.allowed_ports.empty();
        for (uint16_t p : rule.allowed_ports) {
            if (sock.remote_port == p) {
                port_ok = true;
                break;
            }
        }
        if (cidr_ok && port_ok) return true;
    }

    for (const auto& cidr : allowed_outbound_cidrs) {
        if (cidr.matches(sock.remote_addr)) return true;
    }
    for (uint16_t p : allowed_outbound_ports) {
        if (sock.remote_port == p) return true;
    }
    return false;
}

Policy Policy::from_json(const json::Value& val) {
    if (!val.is_object()) {
        throw std::runtime_error("Invalid policy JSON: root must be an object");
    }
    Policy p;
    if (val.contains("default_deny_outbound")) {
        p.default_deny_outbound = val.at("default_deny_outbound").as_bool();
    }
    if (val.contains("alert_on_unsigned")) {
        p.alert_on_unsigned = val.at("alert_on_unsigned").as_bool(true);
    }
    for (const auto& v : val.at("trusted_hashes").as_array()) {
        if (v.is_string()) p.trusted_hashes.push_back(v.as_string());
    }
    for (const auto& v : val.at("blocked_hashes").as_array()) {
        if (v.is_string()) p.blocked_hashes.push_back(v.as_string());
    }
    for (const auto& v : val.at("trusted_paths").as_array()) {
        if (v.is_string()) p.trusted_paths.push_back(v.as_string());
    }
    for (const auto& v : val.at("allowed_outbound_cidrs").as_array()) {
        if (auto c = CidrBlock::parse(v.as_string())) {
            p.allowed_outbound_cidrs.push_back(*c);
        } else {
            throw std::runtime_error("Invalid CIDR in allowed_outbound_cidrs: " + v.as_string());
        }
    }
    for (const auto& v : val.at("denied_outbound_cidrs").as_array()) {
        if (auto c = CidrBlock::parse(v.as_string())) {
            p.denied_outbound_cidrs.push_back(*c);
        } else {
            throw std::runtime_error("Invalid CIDR in denied_outbound_cidrs: " + v.as_string());
        }
    }
    for (const auto& v : val.at("allowed_outbound_ports").as_array()) {
        p.allowed_outbound_ports.push_back(static_cast<uint16_t>(v.as_int()));
    }
    for (const auto& v : val.at("denied_outbound_ports").as_array()) {
        p.denied_outbound_ports.push_back(static_cast<uint16_t>(v.as_int()));
    }
    for (const auto& rv : val.at("process_rules").as_array()) {
        ProcessNetworkRule rule;
        rule.process_name = rv.at("process_name").as_string();
        for (const auto& c : rv.at("allowed_cidrs").as_array()) {
            if (auto parsed = CidrBlock::parse(c.as_string())) {
                rule.allowed_cidrs.push_back(*parsed);
            }
        }
        for (const auto& port : rv.at("allowed_ports").as_array()) {
            rule.allowed_ports.push_back(static_cast<uint16_t>(port.as_int()));
        }
        if (!rule.process_name.empty()) {
            p.process_rules.push_back(std::move(rule));
        }
    }
    return p;
}

Policy Policy::load_from_file(const std::string& path) {
    return from_json(json::parse_file(path));
}

}  // namespace procsnap
