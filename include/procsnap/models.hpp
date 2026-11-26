#pragma once

#include "procsnap/json.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace procsnap {

enum class TrustStatus {
    Trusted,
    Unsigned,
    Suspicious,
    Unknown
};

enum class Severity {
    Info,
    Low,
    Medium,
    High,
    Critical
};

struct BinaryTrust {
    TrustStatus status = TrustStatus::Unknown;
    std::string signer;          // Windows Authenticode signer or Linux package name
    std::string reason;          // Human-readable explanation
    bool is_deleted = false;     // Running from a deleted file on disk
    bool is_memfd = false;       // Fileless / memfd execution (Linux)
    bool suspicious_path = false;
};

struct ProcessInfo {
    uint32_t pid = 0;
    uint32_t ppid = 0;
    uint32_t uid = 0;
    std::string user;
    std::string name;
    std::string exe_path;
    std::string cmdline;
    std::string sha256;
    BinaryTrust trust;
};

struct SocketInfo {
    std::string protocol;     // tcp, tcp6, udp, udp6
    std::string local_addr;
    uint16_t local_port = 0;
    std::string remote_addr;
    uint16_t remote_port = 0;
    std::string state;        // ESTABLISHED, LISTEN, SYN_SENT, etc.
    uint32_t pid = 0;
    std::string process_name;
    bool is_outbound = false;
};

struct Snapshot {
    std::string schema_version = "1.0";
    std::string timestamp_utc;
    std::string hostname;
    std::string platform;     // "linux" or "windows"
    std::vector<ProcessInfo> processes;
    std::vector<SocketInfo> sockets;

    [[nodiscard]] json::Value to_json() const;
    static Snapshot from_json(const json::Value& val);
    void save_to_file(const std::string& path) const;
    static Snapshot load_from_file(const std::string& path);
};

struct Alert {
    Severity severity = Severity::Low;
    std::string rule_id;
    std::string category;     // "unsigned_binary", "outbound_connection", "hash_drift", "policy_violation"
    std::string title;
    std::string detail;
    uint32_t pid = 0;
    std::string process_name;
    std::string exe_path;
    std::string sha256;
    std::string remote_endpoint;

    [[nodiscard]] json::Value to_json() const;
};

std::string to_string(TrustStatus s);
TrustStatus trust_status_from_string(const std::string& s);

std::string to_string(Severity s);
std::optional<Severity> severity_from_string(const std::string& s);
int severity_rank(Severity s);

std::string current_utc_iso8601();

}  // namespace procsnap
