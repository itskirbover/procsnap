#include "procsnap/collector.hpp"
#include "procsnap/detector.hpp"
#include "procsnap/diff.hpp"
#include "procsnap/json.hpp"
#include "procsnap/models.hpp"
#include "procsnap/policy.hpp"
#include "procsnap/sha256.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

int g_passed = 0;
int g_failed = 0;

void expect(bool cond, const std::string& msg) {
    if (!cond) {
        std::cerr << "FAIL: " << msg << "\n";
        ++g_failed;
    } else {
        ++g_passed;
    }
}

bool has_rule(const std::vector<procsnap::Alert>& alerts, const std::string& rule_id) {
    return std::any_of(alerts.begin(), alerts.end(),
                       [&](const procsnap::Alert& a) { return a.rule_id == rule_id; });
}

void test_sha256() {
    using procsnap::Sha256;
    expect(Sha256::hash_string("") ==
               "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
           "SHA-256 empty string");
    expect(Sha256::hash_string("abc") ==
               "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
           "SHA-256 'abc'");
    expect(Sha256::hash_string("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
               "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
           "SHA-256 NIST 448-bit vector");

    auto tmp_path = std::filesystem::temp_directory_path() / "procsnap_sha256_test.bin";
    {
        std::ofstream ofs(tmp_path, std::ios::binary | std::ios::trunc);
        ofs << "abc";
    }
    auto file_hash = Sha256::hash_file(tmp_path.string());
    std::filesystem::remove(tmp_path);
    expect(file_hash.has_value() &&
               *file_hash == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
           "SHA-256 file hashing");
}

void test_json_and_snapshot_roundtrip() {
    procsnap::Snapshot snap;
    snap.timestamp_utc = "2026-11-26T18:00:00Z";
    snap.hostname = "testhost";
    snap.platform = "linux";

    procsnap::ProcessInfo p;
    p.pid = 4242;
    p.ppid = 1;
    p.uid = 1000;
    p.user = "alice";
    p.name = "demo";
    p.exe_path = "/usr/bin/demo";
    p.cmdline = "/usr/bin/demo --flag \"quoted\"";
    p.sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    p.trust.status = procsnap::TrustStatus::Trusted;
    p.trust.signer = "pacman:demo";
    p.trust.reason = "owned by system package";
    snap.processes.push_back(p);

    procsnap::SocketInfo s;
    s.protocol = "tcp";
    s.local_addr = "10.0.0.5";
    s.local_port = 51234;
    s.remote_addr = "93.184.216.34";
    s.remote_port = 443;
    s.state = "ESTABLISHED";
    s.pid = 4242;
    s.process_name = "demo";
    s.is_outbound = true;
    snap.sockets.push_back(s);

    std::string serialized = snap.to_json().dump(2);
    auto parsed = procsnap::json::parse(serialized);
    procsnap::Snapshot restored = procsnap::Snapshot::from_json(parsed);

    expect(restored.hostname == "testhost", "Snapshot roundtrip hostname");
    expect(restored.processes.size() == 1, "Snapshot roundtrip process count");
    expect(restored.processes[0].cmdline == "/usr/bin/demo --flag \"quoted\"", "JSON escaped string roundtrip");
    expect(restored.processes[0].trust.status == procsnap::TrustStatus::Trusted, "TrustStatus roundtrip");
    expect(restored.sockets.size() == 1 && restored.sockets[0].is_outbound, "Socket roundtrip");
}

void test_cidr_and_policy() {
    auto v4 = procsnap::CidrBlock::parse("10.0.0.0/8");
    expect(v4.has_value() && v4->matches("10.42.1.9"), "IPv4 CIDR match");
    expect(v4.has_value() && !v4->matches("192.168.1.1"), "IPv4 CIDR non-match");
    expect(v4.has_value() && v4->matches("::ffff:10.1.2.3"), "IPv4-mapped IPv6 CIDR match");

    auto v6 = procsnap::CidrBlock::parse("2001:db8::/32");
    expect(v6.has_value() && v6->matches("2001:db8::1"), "IPv6 CIDR match");
    expect(v6.has_value() && !v6->matches("2001:db9::1"), "IPv6 CIDR non-match");

    expect(procsnap::is_private_or_local_ip("192.168.10.5"), "RFC1918 private IP");
    expect(!procsnap::is_private_or_local_ip("8.8.8.8"), "Public IP is not private");

    const std::string policy_json = R"({
        "default_deny_outbound": true,
        "alert_on_unsigned": true,
        "trusted_hashes": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
        "blocked_hashes": ["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
        "allowed_outbound_cidrs": ["10.0.0.0/8"],
        "denied_outbound_cidrs": ["198.51.100.0/24"],
        "denied_outbound_ports": [4444],
        "process_rules": [
            { "process_name": "curl", "allowed_ports": [443] }
        ]
    })";
    auto policy = procsnap::Policy::from_json(procsnap::json::parse(policy_json));
    expect(policy.is_hash_trusted("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
           "Policy hash allowlist case-insensitive");
    expect(policy.is_hash_blocked("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
           "Policy hash denylist");

    procsnap::SocketInfo s_allow;
    s_allow.process_name = "curl";
    s_allow.remote_addr = "1.1.1.1";
    s_allow.remote_port = 443;
    expect(policy.is_outbound_allowed(s_allow), "Policy process rule allow");

    procsnap::SocketInfo s_deny;
    s_deny.process_name = "curl";
    s_deny.remote_addr = "198.51.100.25";
    s_deny.remote_port = 443;
    expect(policy.is_outbound_denied(s_deny), "Policy CIDR denylist");
}

void test_diff_and_detector() {
    procsnap::Snapshot base;
    base.hostname = "node1";
    base.platform = "linux";
    {
        procsnap::ProcessInfo p;
        p.pid = 100;
        p.name = "sshd";
        p.exe_path = "/usr/bin/sshd";
        p.sha256 = "1111111111111111111111111111111111111111111111111111111111111111";
        p.trust.status = procsnap::TrustStatus::Trusted;
        base.processes.push_back(p);
    }

    procsnap::Snapshot curr;
    curr.hostname = "node1";
    curr.platform = "linux";
    {
        // Hash drift on sshd
        procsnap::ProcessInfo p1;
        p1.pid = 100;
        p1.name = "sshd";
        p1.exe_path = "/usr/bin/sshd";
        p1.sha256 = "2222222222222222222222222222222222222222222222222222222222222222";
        p1.trust.status = procsnap::TrustStatus::Trusted;
        curr.processes.push_back(p1);

        // Unsigned binary in /tmp connecting to C2 port 4444
        procsnap::ProcessInfo p2;
        p2.pid = 999;
        p2.name = "beacon";
        p2.exe_path = "/tmp/beacon";
        p2.sha256 = "3333333333333333333333333333333333333333333333333333333333333333";
        p2.trust.status = procsnap::TrustStatus::Suspicious;
        p2.trust.suspicious_path = true;
        p2.trust.reason = "executable located in ephemeral/writable directory";
        curr.processes.push_back(p2);

        // LOLBin opening external connection
        procsnap::ProcessInfo p3;
        p3.pid = 1001;
        p3.name = "nc";
        p3.exe_path = "/usr/bin/nc";
        p3.trust.status = procsnap::TrustStatus::Trusted;
        curr.processes.push_back(p3);
    }
    {
        procsnap::SocketInfo s1;
        s1.protocol = "tcp";
        s1.local_addr = "10.0.0.2";
        s1.local_port = 40000;
        s1.remote_addr = "203.0.113.50";
        s1.remote_port = 4444;
        s1.state = "ESTABLISHED";
        s1.pid = 999;
        s1.process_name = "beacon";
        s1.is_outbound = true;
        curr.sockets.push_back(s1);

        procsnap::SocketInfo s2;
        s2.protocol = "tcp";
        s2.local_addr = "10.0.0.2";
        s2.local_port = 40001;
        s2.remote_addr = "203.0.113.51";
        s2.remote_port = 8080;
        s2.state = "ESTABLISHED";
        s2.pid = 1001;
        s2.process_name = "nc";
        s2.is_outbound = true;
        curr.sockets.push_back(s2);
    }

    auto diff = procsnap::diff_snapshots(base, curr);
    expect(diff.hash_drifts.size() == 1, "Diff detects binary hash drift");
    expect(diff.new_processes.size() == 2, "Diff detects new processes");
    expect(diff.new_outbound_connections.size() == 2, "Diff detects new outbound connections");

    procsnap::DetectorOptions opts;
    opts.baseline = base;
    auto alerts = procsnap::evaluate_snapshot(curr, opts);
    expect(has_rule(alerts, "PS-BIN-004"), "Detector fires PS-BIN-004 for /tmp binary");
    expect(has_rule(alerts, "PS-BIN-006"), "Detector fires PS-BIN-006 for hash drift");
    expect(has_rule(alerts, "PS-NET-002"), "Detector fires PS-NET-002 for ephemeral binary outbound");
    expect(has_rule(alerts, "PS-NET-003"), "Detector fires PS-NET-003 for C2 port 4444");
    expect(has_rule(alerts, "PS-NET-004"), "Detector fires PS-NET-004 for LOLBin/shell external outbound");
    expect(has_rule(alerts, "PS-NET-007"), "Detector fires PS-NET-007 for new baseline outbound");
    expect(procsnap::exit_code_for_alerts(alerts) == 3, "Exit code 3 for high/critical alerts");
}

void test_live_collector_smoke() {
    procsnap::CollectOptions opts;
    opts.compute_hashes = false;
    opts.resolve_packages = false;
    auto snap = procsnap::collect_snapshot(opts);
    expect(!snap.processes.empty(), "Live collector finds running processes");
    expect(!snap.hostname.empty(), "Live collector populates hostname");
    expect(!snap.timestamp_utc.empty(), "Live collector populates UTC timestamp");
#if defined(_WIN32)
    expect(snap.platform == "windows", "Live collector platform is windows");
#else
    expect(snap.platform == "linux", "Live collector platform is linux");
#endif
}

}  // namespace

int main() {
    test_sha256();
    test_json_and_snapshot_roundtrip();
    test_cidr_and_policy();
    test_diff_and_detector();
    test_live_collector_smoke();

    std::cout << "Passed: " << g_passed << ", Failed: " << g_failed << "\n";
    return g_failed == 0 ? 0 : 1;
}
