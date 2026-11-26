#include "procsnap/detector.hpp"

#include <algorithm>
#include <cctype>
#include <set>
#include <unordered_map>

namespace procsnap {

namespace {

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool is_suspicious_c2_port(uint16_t port) {
    static const std::set<uint16_t> kPorts = {
        1337, 4444, 4445, 5555, 6666, 6667, 9001, 9050, 9150, 12345, 31337, 54321
    };
    return kPorts.contains(port);
}

bool is_lolbin_or_shell(const std::string& process_name) {
    static const std::set<std::string> kNames = {
        // Windows LOLBins & shells
        "certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
        "bitsadmin.exe", "wscript.exe", "cscript.exe", "msiexec.exe",
        "powershell.exe", "pwsh.exe", "cmd.exe", "installutil.exe",
        "msbuild.exe", "regasm.exe", "regsvcs.exe",
        // Linux shells & raw network utilities
        "nc", "ncat", "netcat", "socat", "bash", "sh", "dash", "zsh", "ksh"
    };
    return kNames.contains(to_lower(process_name));
}

std::string format_endpoint(const SocketInfo& s) {
    if (s.remote_addr.find(':') != std::string::npos) {
        return "[" + s.remote_addr + "]:" + std::to_string(s.remote_port);
    }
    return s.remote_addr + ":" + std::to_string(s.remote_port);
}

bool is_process_trusted(const ProcessInfo& p, const Policy& policy) {
    if (policy.is_hash_trusted(p.sha256) || policy.is_path_trusted(p.exe_path)) {
        return true;
    }
    return p.trust.status == TrustStatus::Trusted;
}

}  // namespace

std::vector<Alert> evaluate_snapshot(const Snapshot& current, const DetectorOptions& opts) {
    const Policy policy = opts.policy.value_or(Policy{});

    std::unordered_map<uint32_t, const ProcessInfo*> pid_map;
    for (const auto& p : current.processes) {
        pid_map[p.pid] = &p;
    }

    std::vector<Alert> alerts;
    std::set<std::string> dedup_keys;

    auto emit = [&](Alert a) {
        if (severity_rank(a.severity) < severity_rank(opts.min_severity)) return;
        std::string key = a.rule_id + "|" + std::to_string(a.pid) + "|" + a.exe_path + "|" + a.remote_endpoint;
        if (dedup_keys.insert(key).second) {
            alerts.push_back(std::move(a));
        }
    };

    // 1. Binary & process trust checks
    for (const auto& p : current.processes) {
        if (policy.is_hash_blocked(p.sha256)) {
            emit(Alert{
                .severity = Severity::Critical,
                .rule_id = "PS-BIN-001",
                .category = "policy_violation",
                .title = "Blocked binary SHA-256 hash executing",
                .detail = "Executable SHA-256 matches policy blocked_hashes denylist.",
                .pid = p.pid,
                .process_name = p.name,
                .exe_path = p.exe_path,
                .sha256 = p.sha256,
                .remote_endpoint = "",
            });
            continue;
        }

        if (p.trust.is_memfd) {
            emit(Alert{
                .severity = Severity::Critical,
                .rule_id = "PS-BIN-002",
                .category = "unsigned_binary",
                .title = "Fileless memfd process execution",
                .detail = "Process is executing directly from an in-memory memfd descriptor.",
                .pid = p.pid,
                .process_name = p.name,
                .exe_path = p.exe_path,
                .sha256 = p.sha256,
                .remote_endpoint = "",
            });
            continue;
        }

        if (p.trust.is_deleted) {
            emit(Alert{
                .severity = Severity::High,
                .rule_id = "PS-BIN-003",
                .category = "unsigned_binary",
                .title = "Process running from deleted executable",
                .detail = "Executable backing this process has been unlinked from disk.",
                .pid = p.pid,
                .process_name = p.name,
                .exe_path = p.exe_path,
                .sha256 = p.sha256,
                .remote_endpoint = "",
            });
            continue;
        }

        if (is_process_trusted(p, policy)) {
            continue;
        }

        if (p.trust.suspicious_path) {
            emit(Alert{
                .severity = Severity::High,
                .rule_id = "PS-BIN-004",
                .category = "unsigned_binary",
                .title = "Executable running from ephemeral or user-writable path",
                .detail = p.trust.reason.empty() ? "Executable resides in a temporary/writable location." : p.trust.reason,
                .pid = p.pid,
                .process_name = p.name,
                .exe_path = p.exe_path,
                .sha256 = p.sha256,
                .remote_endpoint = "",
            });
        } else if (policy.alert_on_unsigned &&
                   (p.trust.status == TrustStatus::Unsigned || p.trust.status == TrustStatus::Suspicious)) {
            emit(Alert{
                .severity = (p.trust.status == TrustStatus::Suspicious) ? Severity::High : Severity::Medium,
                .rule_id = "PS-BIN-005",
                .category = "unsigned_binary",
                .title = "Unsigned or unverified binary executing",
                .detail = p.trust.reason.empty() ? "Executable could not be verified as signed/packaged." : p.trust.reason,
                .pid = p.pid,
                .process_name = p.name,
                .exe_path = p.exe_path,
                .sha256 = p.sha256,
                .remote_endpoint = "",
            });
        }
    }

    // 2. Baseline diff checks (hash drift & new outbound connections)
    std::set<std::string> baseline_outbound_keys;
    if (opts.baseline) {
        SnapshotDiff diff = diff_snapshots(*opts.baseline, current);
        for (const auto& d : diff.hash_drifts) {
            emit(Alert{
                .severity = Severity::Critical,
                .rule_id = "PS-BIN-006",
                .category = "hash_drift",
                .title = "Executable SHA-256 hash changed since baseline",
                .detail = "Baseline hash " + d.old_sha256.substr(0, 12) + "... changed to " +
                          d.new_sha256.substr(0, 12) + "...",
                .pid = d.pid,
                .process_name = d.process_name,
                .exe_path = d.exe_path,
                .sha256 = d.new_sha256,
                .remote_endpoint = "",
            });
        }

        for (const auto& s : opts.baseline->sockets) {
            if (s.is_outbound) {
                baseline_outbound_keys.insert(s.process_name + "|" + s.protocol + "|" +
                                              s.remote_addr + ":" + std::to_string(s.remote_port));
            }
        }
    }

    // 3. Outbound network connection policy + heuristic checks
    for (const auto& s : current.sockets) {
        if (!s.is_outbound) continue;

        const ProcessInfo* proc = nullptr;
        auto it = pid_map.find(s.pid);
        if (it != pid_map.end()) proc = it->second;

        std::string ep = format_endpoint(s);
        std::string exe = proc ? proc->exe_path : "";
        std::string sha = proc ? proc->sha256 : "";
        bool proc_trusted = proc ? is_process_trusted(*proc, policy) : false;

        std::string deny_reason;
        if (policy.is_outbound_denied(s, &deny_reason)) {
            emit(Alert{
                .severity = Severity::Critical,
                .rule_id = "PS-NET-001",
                .category = "policy_violation",
                .title = "Outbound connection violates policy denylist",
                .detail = deny_reason,
                .pid = s.pid,
                .process_name = s.process_name,
                .exe_path = exe,
                .sha256 = sha,
                .remote_endpoint = ep,
            });
            continue;
        }

        bool allowed_by_policy = policy.is_outbound_allowed(s);

        if (proc && (proc->trust.is_memfd || proc->trust.is_deleted || proc->trust.suspicious_path)) {
            emit(Alert{
                .severity = Severity::Critical,
                .rule_id = "PS-NET-002",
                .category = "outbound_connection",
                .title = "Suspicious/ephemeral binary opened outbound connection",
                .detail = "Process (" + proc->trust.reason + ") connected to " + ep,
                .pid = s.pid,
                .process_name = s.process_name,
                .exe_path = exe,
                .sha256 = sha,
                .remote_endpoint = ep,
            });
        }

        if (!allowed_by_policy && is_suspicious_c2_port(s.remote_port)) {
            emit(Alert{
                .severity = Severity::High,
                .rule_id = "PS-NET-003",
                .category = "outbound_connection",
                .title = "Outbound connection to commonly abused C2/reverse-shell port",
                .detail = "Connected via " + s.protocol + " to port " + std::to_string(s.remote_port) + " (" + ep + ")",
                .pid = s.pid,
                .process_name = s.process_name,
                .exe_path = exe,
                .sha256 = sha,
                .remote_endpoint = ep,
            });
        }

        bool is_external = !is_private_or_local_ip(s.remote_addr);

        if (!allowed_by_policy && is_external && is_lolbin_or_shell(s.process_name)) {
            emit(Alert{
                .severity = Severity::High,
                .rule_id = "PS-NET-004",
                .category = "outbound_connection",
                .title = "Dual-use LOLBin or shell opened external outbound connection",
                .detail = "Process '" + s.process_name + "' initiated external " + s.protocol + " connection to " + ep,
                .pid = s.pid,
                .process_name = s.process_name,
                .exe_path = exe,
                .sha256 = sha,
                .remote_endpoint = ep,
            });
        }

        if (!allowed_by_policy && is_external && proc && !proc_trusted &&
            proc->trust.status != TrustStatus::Unknown) {
            emit(Alert{
                .severity = Severity::High,
                .rule_id = "PS-NET-005",
                .category = "outbound_connection",
                .title = "Unsigned/untrusted binary opened external outbound connection",
                .detail = "Unverified binary connected to external endpoint " + ep,
                .pid = s.pid,
                .process_name = s.process_name,
                .exe_path = exe,
                .sha256 = sha,
                .remote_endpoint = ep,
            });
        }

        if (policy.default_deny_outbound && !allowed_by_policy) {
            emit(Alert{
                .severity = Severity::High,
                .rule_id = "PS-NET-006",
                .category = "policy_violation",
                .title = "Outbound connection not permitted by default-deny policy",
                .detail = "No allowlist rule matched " + s.protocol + " -> " + ep,
                .pid = s.pid,
                .process_name = s.process_name,
                .exe_path = exe,
                .sha256 = sha,
                .remote_endpoint = ep,
            });
        } else if (opts.baseline && !allowed_by_policy) {
            std::string out_key = s.process_name + "|" + s.protocol + "|" +
                                  s.remote_addr + ":" + std::to_string(s.remote_port);
            if (!baseline_outbound_keys.contains(out_key)) {
                emit(Alert{
                    .severity = Severity::Medium,
                    .rule_id = "PS-NET-007",
                    .category = "outbound_connection",
                    .title = "Unexpected new outbound connection (not in baseline)",
                    .detail = "Process '" + s.process_name + "' opened new " + s.protocol + " connection to " + ep,
                    .pid = s.pid,
                    .process_name = s.process_name,
                    .exe_path = exe,
                    .sha256 = sha,
                    .remote_endpoint = ep,
                });
            }
        }
    }

    std::sort(alerts.begin(), alerts.end(), [](const Alert& a, const Alert& b) {
        int ra = severity_rank(a.severity);
        int rb = severity_rank(b.severity);
        if (ra != rb) return ra > rb;
        if (a.rule_id != b.rule_id) return a.rule_id < b.rule_id;
        return a.pid < b.pid;
    });

    return alerts;
}

int exit_code_for_alerts(const std::vector<Alert>& alerts) {
    int max_rank = -1;
    for (const auto& a : alerts) {
        max_rank = std::max(max_rank, severity_rank(a.severity));
    }
    if (max_rank >= severity_rank(Severity::High)) return 3;
    if (max_rank >= severity_rank(Severity::Low)) return 2;
    return 0;
}

}  // namespace procsnap
