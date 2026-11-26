#include "procsnap/formatter.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <iomanip>
#include <sstream>

#if defined(_WIN32)
#include <io.h>
#include <cstdio>
#else
#include <unistd.h>
#endif

namespace procsnap {

namespace {

const char* kReset = "\033[0m";
const char* kBold = "\033[1m";
const char* kDim = "\033[2m";
const char* kRed = "\033[31m";
const char* kGreen = "\033[32m";
const char* kYellow = "\033[33m";
const char* kCyan = "\033[36m";
const char* kBrightRed = "\033[91m";

std::string colorize(const std::string& text, const char* code, bool use_color) {
    if (!use_color) return text;
    return std::string(code) + text + kReset;
}

std::string truncate(const std::string& s, size_t max_len) {
    if (s.size() <= max_len) return s;
    if (max_len <= 3) return s.substr(0, max_len);
    return s.substr(0, max_len - 3) + "...";
}

std::string pad_right(const std::string& s, size_t width) {
    if (s.size() >= width) return s;
    return s + std::string(width - s.size(), ' ');
}

std::string severity_badge(Severity s, bool use_color) {
    std::string label = to_string(s);
    std::transform(label.begin(), label.end(), label.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    std::string padded = pad_right("[" + label + "]", 10);
    switch (s) {
        case Severity::Critical: return colorize(padded, kBrightRed, use_color);
        case Severity::High: return colorize(padded, kRed, use_color);
        case Severity::Medium: return colorize(padded, kYellow, use_color);
        case Severity::Low: return colorize(padded, kCyan, use_color);
        case Severity::Info: return colorize(padded, kDim, use_color);
    }
    return padded;
}

std::string trust_badge(TrustStatus s, bool use_color) {
    std::string padded = pad_right(to_string(s), 10);
    switch (s) {
        case TrustStatus::Trusted: return colorize(padded, kGreen, use_color);
        case TrustStatus::Unsigned: return colorize(padded, kYellow, use_color);
        case TrustStatus::Suspicious: return colorize(padded, kBrightRed, use_color);
        case TrustStatus::Unknown: return colorize(padded, kDim, use_color);
    }
    return padded;
}

}  // namespace

std::optional<OutputFormat> output_format_from_string(const std::string& s) {
    std::string lower = s;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (lower == "table") return OutputFormat::Table;
    if (lower == "json") return OutputFormat::Json;
    if (lower == "jsonl") return OutputFormat::Jsonl;
    return std::nullopt;
}

bool should_use_color(bool no_color_flag) {
    if (no_color_flag) return false;
#if defined(_WIN32)
    char* no_color = nullptr;
    size_t len = 0;
    if (_dupenv_s(&no_color, &len, "NO_COLOR") == 0 && no_color != nullptr) {
        std::free(no_color);
        return false;
    }
    return _isatty(_fileno(stdout)) != 0;
#else
    if (std::getenv("NO_COLOR") != nullptr) return false;
    return ::isatty(STDOUT_FILENO) != 0;
#endif
}

std::string format_snapshot(const Snapshot& snap, OutputFormat fmt, bool use_color) {
    if (fmt == OutputFormat::Json) {
        return snap.to_json().dump(2) + "\n";
    }
    if (fmt == OutputFormat::Jsonl) {
        std::ostringstream oss;
        for (const auto& p : snap.processes) {
            json::Value line(json::Value::Object{});
            line["type"] = "process";
            line["timestamp_utc"] = snap.timestamp_utc;
            line["hostname"] = snap.hostname;
            line["pid"] = p.pid;
            line["name"] = p.name;
            line["user"] = p.user;
            line["exe_path"] = p.exe_path;
            line["sha256"] = p.sha256;
            line["trust"] = to_string(p.trust.status);
            line["signer"] = p.trust.signer;
            oss << line.dump(-1) << "\n";
        }
        for (const auto& s : snap.sockets) {
            json::Value line(json::Value::Object{});
            line["type"] = "socket";
            line["timestamp_utc"] = snap.timestamp_utc;
            line["hostname"] = snap.hostname;
            line["protocol"] = s.protocol;
            line["local_addr"] = s.local_addr;
            line["local_port"] = static_cast<uint32_t>(s.local_port);
            line["remote_addr"] = s.remote_addr;
            line["remote_port"] = static_cast<uint32_t>(s.remote_port);
            line["state"] = s.state;
            line["pid"] = s.pid;
            line["process_name"] = s.process_name;
            line["is_outbound"] = s.is_outbound;
            oss << line.dump(-1) << "\n";
        }
        return oss.str();
    }

    std::ostringstream oss;
    oss << colorize("PROCSNAP SNAPSHOT", kBold, use_color)
        << "  host=" << snap.hostname
        << "  platform=" << snap.platform
        << "  time=" << snap.timestamp_utc
        << "  procs=" << snap.processes.size()
        << "  sockets=" << snap.sockets.size() << "\n\n";

    oss << colorize("PROCESSES", kBold, use_color) << "\n";
    oss << pad_right("PID", 8)
        << pad_right("USER", 14)
        << pad_right("NAME", 22)
        << pad_right("TRUST", 12)
        << pad_right("SHA256", 16)
        << "EXECUTABLE\n";
    oss << std::string(100, '-') << "\n";

    for (const auto& p : snap.processes) {
        std::string short_hash = p.sha256.empty() ? "-" : p.sha256.substr(0, 12);
        oss << pad_right(std::to_string(p.pid), 8)
            << pad_right(truncate(p.user, 12), 14)
            << pad_right(truncate(p.name, 20), 22)
            << trust_badge(p.trust.status, use_color) << "  "
            << pad_right(short_hash, 16)
            << truncate(p.exe_path.empty() ? "-" : p.exe_path, 52) << "\n";
    }

    oss << "\n" << colorize("OPEN SOCKETS", kBold, use_color) << "\n";
    oss << pad_right("PROTO", 7)
        << pad_right("STATE", 13)
        << pad_right("DIR", 6)
        << pad_right("PID", 8)
        << pad_right("PROCESS", 18)
        << pad_right("LOCAL", 24)
        << "REMOTE\n";
    oss << std::string(100, '-') << "\n";

    for (const auto& s : snap.sockets) {
        std::string local = s.local_addr + ":" + std::to_string(s.local_port);
        std::string remote = s.remote_addr + ":" + std::to_string(s.remote_port);
        std::string dir = s.is_outbound ? colorize("OUT   ", kYellow, use_color) : pad_right("-", 6);
        oss << pad_right(s.protocol, 7)
            << pad_right(s.state, 13)
            << dir
            << pad_right(s.pid ? std::to_string(s.pid) : "-", 8)
            << pad_right(truncate(s.process_name.empty() ? "-" : s.process_name, 16), 18)
            << pad_right(truncate(local, 22), 24)
            << remote << "\n";
    }

    return oss.str();
}

std::string format_alerts(const Snapshot& snap,
                          const std::vector<Alert>& alerts,
                          OutputFormat fmt,
                          bool use_color) {
    if (fmt == OutputFormat::Json) {
        json::Value root(json::Value::Object{});
        root["timestamp_utc"] = snap.timestamp_utc;
        root["hostname"] = snap.hostname;
        root["platform"] = snap.platform;
        root["alert_count"] = static_cast<uint64_t>(alerts.size());
        json::Value arr(json::Value::Array{});
        for (const auto& a : alerts) arr.push_back(a.to_json());
        root["alerts"] = std::move(arr);
        return root.dump(2) + "\n";
    }
    if (fmt == OutputFormat::Jsonl) {
        std::ostringstream oss;
        for (const auto& a : alerts) {
            json::Value obj = a.to_json();
            obj["timestamp_utc"] = snap.timestamp_utc;
            obj["hostname"] = snap.hostname;
            oss << obj.dump(-1) << "\n";
        }
        return oss.str();
    }

    std::ostringstream oss;
    oss << colorize("PROCSNAP AUDIT", kBold, use_color)
        << "  host=" << snap.hostname
        << "  time=" << snap.timestamp_utc
        << "  alerts=" << alerts.size() << "\n";

    if (alerts.empty()) {
        oss << colorize("No security findings detected.", kGreen, use_color) << "\n";
        return oss.str();
    }

    oss << "\n";
    oss << pad_right("SEVERITY", 11)
        << pad_right("RULE", 12)
        << pad_right("PID", 8)
        << pad_right("PROCESS", 18)
        << pad_right("REMOTE", 24)
        << "TITLE / DETAIL\n";
    oss << std::string(108, '-') << "\n";

    for (const auto& a : alerts) {
        oss << severity_badge(a.severity, use_color) << " "
            << pad_right(a.rule_id, 12)
            << pad_right(a.pid ? std::to_string(a.pid) : "-", 8)
            << pad_right(truncate(a.process_name.empty() ? "-" : a.process_name, 16), 18)
            << pad_right(truncate(a.remote_endpoint.empty() ? "-" : a.remote_endpoint, 22), 24)
            << a.title << "\n";
        if (!a.detail.empty() || !a.exe_path.empty()) {
            oss << "           " << colorize(a.detail, kDim, use_color);
            if (!a.exe_path.empty()) {
                oss << colorize(" (" + a.exe_path + ")", kDim, use_color);
            }
            oss << "\n";
        }
    }

    return oss.str();
}

std::string format_diff(const SnapshotDiff& diff,
                        const std::vector<Alert>& alerts,
                        OutputFormat fmt,
                        bool use_color) {
    if (fmt == OutputFormat::Json) {
        json::Value root(json::Value::Object{});
        root["diff"] = diff.to_json();
        json::Value arr(json::Value::Array{});
        for (const auto& a : alerts) arr.push_back(a.to_json());
        root["alerts"] = std::move(arr);
        return root.dump(2) + "\n";
    }
    if (fmt == OutputFormat::Jsonl) {
        std::ostringstream oss;
        for (const auto& d : diff.hash_drifts) {
            json::Value o(json::Value::Object{});
            o["type"] = "hash_drift";
            o["exe_path"] = d.exe_path;
            o["old_sha256"] = d.old_sha256;
            o["new_sha256"] = d.new_sha256;
            oss << o.dump(-1) << "\n";
        }
        for (const auto& s : diff.new_outbound_connections) {
            json::Value o(json::Value::Object{});
            o["type"] = "new_outbound";
            o["pid"] = s.pid;
            o["process_name"] = s.process_name;
            o["protocol"] = s.protocol;
            o["remote_addr"] = s.remote_addr;
            o["remote_port"] = static_cast<uint32_t>(s.remote_port);
            oss << o.dump(-1) << "\n";
        }
        for (const auto& a : alerts) {
            json::Value o = a.to_json();
            o["type"] = "alert";
            oss << o.dump(-1) << "\n";
        }
        return oss.str();
    }

    std::ostringstream oss;
    oss << colorize("PROCSNAP DIFF", kBold, use_color)
        << "  new_procs=" << diff.new_processes.size()
        << "  terminated=" << diff.terminated_processes.size()
        << "  hash_drifts=" << diff.hash_drifts.size()
        << "  new_outbound=" << diff.new_outbound_connections.size()
        << "  alerts=" << alerts.size() << "\n";

    if (!diff.hash_drifts.empty()) {
        oss << "\n" << colorize("BINARY HASH DRIFT", kBrightRed, use_color) << "\n";
        for (const auto& d : diff.hash_drifts) {
            oss << "  ! " << d.exe_path << " (" << d.process_name << " pid=" << d.pid << ")\n"
                << "      old: " << d.old_sha256 << "\n"
                << "      new: " << d.new_sha256 << "\n";
        }
    }

    if (!diff.new_processes.empty()) {
        oss << "\n" << colorize("NEW PROCESSES", kCyan, use_color) << "\n";
        for (const auto& p : diff.new_processes) {
            oss << "  + [" << p.pid << "] " << p.name << "  trust=" << to_string(p.trust.status)
                << "  exe=" << (p.exe_path.empty() ? "-" : p.exe_path) << "\n";
        }
    }

    if (!diff.new_outbound_connections.empty()) {
        oss << "\n" << colorize("NEW OUTBOUND CONNECTIONS", kYellow, use_color) << "\n";
        for (const auto& s : diff.new_outbound_connections) {
            oss << "  -> [" << s.pid << "] " << s.process_name << "  " << s.protocol << " "
                << s.remote_addr << ":" << s.remote_port << " (" << s.state << ")\n";
        }
    }

    if (!alerts.empty()) {
        oss << "\n" << colorize("ALERTS", kRed, use_color) << "\n";
        for (const auto& a : alerts) {
            oss << "  " << severity_badge(a.severity, use_color) << " "
                << a.rule_id << "  " << a.title << " — " << a.detail << "\n";
        }
    } else if (diff.empty()) {
        oss << colorize("No changes detected against baseline.", kGreen, use_color) << "\n";
    }

    return oss.str();
}

}  // namespace procsnap
