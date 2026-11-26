#include "procsnap/models.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <stdexcept>

namespace procsnap {

std::string to_string(TrustStatus s) {
    switch (s) {
        case TrustStatus::Trusted: return "trusted";
        case TrustStatus::Unsigned: return "unsigned";
        case TrustStatus::Suspicious: return "suspicious";
        case TrustStatus::Unknown: return "unknown";
    }
    return "unknown";
}

TrustStatus trust_status_from_string(const std::string& s) {
    if (s == "trusted") return TrustStatus::Trusted;
    if (s == "unsigned") return TrustStatus::Unsigned;
    if (s == "suspicious") return TrustStatus::Suspicious;
    return TrustStatus::Unknown;
}

std::string to_string(Severity s) {
    switch (s) {
        case Severity::Info: return "info";
        case Severity::Low: return "low";
        case Severity::Medium: return "medium";
        case Severity::High: return "high";
        case Severity::Critical: return "critical";
    }
    return "low";
}

std::optional<Severity> severity_from_string(const std::string& s) {
    std::string lower = s;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (lower == "info") return Severity::Info;
    if (lower == "low") return Severity::Low;
    if (lower == "medium") return Severity::Medium;
    if (lower == "high") return Severity::High;
    if (lower == "critical") return Severity::Critical;
    return std::nullopt;
}

int severity_rank(Severity s) {
    switch (s) {
        case Severity::Info: return 0;
        case Severity::Low: return 1;
        case Severity::Medium: return 2;
        case Severity::High: return 3;
        case Severity::Critical: return 4;
    }
    return 0;
}

std::string current_utc_iso8601() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm utc_tm{};
#if defined(_WIN32)
    gmtime_s(&utc_tm, &t);
#else
    gmtime_r(&t, &utc_tm);
#endif
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ",
                  utc_tm.tm_year + 1900, utc_tm.tm_mon + 1, utc_tm.tm_mday,
                  utc_tm.tm_hour, utc_tm.tm_min, utc_tm.tm_sec);
    return std::string(buf);
}

json::Value Snapshot::to_json() const {
    json::Value root(json::Value::Object{});
    root["schema_version"] = schema_version;
    root["timestamp_utc"] = timestamp_utc;
    root["hostname"] = hostname;
    root["platform"] = platform;

    json::Value procs(json::Value::Array{});
    for (const auto& p : processes) {
        json::Value po(json::Value::Object{});
        po["pid"] = p.pid;
        po["ppid"] = p.ppid;
        po["uid"] = p.uid;
        po["user"] = p.user;
        po["name"] = p.name;
        po["exe_path"] = p.exe_path;
        po["cmdline"] = p.cmdline;
        po["sha256"] = p.sha256;

        json::Value tr(json::Value::Object{});
        tr["status"] = to_string(p.trust.status);
        tr["signer"] = p.trust.signer;
        tr["reason"] = p.trust.reason;
        tr["is_deleted"] = p.trust.is_deleted;
        tr["is_memfd"] = p.trust.is_memfd;
        tr["suspicious_path"] = p.trust.suspicious_path;
        po["trust"] = std::move(tr);

        procs.push_back(std::move(po));
    }
    root["processes"] = std::move(procs);

    json::Value socks(json::Value::Array{});
    for (const auto& s : sockets) {
        json::Value so(json::Value::Object{});
        so["protocol"] = s.protocol;
        so["local_addr"] = s.local_addr;
        so["local_port"] = static_cast<uint32_t>(s.local_port);
        so["remote_addr"] = s.remote_addr;
        so["remote_port"] = static_cast<uint32_t>(s.remote_port);
        so["state"] = s.state;
        so["pid"] = s.pid;
        so["process_name"] = s.process_name;
        so["is_outbound"] = s.is_outbound;
        socks.push_back(std::move(so));
    }
    root["sockets"] = std::move(socks);

    return root;
}

Snapshot Snapshot::from_json(const json::Value& val) {
    if (!val.is_object()) {
        throw std::runtime_error("Invalid snapshot JSON: root must be an object");
    }
    Snapshot snap;
    if (val.contains("schema_version")) snap.schema_version = val.at("schema_version").as_string();
    snap.timestamp_utc = val.at("timestamp_utc").as_string();
    snap.hostname = val.at("hostname").as_string();
    snap.platform = val.at("platform").as_string();

    for (const auto& po : val.at("processes").as_array()) {
        ProcessInfo p;
        p.pid = static_cast<uint32_t>(po.at("pid").as_int());
        p.ppid = static_cast<uint32_t>(po.at("ppid").as_int());
        p.uid = static_cast<uint32_t>(po.at("uid").as_int());
        p.user = po.at("user").as_string();
        p.name = po.at("name").as_string();
        p.exe_path = po.at("exe_path").as_string();
        p.cmdline = po.at("cmdline").as_string();
        p.sha256 = po.at("sha256").as_string();

        const auto& tr = po.at("trust");
        if (tr.is_object()) {
            p.trust.status = trust_status_from_string(tr.at("status").as_string());
            p.trust.signer = tr.at("signer").as_string();
            p.trust.reason = tr.at("reason").as_string();
            p.trust.is_deleted = tr.at("is_deleted").as_bool();
            p.trust.is_memfd = tr.at("is_memfd").as_bool();
            p.trust.suspicious_path = tr.at("suspicious_path").as_bool();
        }
        snap.processes.push_back(std::move(p));
    }

    for (const auto& so : val.at("sockets").as_array()) {
        SocketInfo s;
        s.protocol = so.at("protocol").as_string();
        s.local_addr = so.at("local_addr").as_string();
        s.local_port = static_cast<uint16_t>(so.at("local_port").as_int());
        s.remote_addr = so.at("remote_addr").as_string();
        s.remote_port = static_cast<uint16_t>(so.at("remote_port").as_int());
        s.state = so.at("state").as_string();
        s.pid = static_cast<uint32_t>(so.at("pid").as_int());
        s.process_name = so.at("process_name").as_string();
        s.is_outbound = so.at("is_outbound").as_bool();
        snap.sockets.push_back(std::move(s));
    }

    return snap;
}

void Snapshot::save_to_file(const std::string& path) const {
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    if (!ofs) {
        throw std::runtime_error("Failed to open output file for writing: " + path);
    }
    ofs << to_json().dump(2) << '\n';
}

Snapshot Snapshot::load_from_file(const std::string& path) {
    return from_json(json::parse_file(path));
}

json::Value Alert::to_json() const {
    json::Value obj(json::Value::Object{});
    obj["severity"] = to_string(severity);
    obj["rule_id"] = rule_id;
    obj["category"] = category;
    obj["title"] = title;
    obj["detail"] = detail;
    obj["pid"] = pid;
    obj["process_name"] = process_name;
    obj["exe_path"] = exe_path;
    obj["sha256"] = sha256;
    obj["remote_endpoint"] = remote_endpoint;
    return obj;
}

}  // namespace procsnap
