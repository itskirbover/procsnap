#include "procsnap/diff.hpp"

#include <set>
#include <unordered_map>

namespace procsnap {

namespace {

std::string process_key(const ProcessInfo& p) {
    return p.name + "|" + p.exe_path;
}

std::string outbound_key(const SocketInfo& s) {
    return s.process_name + "|" + s.protocol + "|" + s.remote_addr + ":" + std::to_string(s.remote_port);
}

}  // namespace

SnapshotDiff diff_snapshots(const Snapshot& baseline, const Snapshot& current) {
    SnapshotDiff diff;

    std::set<std::string> base_proc_keys;
    std::unordered_map<std::string, std::string> base_exe_hashes;
    for (const auto& p : baseline.processes) {
        base_proc_keys.insert(process_key(p));
        if (!p.exe_path.empty() && !p.sha256.empty()) {
            base_exe_hashes[p.exe_path] = p.sha256;
        }
    }

    std::set<std::string> curr_proc_keys;
    std::set<std::string> seen_new_procs;
    std::set<std::string> seen_drifts;
    for (const auto& p : current.processes) {
        std::string key = process_key(p);
        curr_proc_keys.insert(key);
        if (!base_proc_keys.contains(key) && seen_new_procs.insert(key).second) {
            diff.new_processes.push_back(p);
        }
        if (!p.exe_path.empty() && !p.sha256.empty()) {
            auto it = base_exe_hashes.find(p.exe_path);
            if (it != base_exe_hashes.end() && it->second != p.sha256) {
                if (seen_drifts.insert(p.exe_path).second) {
                    diff.hash_drifts.push_back(HashDrift{
                        .exe_path = p.exe_path,
                        .old_sha256 = it->second,
                        .new_sha256 = p.sha256,
                        .pid = p.pid,
                        .process_name = p.name,
                    });
                }
            }
        }
    }

    std::set<std::string> seen_term_procs;
    for (const auto& p : baseline.processes) {
        std::string key = process_key(p);
        if (!curr_proc_keys.contains(key) && seen_term_procs.insert(key).second) {
            diff.terminated_processes.push_back(p);
        }
    }

    std::set<std::string> base_out_keys;
    for (const auto& s : baseline.sockets) {
        if (s.is_outbound) base_out_keys.insert(outbound_key(s));
    }

    std::set<std::string> curr_out_keys;
    std::set<std::string> seen_new_out;
    for (const auto& s : current.sockets) {
        if (!s.is_outbound) continue;
        std::string key = outbound_key(s);
        curr_out_keys.insert(key);
        if (!base_out_keys.contains(key) && seen_new_out.insert(key).second) {
            diff.new_outbound_connections.push_back(s);
        }
    }

    std::set<std::string> seen_closed_out;
    for (const auto& s : baseline.sockets) {
        if (!s.is_outbound) continue;
        std::string key = outbound_key(s);
        if (!curr_out_keys.contains(key) && seen_closed_out.insert(key).second) {
            diff.closed_outbound_connections.push_back(s);
        }
    }

    return diff;
}

json::Value SnapshotDiff::to_json() const {
    json::Value root(json::Value::Object{});

    json::Value new_p(json::Value::Array{});
    for (const auto& p : new_processes) {
        json::Value o(json::Value::Object{});
        o["pid"] = p.pid;
        o["name"] = p.name;
        o["exe_path"] = p.exe_path;
        o["sha256"] = p.sha256;
        o["trust"] = to_string(p.trust.status);
        new_p.push_back(std::move(o));
    }
    root["new_processes"] = std::move(new_p);

    json::Value term_p(json::Value::Array{});
    for (const auto& p : terminated_processes) {
        json::Value o(json::Value::Object{});
        o["pid"] = p.pid;
        o["name"] = p.name;
        o["exe_path"] = p.exe_path;
        term_p.push_back(std::move(o));
    }
    root["terminated_processes"] = std::move(term_p);

    json::Value drifts(json::Value::Array{});
    for (const auto& d : hash_drifts) {
        json::Value o(json::Value::Object{});
        o["exe_path"] = d.exe_path;
        o["old_sha256"] = d.old_sha256;
        o["new_sha256"] = d.new_sha256;
        o["pid"] = d.pid;
        o["process_name"] = d.process_name;
        drifts.push_back(std::move(o));
    }
    root["hash_drifts"] = std::move(drifts);

    json::Value new_o(json::Value::Array{});
    for (const auto& s : new_outbound_connections) {
        json::Value o(json::Value::Object{});
        o["pid"] = s.pid;
        o["process_name"] = s.process_name;
        o["protocol"] = s.protocol;
        o["remote_addr"] = s.remote_addr;
        o["remote_port"] = static_cast<uint32_t>(s.remote_port);
        o["state"] = s.state;
        new_o.push_back(std::move(o));
    }
    root["new_outbound_connections"] = std::move(new_o);

    json::Value closed_o(json::Value::Array{});
    for (const auto& s : closed_outbound_connections) {
        json::Value o(json::Value::Object{});
        o["pid"] = s.pid;
        o["process_name"] = s.process_name;
        o["protocol"] = s.protocol;
        o["remote_addr"] = s.remote_addr;
        o["remote_port"] = static_cast<uint32_t>(s.remote_port);
        closed_o.push_back(std::move(o));
    }
    root["closed_outbound_connections"] = std::move(closed_o);

    return root;
}

}  // namespace procsnap
