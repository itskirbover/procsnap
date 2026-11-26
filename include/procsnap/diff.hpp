#pragma once

#include "procsnap/json.hpp"
#include "procsnap/models.hpp"

#include <string>
#include <vector>

namespace procsnap {

struct HashDrift {
    std::string exe_path;
    std::string old_sha256;
    std::string new_sha256;
    uint32_t pid = 0;
    std::string process_name;
};

struct SnapshotDiff {
    std::vector<ProcessInfo> new_processes;
    std::vector<ProcessInfo> terminated_processes;
    std::vector<HashDrift> hash_drifts;
    std::vector<SocketInfo> new_outbound_connections;
    std::vector<SocketInfo> closed_outbound_connections;

    [[nodiscard]] bool empty() const {
        return new_processes.empty() && terminated_processes.empty() &&
               hash_drifts.empty() && new_outbound_connections.empty() &&
               closed_outbound_connections.empty();
    }

    [[nodiscard]] json::Value to_json() const;
};

SnapshotDiff diff_snapshots(const Snapshot& baseline, const Snapshot& current);

}  // namespace procsnap
