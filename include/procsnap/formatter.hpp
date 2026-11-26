#pragma once

#include "procsnap/diff.hpp"
#include "procsnap/models.hpp"

#include <optional>
#include <string>
#include <vector>

namespace procsnap {

enum class OutputFormat {
    Table,
    Json,
    Jsonl
};

std::optional<OutputFormat> output_format_from_string(const std::string& s);
bool should_use_color(bool no_color_flag);

std::string format_snapshot(const Snapshot& snap, OutputFormat fmt, bool use_color);
std::string format_diff(const SnapshotDiff& diff,
                        const std::vector<Alert>& alerts,
                        OutputFormat fmt,
                        bool use_color);
std::string format_alerts(const Snapshot& snap,
                          const std::vector<Alert>& alerts,
                          OutputFormat fmt,
                          bool use_color);

}  // namespace procsnap
