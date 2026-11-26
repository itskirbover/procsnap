#pragma once

#include "procsnap/diff.hpp"
#include "procsnap/models.hpp"
#include "procsnap/policy.hpp"

#include <optional>
#include <vector>

namespace procsnap {

struct DetectorOptions {
    Severity min_severity = Severity::Low;
    std::optional<Policy> policy;
    std::optional<Snapshot> baseline;
};

std::vector<Alert> evaluate_snapshot(const Snapshot& current, const DetectorOptions& opts = {});

int exit_code_for_alerts(const std::vector<Alert>& alerts);

}  // namespace procsnap
