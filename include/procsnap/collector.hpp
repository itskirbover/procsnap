#pragma once

#include "procsnap/models.hpp"

namespace procsnap {

struct CollectOptions {
    bool compute_hashes = true;
    bool verify_trust = true;
    bool resolve_packages = true;  // Linux: check system package manager ownership
};

Snapshot collect_snapshot(const CollectOptions& opts = {});

}  // namespace procsnap
