# procsnap

A fast, zero-dependency **C++20** cross-platform (**Linux & Windows**) CLI tool that snapshots running processes, open network sockets, and executable SHA-256 hashes, alerting on unsigned/untrusted binaries and unexpected outbound connections.

> **Supported Platforms:** Linux and Windows only (macOS is intentionally not supported).

---

## Features

- **Native OS Telemetry (Zero Third-Party Dependencies)**
  - **Linux**: Enumerates `/proc/<pid>/{stat,status,cmdline,exe}`, correlates `/proc/net/{tcp,tcp6,udp,udp6}` sockets to PIDs via `/proc/<pid>/fd` inodes, and verifies binary trust via `memfd:`/deleted/ephemeral-path checks plus cached package-manager ownership (`pacman`, `dpkg`, `rpm`).
  - **Windows**: Enumerates processes via `CreateToolhelp32Snapshot` + `QueryFullProcessImageNameW`, maps IPv4/IPv6 TCP & UDP sockets to PIDs via `GetExtendedTcpTable` / `GetExtendedUdpTable`, and verifies Authenticode signatures via `WinVerifyTrust` + signer extraction via `CryptQueryObject`.
- **Executable Integrity**: Built-in streaming **SHA-256** file hasher (cached per unique executable path) with baseline hash-drift detection.
- **Layered Outbound & Binary Alerting**:
  - **Baseline Diffing**: Detects new/terminated processes, binary SHA-256 drift, and unexpected new outbound connections.
  - **JSON Policy Engine**: Supports IPv4/IPv6 CIDR allow/deny rules (including IPv4-mapped IPv6), port rules, per-process network rules, `default_deny_outbound` mode, and SHA-256 allowlists/denylists.
  - **Built-in Security Heuristics**: Flags fileless `memfd` execution, deleted-on-disk executables, ephemeral/writable execution paths (`/tmp`, `/dev/shm`, `\Temp\`, `\Users\Public\`), unsigned external egress, commonly abused C2/reverse-shell ports, and dual-use LOLBin/shell external outbound connections.
- **Flexible CLI & Output**: `snapshot`, `diff`, `audit`, and continuous `watch` modes with ANSI-colored terminal tables (respecting TTY & `NO_COLOR`), JSON, JSONL, and severity-based exit codes.

---

## Building

### Prerequisites
- CMake 3.20+
- C++20 compiler (GCC 11+, Clang 14+, or MSVC 2022+)

### Linux
```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

### Windows (MSVC)
```powershell
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure
```

---

## Usage

### 1. Capture a golden baseline snapshot
```bash
procsnap snapshot --out baseline.json
```

Print live processes and open sockets as a table, JSON, or JSONL:
```bash
procsnap snapshot --format table
procsnap snapshot --format json
procsnap snapshot --format jsonl
```

### 2. Diff against a baseline
Compare the live host against a saved baseline (or compare two snapshot files):
```bash
procsnap diff baseline.json --policy examples/procsnap.policy.json
procsnap diff baseline.json current.json --format json
```

### 3. Run a live security audit
```bash
procsnap audit --baseline baseline.json --policy examples/procsnap.policy.json --min-severity medium
```

### 4. Continuous watch mode
Poll every 5 seconds and emit real-time delta alerts (JSONL is ideal for SIEM/log ingestion):
```bash
procsnap watch --interval 5 --policy examples/procsnap.policy.json --format jsonl
```

---

## Detection Rules

| Rule ID | Severity | Category | Description |
| :--- | :--- | :--- | :--- |
| `PS-BIN-001` | Critical | `policy_violation` | Running binary matches `blocked_hashes` SHA-256 denylist |
| `PS-BIN-002` | Critical | `unsigned_binary` | Fileless `memfd:` execution detected (Linux) |
| `PS-BIN-003` | High | `unsigned_binary` | Process executing from a deleted binary on disk |
| `PS-BIN-004` | High | `unsigned_binary` | Binary executing from an ephemeral/writable directory |
| `PS-BIN-005` | Medium / High | `unsigned_binary` | Unsigned or unverified executable (not Authenticode-signed / not package-owned) |
| `PS-BIN-006` | Critical | `hash_drift` | Executable SHA-256 hash changed relative to baseline snapshot |
| `PS-NET-001` | Critical | `policy_violation` | Outbound connection matches policy-denied CIDR or port |
| `PS-NET-002` | Critical | `outbound_connection` | Fileless, deleted, or ephemeral-path binary opened an outbound socket |
| `PS-NET-003` | High | `outbound_connection` | Outbound connection to commonly abused C2/reverse-shell port |
| `PS-NET-004` | High | `outbound_connection` | Dual-use LOLBin or shell opened an external outbound connection |
| `PS-NET-005` | High | `outbound_connection` | Unsigned/untrusted binary opened an external outbound connection |
| `PS-NET-006` | High | `policy_violation` | Outbound connection blocked by `default_deny_outbound` policy |
| `PS-NET-007` | Medium | `outbound_connection` | New unexpected outbound connection not present in baseline |

---

## Exit Codes

| Code | Meaning |
| ---: | :--- |
| `0` | Clean / no alerts |
| `1` | CLI usage or runtime error |
| `2` | Low or medium severity alerts detected |
| `3` | High or critical severity alerts detected |

---

## Policy Configuration

See [`examples/procsnap.policy.json`](examples/procsnap.policy.json) for a full example policy supporting:
- `default_deny_outbound` (`bool`)
- `alert_on_unsigned` (`bool`)
- `trusted_hashes` / `blocked_hashes` (SHA-256 hex strings)
- `trusted_paths` (path prefixes)
- `allowed_outbound_cidrs` / `denied_outbound_cidrs` (IPv4 & IPv6 CIDRs)
- `allowed_outbound_ports` / `denied_outbound_ports` (integers)
- `process_rules` (per-process `allowed_cidrs` and `allowed_ports`)

---

## License

MIT — see [LICENSE](LICENSE).
