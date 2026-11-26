#include "procsnap/cli.hpp"
#include "procsnap/collector.hpp"
#include "procsnap/detector.hpp"
#include "procsnap/diff.hpp"
#include "procsnap/formatter.hpp"
#include "procsnap/policy.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace procsnap {

namespace {

std::atomic<bool> g_stop_requested{false};

void handle_signal(int) {
    g_stop_requested.store(true);
}

void print_usage(std::ostream& os) {
    os << "procsnap 0.1.0 — Cross-platform (Linux & Windows) process, socket, and binary integrity CLI\n\n"
       << "USAGE:\n"
       << "  procsnap <command> [options]\n\n"
       << "COMMANDS:\n"
       << "  snapshot                  Capture running processes, open sockets, SHA-256 hashes, and trust status\n"
       << "  diff <base> [target]      Compare a baseline snapshot against a live host or target snapshot file\n"
       << "  audit                     Evaluate live host against heuristics, policy, and optional baseline\n"
       << "  watch                     Continuously monitor and emit real-time delta alerts\n\n"
       << "COMMON OPTIONS:\n"
       << "  --format <table|json|jsonl>   Output format (default: table)\n"
       << "  --policy <file>               JSON policy file (CIDRs, ports, process rules, trusted/blocked hashes)\n"
       << "  --baseline <file>             Baseline snapshot JSON file for diff/audit/watch\n"
       << "  --min-severity <lvl>          Filter alerts: info|low|medium|high|critical (default: low)\n"
       << "  --out <file>                  Save snapshot JSON to file (snapshot command)\n"
       << "  --interval <sec>              Polling interval in seconds for watch mode (default: 5)\n"
       << "  --count <n>                   Stop watch mode after N iterations (0 = run until Ctrl+C)\n"
       << "  --no-hash                     Skip SHA-256 executable hashing for faster collection\n"
       << "  --no-pkg                      Skip Linux package-manager ownership lookup\n"
       << "  --no-color                    Disable ANSI color output (also respects NO_COLOR)\n"
       << "  -h, --help                    Show this help message\n"
       << "  -v, --version                 Show version\n\n"
       << "EXIT CODES:\n"
       << "  0  Success / no alerts\n"
       << "  1  Runtime or CLI usage error\n"
       << "  2  Low or medium severity alerts detected\n"
       << "  3  High or critical severity alerts detected\n";
}

struct ParsedArgs {
    std::string command;
    std::vector<std::string> positional;
    OutputFormat format = OutputFormat::Table;
    Severity min_severity = Severity::Low;
    std::string out_file;
    std::string policy_file;
    std::string baseline_file;
    int interval_sec = 5;
    int watch_count = 0;
    bool no_hash = false;
    bool no_pkg = false;
    bool no_color = false;
    bool help = false;
    bool version = false;
};

ParsedArgs parse_args(int argc, char** argv) {
    ParsedArgs args;
    if (argc < 2) {
        args.help = true;
        return args;
    }

    int i = 1;
    std::string first = argv[1];
    if (first == "-h" || first == "--help") {
        args.help = true;
        return args;
    }
    if (first == "-v" || first == "--version") {
        args.version = true;
        return args;
    }

    args.command = first;
    ++i;

    auto require_value = [&](const std::string& flag) -> std::string {
        if (i + 1 >= argc) {
            throw std::runtime_error("Missing value for option: " + flag);
        }
        return argv[++i];
    };

    for (; i < argc; ++i) {
        std::string tok = argv[i];
        if (tok == "-h" || tok == "--help") {
            args.help = true;
        } else if (tok == "-v" || tok == "--version") {
            args.version = true;
        } else if (tok == "--no-hash") {
            args.no_hash = true;
        } else if (tok == "--no-pkg") {
            args.no_pkg = true;
        } else if (tok == "--no-color") {
            args.no_color = true;
        } else if (tok == "--out" || tok == "-o") {
            args.out_file = require_value(tok);
        } else if (tok == "--policy" || tok == "-p") {
            args.policy_file = require_value(tok);
        } else if (tok == "--baseline" || tok == "-b") {
            args.baseline_file = require_value(tok);
        } else if (tok == "--format" || tok == "-f") {
            std::string val = require_value(tok);
            auto fmt = output_format_from_string(val);
            if (!fmt) throw std::runtime_error("Invalid format '" + val + "' (expected table, json, or jsonl)");
            args.format = *fmt;
        } else if (tok == "--min-severity") {
            std::string val = require_value(tok);
            auto sev = severity_from_string(val);
            if (!sev) throw std::runtime_error("Invalid severity '" + val + "'");
            args.min_severity = *sev;
        } else if (tok == "--interval") {
            args.interval_sec = std::stoi(require_value(tok));
            if (args.interval_sec < 1) throw std::runtime_error("--interval must be >= 1");
        } else if (tok == "--count") {
            args.watch_count = std::stoi(require_value(tok));
            if (args.watch_count < 0) throw std::runtime_error("--count must be >= 0");
        } else if (!tok.empty() && tok[0] == '-') {
            throw std::runtime_error("Unknown option: " + tok);
        } else {
            args.positional.push_back(tok);
        }
    }

    return args;
}

}  // namespace

int run_cli(int argc, char** argv) {
    try {
        ParsedArgs args = parse_args(argc, argv);
        if (args.help) {
            print_usage(std::cout);
            return 0;
        }
        if (args.version) {
            std::cout << "procsnap 0.1.0\n";
            return 0;
        }

        bool use_color = should_use_color(args.no_color);
        CollectOptions collect_opts{
            .compute_hashes = !args.no_hash,
            .verify_trust = true,
            .resolve_packages = !args.no_pkg,
        };

        std::optional<Policy> policy;
        if (!args.policy_file.empty()) {
            policy = Policy::load_from_file(args.policy_file);
        }

        if (args.command == "snapshot") {
            Snapshot snap = collect_snapshot(collect_opts);
            if (!args.out_file.empty()) {
                snap.save_to_file(args.out_file);
                std::cerr << "Saved snapshot (" << snap.processes.size() << " processes, "
                          << snap.sockets.size() << " sockets) to " << args.out_file << "\n";
            } else {
                std::cout << format_snapshot(snap, args.format, use_color);
            }
            return 0;
        }

        if (args.command == "diff") {
            if (args.positional.empty()) {
                throw std::runtime_error("diff requires at least <baseline.json>");
            }
            Snapshot baseline = Snapshot::load_from_file(args.positional[0]);
            Snapshot target = (args.positional.size() >= 2)
                                  ? Snapshot::load_from_file(args.positional[1])
                                  : collect_snapshot(collect_opts);

            SnapshotDiff diff = diff_snapshots(baseline, target);
            DetectorOptions det_opts{
                .min_severity = args.min_severity,
                .policy = policy,
                .baseline = baseline,
            };
            auto alerts = evaluate_snapshot(target, det_opts);
            std::cout << format_diff(diff, alerts, args.format, use_color);
            return exit_code_for_alerts(alerts);
        }

        if (args.command == "audit") {
            Snapshot current = collect_snapshot(collect_opts);
            std::optional<Snapshot> baseline;
            if (!args.baseline_file.empty()) {
                baseline = Snapshot::load_from_file(args.baseline_file);
            }
            DetectorOptions det_opts{
                .min_severity = args.min_severity,
                .policy = policy,
                .baseline = baseline,
            };
            auto alerts = evaluate_snapshot(current, det_opts);
            std::cout << format_alerts(current, alerts, args.format, use_color);
            return exit_code_for_alerts(alerts);
        }

        if (args.command == "watch") {
            g_stop_requested.store(false);
            std::signal(SIGINT, handle_signal);
            std::signal(SIGTERM, handle_signal);

            Snapshot baseline = args.baseline_file.empty()
                                    ? collect_snapshot(collect_opts)
                                    : Snapshot::load_from_file(args.baseline_file);

            if (args.format == OutputFormat::Table) {
                std::cerr << "Watching host '" << baseline.hostname << "' every "
                          << args.interval_sec << "s (baseline: " << baseline.processes.size()
                          << " procs, " << baseline.sockets.size() << " sockets). Press Ctrl+C to stop.\n";
            }

            int max_exit = 0;
            int iteration = 0;
            while (!g_stop_requested.load()) {
                ++iteration;
                if (args.watch_count > 0 && iteration > args.watch_count) break;

                for (int s = 0; s < args.interval_sec && !g_stop_requested.load(); ++s) {
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                }
                if (g_stop_requested.load()) break;

                Snapshot current = collect_snapshot(collect_opts);
                DetectorOptions det_opts{
                    .min_severity = args.min_severity,
                    .policy = policy,
                    .baseline = baseline,
                };
                auto alerts = evaluate_snapshot(current, det_opts);
                if (!alerts.empty()) {
                    std::cout << format_alerts(current, alerts, args.format, use_color) << std::flush;
                    max_exit = std::max(max_exit, exit_code_for_alerts(alerts));
                }
                baseline = std::move(current);
            }
            return max_exit;
        }

        throw std::runtime_error("Unknown command: " + args.command);
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }
}

}  // namespace procsnap
