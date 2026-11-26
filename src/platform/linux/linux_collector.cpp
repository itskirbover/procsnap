#if defined(__linux__)

#include "procsnap/collector.hpp"
#include "procsnap/sha256.hpp"

#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace procsnap {

namespace {

bool is_numeric(const std::string& s) {
    if (s.empty()) return false;
    return std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isdigit(c) != 0; });
}

std::string get_hostname() {
    char buf[256] = {};
    if (::gethostname(buf, sizeof(buf) - 1) == 0) {
        buf[sizeof(buf) - 1] = '\0';
        return std::string(buf);
    }
    return "unknown";
}

std::string resolve_username(uint32_t uid, std::unordered_map<uint32_t, std::string>& cache) {
    auto it = cache.find(uid);
    if (it != cache.end()) return it->second;
    struct passwd* pw = ::getpwuid(static_cast<uid_t>(uid));
    std::string name = (pw && pw->pw_name) ? std::string(pw->pw_name) : std::to_string(uid);
    cache.emplace(uid, name);
    return name;
}

std::optional<std::string> read_symlink(const std::string& path) {
    std::vector<char> buf(4096);
    ssize_t len = ::readlink(path.c_str(), buf.data(), buf.size() - 1);
    if (len < 0) return std::nullopt;
    buf[static_cast<size_t>(len)] = '\0';
    return std::string(buf.data(), static_cast<size_t>(len));
}

std::string read_cmdline(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return {};
    std::string raw((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    for (char& c : raw) {
        if (c == '\0') c = ' ';
    }
    while (!raw.empty() && raw.back() == ' ') raw.pop_back();
    return raw;
}

void parse_stat(const std::string& path, std::string& name, uint32_t& ppid) {
    std::ifstream ifs(path);
    if (!ifs) return;
    std::string line;
    std::getline(ifs, line);
    auto open_paren = line.find('(');
    auto close_paren = line.rfind(')');
    if (open_paren == std::string::npos || close_paren == std::string::npos || close_paren <= open_paren) {
        return;
    }
    name = line.substr(open_paren + 1, close_paren - open_paren - 1);
    if (close_paren + 2 < line.size()) {
        std::istringstream iss(line.substr(close_paren + 2));
        std::string state;
        uint32_t p = 0;
        if (iss >> state >> p) {
            ppid = p;
        }
    }
}

uint32_t parse_uid(const std::string& status_path) {
    std::ifstream ifs(status_path);
    if (!ifs) return 0;
    std::string line;
    while (std::getline(ifs, line)) {
        if (line.rfind("Uid:", 0) == 0) {
            std::istringstream iss(line.substr(4));
            uint32_t real_uid = 0;
            if (iss >> real_uid) return real_uid;
        }
    }
    return 0;
}

bool is_suspicious_linux_path(const std::string& path) {
    static const std::vector<std::string> kPrefixes = {
        "/tmp/",
        "/var/tmp/",
        "/dev/shm/",
        "/run/shm/",
        "/run/user/",
    };
    for (const auto& pfx : kPrefixes) {
        if (path.rfind(pfx, 0) == 0) return true;
    }
    if (path.find("/Downloads/") != std::string::npos) return true;
    return false;
}

enum class PkgManager { None, Pacman, Dpkg, Rpm };

PkgManager detect_pkg_manager() {
    if (::access("/usr/bin/pacman", X_OK) == 0) return PkgManager::Pacman;
    if (::access("/usr/bin/dpkg", X_OK) == 0) return PkgManager::Dpkg;
    if (::access("/usr/bin/rpm", X_OK) == 0 || ::access("/bin/rpm", X_OK) == 0) return PkgManager::Rpm;
    return PkgManager::None;
}

// Safely invoke a binary with execvp (no shell expansion) and capture stdout.
std::optional<std::string> run_exec_capture(const std::vector<std::string>& args) {
    if (args.empty()) return std::nullopt;
    int pipefd[2];
    if (::pipe(pipefd) != 0) return std::nullopt;

    pid_t pid = ::fork();
    if (pid < 0) {
        ::close(pipefd[0]);
        ::close(pipefd[1]);
        return std::nullopt;
    }
    if (pid == 0) {
        ::close(pipefd[0]);
        ::dup2(pipefd[1], STDOUT_FILENO);
        int devnull = ::open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            ::dup2(devnull, STDERR_FILENO);
            ::close(devnull);
        }
        ::close(pipefd[1]);

        std::vector<char*> argv;
        argv.reserve(args.size() + 1);
        for (const auto& a : args) {
            argv.push_back(const_cast<char*>(a.c_str()));
        }
        argv.push_back(nullptr);
        ::execvp(argv[0], argv.data());
        ::_exit(127);
    }

    ::close(pipefd[1]);
    std::string out;
    char buf[512];
    ssize_t n = 0;
    while ((n = ::read(pipefd[0], buf, sizeof(buf))) > 0) {
        out.append(buf, static_cast<size_t>(n));
    }
    ::close(pipefd[0]);

    int status = 0;
    if (::waitpid(pid, &status, 0) < 0) return std::nullopt;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return std::nullopt;

    while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) out.pop_back();
    return out;
}

std::optional<std::string> query_package_owner(PkgManager pm, const std::string& exe_path) {
    switch (pm) {
        case PkgManager::Pacman: {
            auto out = run_exec_capture({"pacman", "-Qoq", exe_path});
            if (out && !out->empty()) return "pacman:" + *out;
            break;
        }
        case PkgManager::Dpkg: {
            auto out = run_exec_capture({"dpkg", "-S", exe_path});
            if (out && !out->empty()) {
                auto colon = out->find(':');
                std::string pkg = (colon != std::string::npos) ? out->substr(0, colon) : *out;
                return "dpkg:" + pkg;
            }
            break;
        }
        case PkgManager::Rpm: {
            auto out = run_exec_capture({"rpm", "-qf", "--qf", "%{NAME}", exe_path});
            if (out && !out->empty()) return "rpm:" + *out;
            break;
        }
        case PkgManager::None:
            break;
    }
    return std::nullopt;
}

std::string tcp_state_name(unsigned int st) {
    switch (st) {
        case 0x01: return "ESTABLISHED";
        case 0x02: return "SYN_SENT";
        case 0x03: return "SYN_RECV";
        case 0x04: return "FIN_WAIT1";
        case 0x05: return "FIN_WAIT2";
        case 0x06: return "TIME_WAIT";
        case 0x07: return "CLOSE";
        case 0x08: return "CLOSE_WAIT";
        case 0x09: return "LAST_ACK";
        case 0x0A: return "LISTEN";
        case 0x0B: return "CLOSING";
        default: return "UNKNOWN";
    }
}

bool decode_ipv4(const std::string& hex_ip, std::string& out) {
    if (hex_ip.size() != 8) return false;
    uint32_t addr = 0;
    try {
        addr = static_cast<uint32_t>(std::stoul(hex_ip, nullptr, 16));
    } catch (...) {
        return false;
    }
    struct in_addr in{};
    in.s_addr = addr;  // /proc/net/tcp stores IPv4 in host-endian order matching in_addr on little-endian
    char buf[INET_ADDRSTRLEN] = {};
    if (!::inet_ntop(AF_INET, &in, buf, sizeof(buf))) return false;
    out = buf;
    return true;
}

bool decode_ipv6(const std::string& hex_ip, std::string& out) {
    if (hex_ip.size() != 32) return false;
    struct in6_addr in6{};
    for (int word = 0; word < 4; ++word) {
        uint32_t v = 0;
        try {
            v = static_cast<uint32_t>(std::stoul(hex_ip.substr(static_cast<size_t>(word * 8), 8), nullptr, 16));
        } catch (...) {
            return false;
        }
        std::memcpy(&in6.s6_addr[word * 4], &v, 4);
    }
    char buf[INET6_ADDRSTRLEN] = {};
    if (!::inet_ntop(AF_INET6, &in6, buf, sizeof(buf))) return false;
    out = buf;
    return true;
}

bool is_unspecified_or_loopback(const std::string& addr) {
    return addr == "0.0.0.0" || addr == "::" || addr == "::1" ||
           addr.rfind("127.", 0) == 0 || addr == "::ffff:127.0.0.1";
}

void parse_proc_net_file(const std::string& path,
                         const std::string& protocol,
                         bool is_ipv6,
                         bool is_tcp,
                         const std::unordered_map<uint64_t, uint32_t>& inode_to_pid,
                         const std::unordered_map<uint32_t, std::string>& pid_to_name,
                         std::vector<SocketInfo>& out_sockets) {
    std::ifstream ifs(path);
    if (!ifs) return;

    std::string line;
    std::getline(ifs, line);  // skip header

    while (std::getline(ifs, line)) {
        std::istringstream iss(line);
        std::string sl, local_ep, remote_ep, st_hex, tx_rx, tr_tm, retrnsmt, uid_s, timeout_s;
        uint64_t inode = 0;
        if (!(iss >> sl >> local_ep >> remote_ep >> st_hex >> tx_rx >> tr_tm >> retrnsmt >> uid_s >> timeout_s >> inode)) {
            continue;
        }

        auto l_colon = local_ep.find(':');
        auto r_colon = remote_ep.find(':');
        if (l_colon == std::string::npos || r_colon == std::string::npos) continue;

        SocketInfo sock;
        sock.protocol = protocol;

        std::string l_hex = local_ep.substr(0, l_colon);
        std::string r_hex = remote_ep.substr(0, r_colon);
        if (is_ipv6) {
            if (!decode_ipv6(l_hex, sock.local_addr) || !decode_ipv6(r_hex, sock.remote_addr)) continue;
        } else {
            if (!decode_ipv4(l_hex, sock.local_addr) || !decode_ipv4(r_hex, sock.remote_addr)) continue;
        }

        try {
            sock.local_port = static_cast<uint16_t>(std::stoul(local_ep.substr(l_colon + 1), nullptr, 16));
            sock.remote_port = static_cast<uint16_t>(std::stoul(remote_ep.substr(r_colon + 1), nullptr, 16));
            unsigned int st_val = static_cast<unsigned int>(std::stoul(st_hex, nullptr, 16));
            sock.state = is_tcp ? tcp_state_name(st_val) : (sock.remote_port != 0 ? "CONNECTED" : "UNCONN");
        } catch (...) {
            continue;
        }

        auto it_pid = inode_to_pid.find(inode);
        if (it_pid != inode_to_pid.end()) {
            sock.pid = it_pid->second;
            auto it_name = pid_to_name.find(sock.pid);
            if (it_name != pid_to_name.end()) {
                sock.process_name = it_name->second;
            }
        }

        out_sockets.push_back(std::move(sock));
    }
}

}  // namespace

Snapshot collect_snapshot(const CollectOptions& opts) {
    Snapshot snap;
    snap.timestamp_utc = current_utc_iso8601();
    snap.hostname = get_hostname();
    snap.platform = "linux";

    std::unordered_map<uint32_t, std::string> uid_cache;
    std::unordered_map<std::string, std::string> hash_cache;
    std::unordered_map<std::string, BinaryTrust> trust_cache;
    std::unordered_map<uint64_t, uint32_t> inode_to_pid;
    std::unordered_map<uint32_t, std::string> pid_to_name;

    PkgManager pm = opts.resolve_packages ? detect_pkg_manager() : PkgManager::None;

    DIR* proc_dir = ::opendir("/proc");
    if (proc_dir) {
        struct dirent* ent = nullptr;
        while ((ent = ::readdir(proc_dir)) != nullptr) {
            std::string dname(ent->d_name);
            if (!is_numeric(dname)) continue;

            uint32_t pid = static_cast<uint32_t>(std::stoul(dname));
            std::string base = "/proc/" + dname;

            ProcessInfo proc;
            proc.pid = pid;
            parse_stat(base + "/stat", proc.name, proc.ppid);
            proc.uid = parse_uid(base + "/status");
            proc.user = resolve_username(proc.uid, uid_cache);
            proc.cmdline = read_cmdline(base + "/cmdline");

            auto exe_link = read_symlink(base + "/exe");
            if (exe_link) {
                std::string raw_exe = *exe_link;
                if (raw_exe.rfind("memfd:", 0) == 0 || raw_exe.rfind("/memfd:", 0) == 0) {
                    proc.trust.is_memfd = true;
                }
                const std::string deleted_suffix = " (deleted)";
                if (raw_exe.size() > deleted_suffix.size() &&
                    raw_exe.compare(raw_exe.size() - deleted_suffix.size(), deleted_suffix.size(), deleted_suffix) == 0) {
                    proc.trust.is_deleted = true;
                    raw_exe.erase(raw_exe.size() - deleted_suffix.size());
                }
                proc.exe_path = raw_exe;
                proc.trust.suspicious_path = is_suspicious_linux_path(proc.exe_path);

                if (opts.compute_hashes && !proc.exe_path.empty() && !proc.trust.is_memfd) {
                    std::string hash_target = proc.trust.is_deleted ? (base + "/exe") : proc.exe_path;
                    auto it_h = hash_cache.find(hash_target);
                    if (it_h != hash_cache.end()) {
                        proc.sha256 = it_h->second;
                    } else {
                        auto h = Sha256::hash_file(hash_target);
                        if (h) {
                            proc.sha256 = *h;
                            hash_cache.emplace(hash_target, *h);
                        }
                    }
                }

                if (opts.verify_trust) {
                    if (proc.trust.is_memfd) {
                        proc.trust.status = TrustStatus::Suspicious;
                        proc.trust.reason = "fileless memfd execution";
                    } else if (proc.trust.is_deleted) {
                        proc.trust.status = TrustStatus::Suspicious;
                        proc.trust.reason = "executable deleted from disk";
                    } else if (proc.trust.suspicious_path) {
                        proc.trust.status = TrustStatus::Suspicious;
                        proc.trust.reason = "executable located in ephemeral/writable directory";
                    } else {
                        auto it_t = trust_cache.find(proc.exe_path);
                        if (it_t != trust_cache.end()) {
                            proc.trust = it_t->second;
                        } else {
                            BinaryTrust bt;
                            auto pkg = query_package_owner(pm, proc.exe_path);
                            if (pkg) {
                                bt.status = TrustStatus::Trusted;
                                bt.signer = *pkg;
                                bt.reason = "owned by system package";
                            } else {
                                bt.status = TrustStatus::Unsigned;
                                bt.reason = (pm == PkgManager::None)
                                                ? "no supported package manager to verify ownership"
                                                : "not owned by any system package";
                            }
                            trust_cache.emplace(proc.exe_path, bt);
                            proc.trust = bt;
                        }
                    }
                }
            } else {
                proc.trust.status = TrustStatus::Unknown;
                proc.trust.reason = "unreadable /proc/<pid>/exe (kernel thread or insufficient privileges)";
            }

            // Collect socket inodes for this PID
            std::string fd_dir_path = base + "/fd";
            DIR* fd_dir = ::opendir(fd_dir_path.c_str());
            if (fd_dir) {
                struct dirent* fd_ent = nullptr;
                while ((fd_ent = ::readdir(fd_dir)) != nullptr) {
                    if (fd_ent->d_name[0] == '.') continue;
                    auto target = read_symlink(fd_dir_path + "/" + fd_ent->d_name);
                    if (target && target->rfind("socket:[", 0) == 0 && target->back() == ']') {
                        std::string inode_str = target->substr(8, target->size() - 9);
                        if (is_numeric(inode_str)) {
                            inode_to_pid[std::stoull(inode_str)] = pid;
                        }
                    }
                }
                ::closedir(fd_dir);
            }

            pid_to_name[pid] = proc.name;
            snap.processes.push_back(std::move(proc));
        }
        ::closedir(proc_dir);
    }

    std::sort(snap.processes.begin(), snap.processes.end(),
              [](const ProcessInfo& a, const ProcessInfo& b) { return a.pid < b.pid; });

    parse_proc_net_file("/proc/net/tcp", "tcp", false, true, inode_to_pid, pid_to_name, snap.sockets);
    parse_proc_net_file("/proc/net/tcp6", "tcp6", true, true, inode_to_pid, pid_to_name, snap.sockets);
    parse_proc_net_file("/proc/net/udp", "udp", false, false, inode_to_pid, pid_to_name, snap.sockets);
    parse_proc_net_file("/proc/net/udp6", "udp6", true, false, inode_to_pid, pid_to_name, snap.sockets);

    // Collect local listening TCP ports to distinguish outbound client connections from accepted server connections
    std::set<uint16_t> listening_ports;
    for (const auto& s : snap.sockets) {
        if (s.state == "LISTEN") {
            listening_ports.insert(s.local_port);
        }
    }

    for (auto& s : snap.sockets) {
        if (s.remote_port == 0 || is_unspecified_or_loopback(s.remote_addr)) {
            s.is_outbound = false;
            continue;
        }
        if (s.protocol == "tcp" || s.protocol == "tcp6") {
            if ((s.state == "ESTABLISHED" || s.state == "SYN_SENT") && !listening_ports.contains(s.local_port)) {
                s.is_outbound = true;
            }
        } else {
            // Connected UDP socket to a non-loopback remote address
            s.is_outbound = true;
        }
    }

    return snap;
}

}  // namespace procsnap

#endif  // __linux__
