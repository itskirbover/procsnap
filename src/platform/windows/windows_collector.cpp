#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <tlhelp32.h>
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>

#include "procsnap/collector.hpp"
#include "procsnap/sha256.hpp"

#include <algorithm>
#include <cctype>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

namespace procsnap {

namespace {

std::string wide_to_utf8(const std::wstring& w) {
    if (w.empty()) return {};
    int needed = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};
    std::string out(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), out.data(), needed, nullptr, nullptr);
    return out;
}

std::wstring utf8_to_wide(const std::string& s) {
    if (s.empty()) return {};
    int needed = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (needed <= 0) return {};
    std::wstring out(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), needed);
    return out;
}

std::string to_lower_ascii(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string get_hostname() {
    wchar_t buf[256] = {};
    DWORD sz = static_cast<DWORD>(std::size(buf));
    if (GetComputerNameExW(ComputerNameDnsHostname, buf, &sz)) {
        return wide_to_utf8(std::wstring(buf, sz));
    }
    return "unknown";
}

bool is_suspicious_windows_path(const std::string& path) {
    std::string lower = to_lower_ascii(path);
    static const std::vector<std::string> kMarkers = {
        "\\temp\\",
        "\\appdata\\local\\temp\\",
        "\\users\\public\\",
        "\\programdata\\",
        "\\downloads\\",
        "\\windows\\tasks\\",
    };
    for (const auto& m : kMarkers) {
        if (lower.find(m) != std::string::npos) return true;
    }
    return false;
}

std::string query_process_user(HANDLE hProcess) {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) return {};

    DWORD needed = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &needed);
    if (needed == 0) {
        CloseHandle(hToken);
        return {};
    }

    std::vector<BYTE> buf(needed);
    std::string result;
    if (GetTokenInformation(hToken, TokenUser, buf.data(), needed, &needed)) {
        auto* tu = reinterpret_cast<TOKEN_USER*>(buf.data());
        wchar_t name[256] = {};
        wchar_t domain[256] = {};
        DWORD name_len = static_cast<DWORD>(std::size(name));
        DWORD domain_len = static_cast<DWORD>(std::size(domain));
        SID_NAME_USE use{};
        if (LookupAccountSidW(nullptr, tu->User.Sid, name, &name_len, domain, &domain_len, &use)) {
            std::wstring combined;
            if (domain_len > 0) {
                combined = std::wstring(domain, domain_len) + L"\\" + std::wstring(name, name_len);
            } else {
                combined = std::wstring(name, name_len);
            }
            result = wide_to_utf8(combined);
        }
    }
    CloseHandle(hToken);
    return result;
}

std::string extract_authenticode_signer(const std::wstring& wpath) {
    DWORD encoding = 0;
    DWORD content_type = 0;
    DWORD format_type = 0;
    HCERTSTORE store = nullptr;
    HCRYPTMSG msg = nullptr;

    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, wpath.c_str(),
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY, 0, &encoding, &content_type,
                          &format_type, &store, &msg, nullptr)) {
        return {};
    }

    std::string signer;
    DWORD signer_info_size = 0;
    if (CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signer_info_size) && signer_info_size > 0) {
        std::vector<BYTE> buf(signer_info_size);
        if (CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, buf.data(), &signer_info_size)) {
            auto* si = reinterpret_cast<CMSG_SIGNER_INFO*>(buf.data());
            CERT_INFO ci{};
            ci.Issuer = si->Issuer;
            ci.SerialNumber = si->SerialNumber;
            PCCERT_CONTEXT cert = CertFindCertificateInStore(
                store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_CERT, &ci, nullptr);
            if (cert) {
                DWORD chars = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
                if (chars > 1) {
                    std::wstring name(chars - 1, L'\0');
                    CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, name.data(), chars);
                    signer = wide_to_utf8(name);
                }
                CertFreeCertificateContext(cert);
            }
        }
    }

    if (store) CertCloseStore(store, 0);
    if (msg) CryptMsgClose(msg);
    return signer;
}

BinaryTrust verify_windows_trust(const std::string& exe_path) {
    BinaryTrust trust;
    if (exe_path.empty()) {
        trust.status = TrustStatus::Unknown;
        trust.reason = "unreadable executable path (system process or insufficient privileges)";
        return trust;
    }

    trust.suspicious_path = is_suspicious_windows_path(exe_path);
    std::wstring wpath = utf8_to_wide(exe_path);

    WINTRUST_FILE_INFO file_info{};
    file_info.cbStruct = sizeof(WINTRUST_FILE_INFO);
    file_info.pcwszFilePath = wpath.c_str();

    GUID policy_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA wt_data{};
    wt_data.cbStruct = sizeof(WINTRUST_DATA);
    wt_data.dwUIChoice = WTD_UI_NONE;
    wt_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    wt_data.dwUnionChoice = WTD_CHOICE_FILE;
    wt_data.pFile = &file_info;
    wt_data.dwStateAction = WTD_STATEACTION_VERIFY;
    wt_data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    LONG status = WinVerifyTrust(nullptr, &policy_guid, &wt_data);

    wt_data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policy_guid, &wt_data);

    if (status == ERROR_SUCCESS) {
        trust.signer = extract_authenticode_signer(wpath);
        if (trust.suspicious_path) {
            trust.status = TrustStatus::Suspicious;
            trust.reason = "signed binary executing from ephemeral/temp directory";
        } else {
            trust.status = TrustStatus::Trusted;
            trust.reason = "valid Authenticode signature";
        }
    } else if (status == TRUST_E_NOSIGNATURE || status == TRUST_E_SUBJECT_FORM_UNKNOWN) {
        trust.status = trust.suspicious_path ? TrustStatus::Suspicious : TrustStatus::Unsigned;
        trust.reason = trust.suspicious_path
                           ? "unsigned binary executing from ephemeral/temp directory"
                           : "binary is not Authenticode signed";
    } else {
        trust.status = TrustStatus::Suspicious;
        trust.reason = "invalid or untrusted Authenticode signature";
    }

    return trust;
}

std::string tcp_state_name(DWORD state) {
    switch (state) {
        case MIB_TCP_STATE_CLOSED: return "CLOSED";
        case MIB_TCP_STATE_LISTEN: return "LISTEN";
        case MIB_TCP_STATE_SYN_SENT: return "SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD: return "SYN_RECV";
        case MIB_TCP_STATE_ESTAB: return "ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1: return "FIN_WAIT1";
        case MIB_TCP_STATE_FIN_WAIT2: return "FIN_WAIT2";
        case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING: return "CLOSING";
        case MIB_TCP_STATE_LAST_ACK: return "LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT: return "TIME_WAIT";
        case MIB_TCP_STATE_DELETE_TCB: return "DELETE_TCB";
        default: return "UNKNOWN";
    }
}

std::string format_ipv4(DWORD addr) {
    struct in_addr in{};
    in.S_un.S_addr = addr;
    char buf[INET_ADDRSTRLEN] = {};
    if (InetNtopA(AF_INET, &in, buf, sizeof(buf))) return std::string(buf);
    return "0.0.0.0";
}

std::string format_ipv6(const UCHAR addr[16]) {
    struct in6_addr in6{};
    memcpy(in6.u.Byte, addr, 16);
    char buf[INET6_ADDRSTRLEN] = {};
    if (InetNtopA(AF_INET6, &in6, buf, sizeof(buf))) return std::string(buf);
    return "::";
}

bool is_unspecified_or_loopback(const std::string& addr) {
    return addr == "0.0.0.0" || addr == "::" || addr == "::1" ||
           addr.rfind("127.", 0) == 0 || addr == "::ffff:127.0.0.1";
}

void collect_tcp4_sockets(const std::unordered_map<uint32_t, std::string>& pid_to_name,
                          std::vector<SocketInfo>& out) {
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0) return;

    std::vector<BYTE> buf(size);
    if (GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
        return;
    }

    auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        SocketInfo s;
        s.protocol = "tcp";
        s.local_addr = format_ipv4(row.dwLocalAddr);
        s.local_port = ntohs(static_cast<u_short>(row.dwLocalPort));
        s.remote_addr = format_ipv4(row.dwRemoteAddr);
        s.remote_port = ntohs(static_cast<u_short>(row.dwRemotePort));
        s.state = tcp_state_name(row.dwState);
        s.pid = row.dwOwningPid;
        auto it = pid_to_name.find(s.pid);
        if (it != pid_to_name.end()) s.process_name = it->second;
        out.push_back(std::move(s));
    }
}

void collect_tcp6_sockets(const std::unordered_map<uint32_t, std::string>& pid_to_name,
                          std::vector<SocketInfo>& out) {
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0) return;

    std::vector<BYTE> buf(size);
    if (GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
        return;
    }

    auto* table = reinterpret_cast<MIB_TCP6TABLE_OWNER_PID*>(buf.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        SocketInfo s;
        s.protocol = "tcp6";
        s.local_addr = format_ipv6(row.ucLocalAddr);
        s.local_port = ntohs(static_cast<u_short>(row.dwLocalPort));
        s.remote_addr = format_ipv6(row.ucRemoteAddr);
        s.remote_port = ntohs(static_cast<u_short>(row.dwRemotePort));
        s.state = tcp_state_name(row.dwState);
        s.pid = row.dwOwningPid;
        auto it = pid_to_name.find(s.pid);
        if (it != pid_to_name.end()) s.process_name = it->second;
        out.push_back(std::move(s));
    }
}

void collect_udp4_sockets(const std::unordered_map<uint32_t, std::string>& pid_to_name,
                          std::vector<SocketInfo>& out) {
    DWORD size = 0;
    GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (size == 0) return;

    std::vector<BYTE> buf(size);
    if (GetExtendedUdpTable(buf.data(), &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) != NO_ERROR) {
        return;
    }

    auto* table = reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(buf.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        SocketInfo s;
        s.protocol = "udp";
        s.local_addr = format_ipv4(row.dwLocalAddr);
        s.local_port = ntohs(static_cast<u_short>(row.dwLocalPort));
        s.remote_addr = "0.0.0.0";
        s.remote_port = 0;
        s.state = "UNCONN";
        s.pid = row.dwOwningPid;
        auto it = pid_to_name.find(s.pid);
        if (it != pid_to_name.end()) s.process_name = it->second;
        out.push_back(std::move(s));
    }
}

void collect_udp6_sockets(const std::unordered_map<uint32_t, std::string>& pid_to_name,
                          std::vector<SocketInfo>& out) {
    DWORD size = 0;
    GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
    if (size == 0) return;

    std::vector<BYTE> buf(size);
    if (GetExtendedUdpTable(buf.data(), &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0) != NO_ERROR) {
        return;
    }

    auto* table = reinterpret_cast<MIB_UDP6TABLE_OWNER_PID*>(buf.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        SocketInfo s;
        s.protocol = "udp6";
        s.local_addr = format_ipv6(row.ucLocalAddr);
        s.local_port = ntohs(static_cast<u_short>(row.dwLocalPort));
        s.remote_addr = "::";
        s.remote_port = 0;
        s.state = "UNCONN";
        s.pid = row.dwOwningPid;
        auto it = pid_to_name.find(s.pid);
        if (it != pid_to_name.end()) s.process_name = it->second;
        out.push_back(std::move(s));
    }
}

}  // namespace

Snapshot collect_snapshot(const CollectOptions& opts) {
    Snapshot snap;
    snap.timestamp_utc = current_utc_iso8601();
    snap.hostname = get_hostname();
    snap.platform = "windows";

    std::unordered_map<std::string, std::string> hash_cache;
    std::unordered_map<std::string, BinaryTrust> trust_cache;
    std::unordered_map<uint32_t, std::string> pid_to_name;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                ProcessInfo proc;
                proc.pid = pe.th32ProcessID;
                proc.ppid = pe.th32ParentProcessID;
                proc.name = wide_to_utf8(pe.szExeFile);

                HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, proc.pid);
                if (hProc) {
                    wchar_t path_buf[32768];
                    DWORD path_len = static_cast<DWORD>(std::size(path_buf));
                    if (QueryFullProcessImageNameW(hProc, 0, path_buf, &path_len)) {
                        proc.exe_path = wide_to_utf8(std::wstring(path_buf, path_len));
                    }
                    proc.user = query_process_user(hProc);
                    CloseHandle(hProc);
                }

                if (opts.compute_hashes && !proc.exe_path.empty()) {
                    auto it_h = hash_cache.find(proc.exe_path);
                    if (it_h != hash_cache.end()) {
                        proc.sha256 = it_h->second;
                    } else {
                        auto h = Sha256::hash_file(proc.exe_path);
                        if (h) {
                            proc.sha256 = *h;
                            hash_cache.emplace(proc.exe_path, *h);
                        }
                    }
                }

                if (opts.verify_trust) {
                    auto it_t = trust_cache.find(proc.exe_path);
                    if (it_t != trust_cache.end()) {
                        proc.trust = it_t->second;
                    } else {
                        BinaryTrust bt = verify_windows_trust(proc.exe_path);
                        trust_cache.emplace(proc.exe_path, bt);
                        proc.trust = bt;
                    }
                }

                pid_to_name[proc.pid] = proc.name;
                snap.processes.push_back(std::move(proc));
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }

    std::sort(snap.processes.begin(), snap.processes.end(),
              [](const ProcessInfo& a, const ProcessInfo& b) { return a.pid < b.pid; });

    collect_tcp4_sockets(pid_to_name, snap.sockets);
    collect_tcp6_sockets(pid_to_name, snap.sockets);
    collect_udp4_sockets(pid_to_name, snap.sockets);
    collect_udp6_sockets(pid_to_name, snap.sockets);

    std::set<uint16_t> listening_ports;
    for (const auto& s : snap.sockets) {
        if (s.state == "LISTEN") listening_ports.insert(s.local_port);
    }

    for (auto& s : snap.sockets) {
        if (s.remote_port == 0 || is_unspecified_or_loopback(s.remote_addr)) {
            s.is_outbound = false;
            continue;
        }
        if ((s.protocol == "tcp" || s.protocol == "tcp6") &&
            (s.state == "ESTABLISHED" || s.state == "SYN_SENT") &&
            !listening_ports.contains(s.local_port)) {
            s.is_outbound = true;
        }
    }

    return snap;
}

}  // namespace procsnap

#endif  // _WIN32
