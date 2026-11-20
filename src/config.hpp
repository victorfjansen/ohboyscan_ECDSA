#pragma once
#include <map>
#include <string>
#include <vector>

namespace ohb {

struct Config {
    // [router]
    std::string host = "192.168.88.1";
    int port = 0;  // 0 => 8728 (api) ou 8729 (api-ssl)
    std::string user = "ohboyscan";
    std::string password;
    bool tls = false;
    std::string tls_ca_file;      // verificação por CA
    std::string tls_fingerprint;  // pinning: SHA-256 (hex) do certificado DER
    int timeout_ms = 5000;

    // [audit]
    std::vector<std::string> sections = {"/ip/service", "/ip/firewall/filter", "/user"};
    std::vector<std::string> ignore_fields = {"bytes", "packets", "last-logged-in", "run-count",
                                              "last-started", "invalid"};
    bool audit_scripts = true;
    std::string scripts_path = "/system/script";

    // [paths]
    std::string data_dir = "/var/lib/ohboyscan";
    std::string log_file = "/var/log/ohboyscan/audit.jsonl";
    std::string lock_file = "/run/ohboyscan.lock";

    // [alert]
    bool alert_syslog = true;
    std::string alert_command;  // recebe o evento JSON via stdin
    bool alert_on_ok = false;

    // [crypto]
    bool deterministic_nonce = false;  // RFC 6979 (requer OpenSSL >= 3.2)

    int effective_port() const { return port ? port : (tls ? 8729 : 8728); }
    std::string keys_dir() const;
    std::string preset_path() const;
    std::string preset_sig_path() const;
    std::string history_path() const;

    static Config load(const std::string& path, bool must_exist);
};

}  // namespace ohb
