#include "config.hpp"

#include <cctype>
#include <cstdio>
#include <algorithm>
#include <cstdlib>

#include "util.hpp"

namespace ohb {

std::string Config::keys_dir() const { return join_path(data_dir, "keys"); }
std::string Config::preset_path() const { return join_path(data_dir, "preset.json"); }
std::string Config::preset_sig_path() const { return join_path(data_dir, "preset.json.sig"); }
std::string Config::history_path() const { return join_path(data_dir, "history.jsonl"); }

Config Config::load(const std::string& path, bool must_exist) {
    Config c;
    std::map<std::string, std::string> kv;
    if (file_exists(path)) {
        std::string section;
        int lineno = 0;
        for (auto& raw : split(read_file(path), '\n')) {
            ++lineno;
            std::string line = trim(raw);
            if (line.empty() || line[0] == '#' || line[0] == ';') continue;
            if (line.front() == '[' && line.back() == ']') {
                section = trim(line.substr(1, line.size() - 2));
                continue;
            }
            auto eq = line.find('=');
            if (eq == std::string::npos) throw Error(path + ": linha inválida: " + line);
            std::string k = trim(line.substr(0, eq));
            kv[section.empty() ? k : section + "." + k] = trim(line.substr(eq + 1));
        }
    } else if (must_exist) {
        throw Error("arquivo de configuração não encontrado: " + path);
    }

    auto get = [&](const char* k, auto& out) {
        auto it = kv.find(k);
        if (it == kv.end()) return;
        using T = std::decay_t<decltype(out)>;
        if constexpr (std::is_same_v<T, std::string>) out = it->second;
        else if constexpr (std::is_same_v<T, bool>) out = parse_bool(it->second);
        else if constexpr (std::is_same_v<T, int>) out = std::stoi(it->second);
        else out = split(it->second, ',');
        kv.erase(it);
    };
    get("router.host", c.host);
    get("router.port", c.port);
    get("router.user", c.user);
    get("router.password", c.password);
    std::string pwfile;
    get("router.password_file", pwfile);
    get("router.tls", c.tls);
    get("router.tls_ca_file", c.tls_ca_file);
    get("router.tls_fingerprint", c.tls_fingerprint);
    get("router.timeout_ms", c.timeout_ms);
    get("audit.sections", c.sections);
    get("audit.ignore_fields", c.ignore_fields);
    get("audit.audit_scripts", c.audit_scripts);
    get("audit.scripts_path", c.scripts_path);
    get("paths.data_dir", c.data_dir);
    get("paths.log_file", c.log_file);
    get("paths.lock_file", c.lock_file);
    get("alert.syslog", c.alert_syslog);
    get("alert.command", c.alert_command);
    get("alert.on_ok", c.alert_on_ok);
    get("crypto.deterministic_nonce", c.deterministic_nonce);
    if (!kv.empty()) throw Error(path + ": chave desconhecida: " + kv.begin()->first);

    if (!pwfile.empty()) c.password = trim(read_file(pwfile));
    if (const char* e = std::getenv("OHBOY_ROUTER_PASSWORD")) c.password = e;
    if (const char* e = std::getenv("OHBOY_ROUTER_HOST")) c.host = e;
    if (const char* e = std::getenv("OHBOY_ROUTER_PORT")) c.port = std::atoi(e);
    // Normaliza o fingerprint: minúsculas, sem ':'
    std::string fp;
    for (char ch : c.tls_fingerprint)
        if (ch != ':') fp += static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    c.tls_fingerprint = fp;
    return c;
}

}  // namespace ohb
