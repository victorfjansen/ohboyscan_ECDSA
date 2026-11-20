#include "history.hpp"

#include <iostream>

#include "preset.hpp"
#include "util.hpp"

namespace ohb {

static std::string last_line_hash(const std::string& path) {
    if (!file_exists(path)) return std::string(64, '0');
    auto lines = split(read_file(path), '\n');
    if (lines.empty()) return std::string(64, '0');
    return crypto::sha256_hex(lines.back());
}

void append_history(const Config& cfg, const crypto::Key& key, const std::string& op, const std::string& action,
                    json::Object entry) {
    auto path = cfg.history_path();
    entry["ts"] = now_iso8601();
    entry["operator"] = op;
    entry["key_id"] = crypto::key_id(key);
    entry["action"] = action;
    entry["prev"] = last_line_hash(path);
    std::string body = json::dump(entry, false);
    entry["sig"] = crypto::b64encode(crypto::sign(key, body, cfg.deterministic_nonce));
    append_file(path, json::dump(entry, false) + "\n", 0644);
}

int print_history(const Config& cfg, bool verify) {
    auto path = cfg.history_path();
    if (!file_exists(path)) {
        std::cout << "(histórico vazio)\n";
        return 0;
    }
    int bad = 0;
    std::string prev(64, '0');
    for (auto& line : split(read_file(path), '\n')) {
        std::string status = "-";
        json::Value e;
        try {
            e = json::parse(line);
            if (verify) {
                json::Object body = e.obj();
                auto sig = crypto::b64decode(body.at("sig").str());
                body.erase("sig");
                auto pub = load_operator_public(cfg, body.at("operator").str());
                bool ok = crypto::verify(pub, json::dump(body, false), sig) && body.at("prev").str() == prev;
                status = ok ? "OK " : "INVÁLIDA";
                if (!ok) ++bad;
            }
        } catch (const std::exception& ex) {
            status = std::string("ERRO(") + ex.what() + ")";
            ++bad;
        }
        prev = crypto::sha256_hex(line);
        if (e.is_object())
            std::cout << "[" << status << "] " << e.get_str("ts") << "  " << e.get_str("operator") << "  "
                      << e.get_str("action") << "  sha256=" << e.get_str("preset_sha256").substr(0, 16)
                      << "  " << e.get_str("comment") << "\n";
        else
            std::cout << "[" << status << "] " << line.substr(0, 80) << "\n";
    }
    return bad;
}

}  // namespace ohb
