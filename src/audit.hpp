#pragma once
#include <string>
#include <vector>

#include "config.hpp"
#include "json.hpp"

namespace ohb {

enum class Severity { Info, Warning, Critical };
const char* severity_name(Severity s);

struct Finding {
    Severity severity;
    std::string category;  // local-tamper | config-drift | script-tamper | script-unsigned | script-removed | router-unreachable | info
    std::string path;      // ex.: /ip/service[telnet].disabled
    std::string message;
    std::string before, after;
};

struct AuditReport {
    std::string started_at;
    std::string host;
    std::string preset_operator, preset_sha256;
    bool preset_valid = false;
    double total_ms = 0, local_verify_ms = 0, api_ms = 0, scripts_verify_ms = 0, diff_ms = 0;
    size_t scripts_checked = 0, items_checked = 0;
    std::vector<Finding> findings;

    bool clean() const;
    int exit_code() const;  // 0 íntegro, 1 divergência/adulteração, 2 erro operacional
    json::Value to_json() const;
    std::string to_text() const;
};

// Diff de seções normalizadas (exposto para testes).
std::vector<Finding> diff_sections(const json::Value& baseline, const json::Object& current);

AuditReport run_audit(const Config& cfg);

}  // namespace ohb
