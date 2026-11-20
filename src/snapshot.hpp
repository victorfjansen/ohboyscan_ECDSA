#pragma once
// Coleta do estado do roteador via API e normalização canônica.
#include <string>
#include <vector>

#include "config.hpp"
#include "json.hpp"
#include "routeros_api.hpp"

namespace ohb {

struct Snapshot {
    json::Object router;    // host, identity, version, board-name (informativo)
    json::Object sections;  // "/ip/service" -> [ {campo: valor, ...}, ... ] (ordem do roteador)
    json::Array scripts;    // registros de /system/script normalizados (inclui "source")
};

// Normaliza um registro: remove campos voláteis, garante UTF-8 válido.
json::Object normalize_record(const ros::Record& r, const std::vector<std::string>& ignore);
Snapshot collect_snapshot(ros::ApiClient& api, const Config& cfg,
                          const std::vector<std::string>& sections,
                          const std::vector<std::string>& ignore_fields);

}  // namespace ohb
