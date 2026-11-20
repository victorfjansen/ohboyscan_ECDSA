#include "snapshot.hpp"

#include <algorithm>

namespace ohb {

json::Object normalize_record(const ros::Record& r, const std::vector<std::string>& ignore) {
    json::Object o;
    for (auto& [k, v] : r) {
        if (std::find(ignore.begin(), ignore.end(), k) != ignore.end()) continue;
        o[json::to_valid_utf8(k)] = json::to_valid_utf8(v);
    }
    return o;
}

Snapshot collect_snapshot(ros::ApiClient& api, const Config& cfg, const std::vector<std::string>& sections,
                          const std::vector<std::string>& ignore) {
    Snapshot s;
    s.router["host"] = cfg.host;
    try {
        auto id = api.print("/system/identity");
        if (!id.empty()) s.router["identity"] = json::to_valid_utf8(id[0]["name"]);
        auto res = api.print("/system/resource");
        if (!res.empty()) {
            s.router["version"] = json::to_valid_utf8(res[0]["version"]);
            s.router["board-name"] = json::to_valid_utf8(res[0]["board-name"]);
        }
    } catch (const std::exception&) {
        // Informações opcionais: o usuário de auditoria pode não ter acesso.
    }
    for (auto& path : sections) {
        json::Array items;
        for (auto& rec : api.print(path)) items.push_back(normalize_record(rec, ignore));
        s.sections[path] = std::move(items);
    }
    if (cfg.audit_scripts) {
        for (auto& rec : api.print(cfg.scripts_path)) s.scripts.push_back(normalize_record(rec, ignore));
    }
    return s;
}

}  // namespace ohb
