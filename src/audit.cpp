#include "audit.hpp"

#include <algorithm>
#include <map>
#include <set>
#include <sstream>

#include "crypto.hpp"
#include "preset.hpp"
#include "routeros_api.hpp"
#include "snapshot.hpp"
#include "util.hpp"

namespace ohb {

const char* severity_name(Severity s) {
    switch (s) {
        case Severity::Info: return "info";
        case Severity::Warning: return "warning";
        default: return "critical";
    }
}

bool AuditReport::clean() const {
    return std::none_of(findings.begin(), findings.end(),
                        [](const Finding& f) { return f.severity != Severity::Info; });
}

int AuditReport::exit_code() const {
    for (auto& f : findings)
        if (f.category == "router-unreachable" || f.category == "error") return 2;
    return clean() ? 0 : 1;
}

json::Value AuditReport::to_json() const {
    json::Array fs;
    for (auto& f : findings) {
        json::Object o{{"severity", severity_name(f.severity)}, {"category", f.category}, {"message", f.message}};
        if (!f.path.empty()) o["path"] = f.path;
        if (!f.before.empty() || !f.after.empty()) {
            o["before"] = f.before;
            o["after"] = f.after;
        }
        fs.push_back(o);
    }
    auto ms = [](double v) { return static_cast<int64_t>(v * 1000); };  // microssegundos
    return json::Object{
        {"event", "ohboyscan.audit"},
        {"ts", started_at},
        {"host", host},
        {"status", clean() ? "OK" : "ALERT"},
        {"preset", json::Object{{"valid", preset_valid}, {"operator", preset_operator}, {"sha256", preset_sha256}}},
        {"timing_us", json::Object{{"total", ms(total_ms)},
                                   {"local_verify", ms(local_verify_ms)},
                                   {"api", ms(api_ms)},
                                   {"scripts_verify", ms(scripts_verify_ms)},
                                   {"diff", ms(diff_ms)}}},
        {"checked", json::Object{{"items", static_cast<int64_t>(items_checked)},
                                 {"scripts", static_cast<int64_t>(scripts_checked)}}},
        {"findings", fs}};
}

std::string AuditReport::to_text() const {
    std::ostringstream o;
    o << "OhBoyScan audit @ " << started_at << "  roteador=" << host << "\n";
    o << "  preset: " << (preset_valid ? "assinatura VÁLIDA" : "assinatura INVÁLIDA/ausente");
    if (!preset_operator.empty()) o << " (operador " << preset_operator << ")";
    o << "\n  verificados: " << items_checked << " itens de configuração, " << scripts_checked << " scripts\n";
    char buf[200];
    std::snprintf(buf, sizeof buf,
                  "  tempos: total %.2f ms | verif. local %.3f ms | API %.2f ms | ECDSA scripts %.3f ms\n", total_ms,
                  local_verify_ms, api_ms, scripts_verify_ms);
    o << buf;
    if (findings.empty()) o << "  resultado: OK — nenhuma divergência\n";
    for (auto& f : findings) {
        o << "  [" << severity_name(f.severity) << "] " << f.category << ": " << f.message;
        if (!f.path.empty()) o << "\n      em " << f.path;
        if (!f.before.empty() || !f.after.empty()) o << "\n      antes: " << f.before << "\n      agora: " << f.after;
        o << "\n";
    }
    o << "  status: " << (clean() ? "OK" : "ALERTA") << "\n";
    return o.str();
}

namespace {

std::string item_label(const json::Object& it, const std::string& idkey) {
    auto get = [&](const char* k) {
        auto p = it.find(k);
        return p != it.end() && p->second.is_string() ? p->second.str() : std::string();
    };
    std::string l = get(idkey.c_str());
    if (idkey != "name") {
        std::string extra;
        for (const char* k : {"chain", "action", "comment"}) {
            auto v = get(k);
            if (!v.empty()) extra += (extra.empty() ? "" : " ") + std::string(k) + "=" + v;
        }
        if (!extra.empty()) l += " (" + extra + ")";
    }
    return l;
}

std::string choose_idkey(const json::Array& a, const json::Array& b) {
    std::set<std::string> na, nb;
    for (auto* arr : {&a, &b}) {
        auto& seen = arr == &a ? na : nb;
        for (auto& it : *arr) {
            auto n = it.get_str("name", "\x01");
            if (n == "\x01" || !seen.insert(n).second) return ".id";
        }
    }
    return "name";
}

std::string summarize(const json::Object& it) {
    std::string s;
    for (auto& [k, v] : it) {
        if (k == ".id" || !v.is_string()) continue;
        if (!s.empty()) s += " ";
        s += k + "=" + v.str();
        if (s.size() > 160) return s.substr(0, 160) + "…";
    }
    return s;
}

}  // namespace

std::vector<Finding> diff_sections(const json::Value& baseline, const json::Object& current) {
    std::vector<Finding> out;
    for (auto& [path, base_v] : baseline.obj()) {
        auto cit = current.find(path);
        if (cit == current.end()) {
            out.push_back({Severity::Critical, "config-drift", path, "seção não pôde ser coletada", "", ""});
            continue;
        }
        const auto& A = base_v.arr();
        const auto& B = cit->second.arr();
        std::string idk = choose_idkey(A, B);
        std::map<std::string, const json::Object*> ma, mb;
        std::vector<std::string> oa, ob;
        for (auto& it : A) {
            auto k = it.get_str(idk);
            ma[k] = &it.obj();
            oa.push_back(k);
        }
        for (auto& it : B) {
            auto k = it.get_str(idk);
            mb[k] = &it.obj();
            ob.push_back(k);
        }
        for (auto& k : oa) {
            auto bi = mb.find(k);
            if (bi == mb.end()) {
                out.push_back({Severity::Critical, "config-drift", path + "[" + item_label(*ma[k], idk) + "]",
                               "item removido", summarize(*ma[k]), "(ausente)"});
                continue;
            }
            const auto& x = *ma[k];
            const auto& y = *bi->second;
            std::set<std::string> fields;
            for (auto& [f, _] : x) fields.insert(f);
            for (auto& [f, _] : y) fields.insert(f);
            for (auto& f : fields) {
                auto val = [&f](const json::Object& m) -> std::string {
                    auto p = m.find(f);
                    if (p == m.end()) return "(ausente)";
                    return p->second.is_string() ? p->second.str() : json::dump(p->second, false);
                };
                std::string vx = val(x), vy = val(y);
                if (vx != vy)
                    out.push_back({Severity::Critical, "config-drift",
                                   path + "[" + item_label(x, idk) + "]." + f, "campo alterado", vx, vy});
            }
        }
        for (auto& k : ob)
            if (!ma.count(k))
                out.push_back({Severity::Critical, "config-drift", path + "[" + item_label(*mb[k], idk) + "]",
                               "item adicionado", "(ausente)", summarize(*mb[k])});
        // Ordem relevante (ex.: regras de firewall são avaliadas sequencialmente)
        std::vector<std::string> ca, cb;
        for (auto& k : oa)
            if (mb.count(k)) ca.push_back(k);
        for (auto& k : ob)
            if (ma.count(k)) cb.push_back(k);
        if (ca != cb) {
            auto join = [](const std::vector<std::string>& v) {
                std::string s;
                for (auto& x : v) s += (s.empty() ? "" : ",") + x;
                return s;
            };
            out.push_back({Severity::Critical, "config-drift", path, "ordem dos itens alterada", join(ca), join(cb)});
        }
    }
    return out;
}

AuditReport run_audit(const Config& cfg) {
    AuditReport rep;
    rep.started_at = now_iso8601();
    rep.host = cfg.host;
    double t0 = monotonic_ms();

    // Etapa 1 — integridade local do baseline, ANTES de qualquer consulta à API.
    auto vp = verify_local_preset(cfg);
    rep.local_verify_ms = vp.verify_ms;
    rep.preset_valid = vp.valid;
    rep.preset_operator = vp.op;
    rep.preset_sha256 = vp.sha256;
    if (!vp.valid) {
        rep.findings.push_back({Severity::Critical, "local-tamper", cfg.preset_path(),
                                "verificação local do baseline falhou: " + vp.reason, "", ""});
        rep.total_ms = monotonic_ms() - t0;
        return rep;
    }
    const auto& doc = vp.doc;
    auto pub = load_operator_public(cfg, vp.op);

    // Etapa 2 — coleta do estado atual com os parâmetros ASSINADOS do baseline.
    std::vector<std::string> sections, ignore;
    for (auto& [k, _] : doc.at("sections").obj()) sections.push_back(k);
    for (auto& f : doc.at("ignore_fields").arr()) ignore.push_back(f.str());
    Config c2 = cfg;
    c2.audit_scripts = doc.at("audit_scripts").boolean();
    c2.scripts_path = doc.get_str("scripts_path", cfg.scripts_path);

    Snapshot snap;
    double ta = monotonic_ms();
    try {
        ros::ApiClient api(cfg);
        api.connect();
        snap = collect_snapshot(api, c2, sections, ignore);
    } catch (const std::exception& e) {
        rep.api_ms = monotonic_ms() - ta;
        rep.findings.push_back({Severity::Critical, "router-unreachable", cfg.host,
                                std::string("falha ao consultar a API do roteador: ") + e.what(), "", ""});
        rep.total_ms = monotonic_ms() - t0;
        return rep;
    }
    rep.api_ms = monotonic_ms() - ta;

    auto base_router = doc.at("meta").find("router");
    if (base_router && base_router->is_object()) {
        for (const char* k : {"identity", "version", "board-name"}) {
            auto a = base_router->get_str(k), b = json::Value(snap.router).get_str(k);
            if (!a.empty() && !b.empty() && a != b)
                rep.findings.push_back({Severity::Info, "info", std::string("/system/") + k,
                                        "metadado do roteador mudou", a, b});
        }
    }

    // Etapa 3 — desvio de configuração.
    double td = monotonic_ms();
    for (auto& [_, v] : snap.sections) rep.items_checked += v.arr().size();
    for (auto& f : diff_sections(doc.at("sections"), snap.sections)) rep.findings.push_back(std::move(f));
    rep.diff_ms = monotonic_ms() - td;

    // Etapa 4 — assinaturas ECDSA dos scripts ativos.
    if (c2.audit_scripts) {
        std::map<std::string, const json::Value*> signed_scripts;
        for (auto& s : doc.at("scripts").arr()) signed_scripts[s.get_str("name")] = &s;
        std::set<std::string> seen;
        double ts = monotonic_ms();
        for (auto& cur : snap.scripts) {
            std::string name = cur.get_str("name");
            std::string source = cur.get_str("source");
            std::string path = c2.scripts_path + "[" + name + "]";
            seen.insert(name);
            ++rep.scripts_checked;
            auto it = signed_scripts.find(name);
            if (it == signed_scripts.end()) {
                rep.findings.push_back({Severity::Critical, "script-unsigned", path,
                                        "script sem assinatura (não presente no baseline)", "",
                                        "sha256=" + crypto::sha256_hex(source)});
                continue;
            }
            const auto& base = *it->second;
            bool ok = false;
            try {
                ok = crypto::verify(pub, source, crypto::b64decode(base.get_str("signature")));
            } catch (const std::exception&) {
            }
            if (!ok)
                rep.findings.push_back({Severity::Critical, "script-tamper", path,
                                        "falha na verificação ECDSA do código do script",
                                        "sha256=" + base.get_str("sha256"), "sha256=" + crypto::sha256_hex(source)});
            // Metadados do script (policy, owner, ...) são comparados como configuração.
            for (auto& [f, bv] : base.obj()) {
                if (f == "signature" || f == "sha256" || !bv.is_string()) continue;
                auto cv = cur.get_str(f, "(ausente)");
                if (cv != bv.str())
                    rep.findings.push_back(
                        {Severity::Critical, "config-drift", path + "." + f, "campo alterado", bv.str(), cv});
            }
        }
        rep.scripts_verify_ms = monotonic_ms() - ts;
        for (auto& [name, _] : signed_scripts)
            if (!seen.count(name))
                rep.findings.push_back({Severity::Critical, "script-removed", c2.scripts_path + "[" + name + "]",
                                        "script assinado foi removido do roteador", "", ""});
    }
    rep.total_ms = monotonic_ms() - t0;
    return rep;
}

}  // namespace ohb
