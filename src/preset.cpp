#include "preset.hpp"

#include <cctype>
#include <cstdio>
#include <algorithm>
#include <sys/stat.h>

#include "history.hpp"
#include "util.hpp"

namespace ohb {

void validate_operator_name(const std::string& op) {
    if (op.empty() || op.size() > 64) throw Error("nome de operador inválido");
    for (char c : op)
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-' || c == '.'))
            throw Error("nome de operador inválido (use [A-Za-z0-9_.-]): " + op);
    if (op[0] == '.') throw Error("nome de operador inválido");
}

std::string pubkey_path(const Config& cfg, const std::string& op) {
    return join_path(cfg.keys_dir(), op + ".pub.pem");
}
std::string privkey_path(const Config& cfg, const std::string& op) {
    return join_path(cfg.keys_dir(), op + ".key.pem");
}

std::string init_keys(const Config& cfg, const std::string& op, const std::string& pass, bool force) {
    validate_operator_name(op);
    make_dirs(cfg.keys_dir(), 0755);
    ::chmod(cfg.data_dir.c_str(), 0755);
    auto priv = privkey_path(cfg, op), pub = pubkey_path(cfg, op);
    if (!force && (file_exists(priv) || file_exists(pub)))
        throw Error("já existem chaves para '" + op + "' (use --force para substituir)");
    auto key = crypto::generate_p256();
    write_file_atomic(priv, crypto::private_pem_encrypted(key, pass), 0600);
    write_file_atomic(pub, crypto::public_pem(key), 0444);
    return crypto::key_id(key);
}

crypto::Key load_operator_private(const Config& cfg, const std::string& op, const std::string& pass) {
    validate_operator_name(op);
    return crypto::load_private_pem(read_file(privkey_path(cfg, op)), pass);
}

crypto::Key load_operator_public(const Config& cfg, const std::string& op) {
    validate_operator_name(op);
    return crypto::load_public_pem(read_file(pubkey_path(cfg, op)));
}

SavedPreset save_preset(const Config& cfg, const Snapshot& snap, const std::string& op, const crypto::Key& key,
                        const std::string& comment) {
    SavedPreset out;
    out.key_id = crypto::key_id(key);

    json::Array scripts;
    for (auto& sv : snap.scripts) {
        json::Object s = sv.obj();
        if (!s.count("source"))
            throw Error("o usuário da API não consegue ler o código (source) do script '" +
                        (s.count("name") ? s["name"].str() : std::string("?")) + "' — verifique as policies do grupo (read,api,sensitive)");
        std::string source = s.count("source") ? s["source"].str() : "";
        auto sig = crypto::sign(key, source, cfg.deterministic_nonce);
        s.erase("source");
        s.erase(".id");
        s["sha256"] = crypto::sha256_hex(source);
        s["signature"] = crypto::b64encode(sig);
        scripts.push_back(std::move(s));
    }

    json::Array ignore;
    for (auto& f : cfg.ignore_fields) ignore.push_back(f);

    json::Object meta{{"operator", op},
                      {"key_id", out.key_id},
                      {"created_at", now_iso8601()},
                      {"comment", comment},
                      {"tool_version", OHBOY_VERSION},
                      {"router", snap.router}};
    json::Object doc{{"format", kPresetFormat},
                     {"meta", meta},
                     {"ignore_fields", ignore},
                     {"scripts_path", cfg.scripts_path},
                     {"audit_scripts", cfg.audit_scripts},
                     {"sections", snap.sections},
                     {"scripts", scripts}};

    std::string bytes = json::dump(doc, true);
    double t0 = monotonic_ms();
    auto sig = crypto::sign(key, bytes, cfg.deterministic_nonce);
    out.sign_ms = monotonic_ms() - t0;
    out.sha256 = crypto::sha256_hex(bytes);

    json::Object sigdoc{{"format", kSigFormat},       {"alg", kAlg},
                        {"operator", op},             {"key_id", out.key_id},
                        {"preset_sha256", out.sha256}, {"signature", crypto::b64encode(sig)}};

    make_dirs(cfg.data_dir, 0755);
    out.path = cfg.preset_path();
    out.sig_path = cfg.preset_sig_path();
    write_file_atomic(out.path, bytes, 0644);
    write_file_atomic(out.sig_path, json::dump(sigdoc, true), 0644);

    out.n_sections = snap.sections.size();
    for (auto& [_, v] : snap.sections) out.n_items += v.arr().size();
    out.n_scripts = scripts.size();

    append_history(cfg, key, op, "preset-save",
                   json::Object{{"preset_sha256", out.sha256}, {"comment", comment},
                                {"router", snap.router}});
    return out;
}

VerifiedPreset verify_local_preset(const Config& cfg) {
    VerifiedPreset v;
    std::string bytes, sigtxt;
    try {
        bytes = read_file(cfg.preset_path());
        sigtxt = read_file(cfg.preset_sig_path());
    } catch (const std::exception& e) {
        v.reason = std::string("preset ausente ou ilegível: ") + e.what();
        return v;
    }
    v.sha256 = crypto::sha256_hex(bytes);
    try {
        json::Value sig = json::parse(sigtxt);
        if (sig.get_str("format") != kSigFormat || sig.get_str("alg") != kAlg)
            throw Error("formato de assinatura desconhecido");
        v.op = sig.get_str("operator");
        v.key_id = sig.get_str("key_id");
        auto pub = load_operator_public(cfg, v.op);  // chave do repositório confiável local
        if (crypto::key_id(pub) != v.key_id) throw Error("key_id não corresponde à chave confiável de " + v.op);
        auto der = crypto::b64decode(sig.get_str("signature"));
        double t0 = monotonic_ms();
        bool ok = crypto::verify(pub, bytes, der);
        v.verify_ms = monotonic_ms() - t0;
        if (!ok) throw Error("assinatura ECDSA do preset.json INVÁLIDA (sha256 atual " + v.sha256 + ")");
        // Somente após a verificação o conteúdo é interpretado.
        v.doc = json::parse(bytes);
        if (v.doc.get_str("format") != kPresetFormat) throw Error("formato de preset desconhecido");
        if (v.doc.at("meta").get_str("operator") != v.op) throw Error("operador do .sig difere do preset");
        v.valid = true;
    } catch (const std::exception& e) {
        v.reason = e.what();
    }
    return v;
}

}  // namespace ohb
