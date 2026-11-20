#pragma once
// preset.json  : baseline canônica assinada (bytes exatos do arquivo são assinados)
// preset.json.sig : {"alg","operator","key_id","signature"(DER base64),"preset_sha256"}
// Cada script de automação tem sua própria assinatura ECDSA sobre o "source" (UTF-8),
// armazenada em preset.json -> scripts[i].signature.
// Ambos podem ser verificados externamente com:
//   openssl dgst -sha256 -verify keys/<op>.pub.pem -signature sig.der preset.json
#include <string>

#include "config.hpp"
#include "crypto.hpp"
#include "json.hpp"
#include "snapshot.hpp"

namespace ohb {

inline constexpr const char* kPresetFormat = "ohboyscan-preset/1";
inline constexpr const char* kSigFormat = "ohboyscan-sig/1";
inline constexpr const char* kAlg = "ECDSA-P256-SHA256";

std::string pubkey_path(const Config& cfg, const std::string& op);
std::string privkey_path(const Config& cfg, const std::string& op);
void validate_operator_name(const std::string& op);

// Gera par de chaves para o operador (init).
std::string init_keys(const Config& cfg, const std::string& op, const std::string& passphrase, bool force);
crypto::Key load_operator_private(const Config& cfg, const std::string& op, const std::string& passphrase);
crypto::Key load_operator_public(const Config& cfg, const std::string& op);

struct SavedPreset {
    std::string path, sig_path, sha256, key_id;
    size_t n_sections = 0, n_items = 0, n_scripts = 0;
    double sign_ms = 0;
};
SavedPreset save_preset(const Config& cfg, const Snapshot& snap, const std::string& op, const crypto::Key& key,
                        const std::string& comment);

struct VerifiedPreset {
    bool valid = false;
    std::string reason;  // motivo da falha
    std::string op, key_id, sha256;
    json::Value doc;     // só preenchido quando valid
    double verify_ms = 0;
};
// Verificação local (etapa 1 da auditoria): nenhum byte não autenticado é interpretado
// além do .sig (que só seleciona a chave pública confiável).
VerifiedPreset verify_local_preset(const Config& cfg);

}  // namespace ohb
