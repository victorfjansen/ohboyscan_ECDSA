#pragma once
// Trilha de auditoria append-only (history.jsonl): cada entrada é assinada pelo
// operador que a produziu e encadeada por hash (prev = SHA-256 da linha anterior),
// materializando o não-repúdio: só quem conhece a passphrase consegue assinar.
#include <string>

#include "config.hpp"
#include "crypto.hpp"
#include "json.hpp"

namespace ohb {

void append_history(const Config& cfg, const crypto::Key& key, const std::string& op, const std::string& action,
                    json::Object extra);
// Imprime e verifica a trilha; retorna número de entradas inválidas.
int print_history(const Config& cfg, bool verify);

}  // namespace ohb
