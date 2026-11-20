#pragma once
#include "audit.hpp"
#include "config.hpp"

namespace ohb {
// Registra o relatório em log JSONL, syslog (LOG_AUTHPRIV) e, se houver achados,
// executa alert.command (sh -c) com o evento JSON no stdin — ex.: curl (webhook) ou msmtp (e-mail).
void emit_alerts(const Config& cfg, const AuditReport& rep);
}
