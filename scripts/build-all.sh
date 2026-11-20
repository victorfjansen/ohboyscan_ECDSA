#!/usr/bin/env bash
# Compila e valida o OhBoyScan para cada alvo:
#   native  -> x86_64 (notebook Zorin OS)
#   aarch64 -> Raspberry Pi 3B+ 64 bits (Cortex-A53, Yocto raspberrypi3-64)
#   armhf   -> Raspberry Pi 3B+ 32 bits (Yocto raspberrypi3)
# Para cada alvo: build Release, testes unitários (ctest; ARM via qemu-user) e os
# 4 cenários funcionais contra o mock da API (ARM via qemu-user).
#
# Uso: scripts/build-all.sh [native] [aarch64] [armhf] [--tls] [--no-scenarios]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
TARGETS=(); SCEN_ARGS=(); SCEN=1
for a in "$@"; do
  case "$a" in
    --tls) SCEN_ARGS+=(--tls) ;;
    --no-scenarios) SCEN=0 ;;
    *) TARGETS+=("$a") ;;
  esac
done
(( ${#TARGETS[@]} )) || TARGETS=(native aarch64 armhf)

# Toolchain sem root (scripts/bootstrap-toolchain.sh), se existir e não houver outra configurada.
if [[ -z "${OHBOY_TOOLCHAIN_ROOT:-}" && -f "$ROOT/.toolchain/env.sh" ]]; then
  # shellcheck disable=SC1091
  . "$ROOT/.toolchain/env.sh"
fi
TCR="${OHBOY_TOOLCHAIN_ROOT:-}"
SUMMARY=()

for t in "${TARGETS[@]}"; do
  echo; echo "################ $t ################"
  B="build-$t"
  case "$t" in
    native)
      ARGS=()
      if [[ ! -f /usr/include/openssl/evp.h && -n "$TCR" ]]; then
        ARGS+=(-DOPENSSL_INCLUDE_DIR="$TCR/usr/include"
               -DOPENSSL_CRYPTO_LIBRARY="$TCR/usr/lib/x86_64-linux-gnu/libcrypto.so"
               -DOPENSSL_SSL_LIBRARY="$TCR/usr/lib/x86_64-linux-gnu/libssl.so"
               -DCMAKE_CXX_FLAGS="-isystem $TCR/usr/include/x86_64-linux-gnu")
      fi
      RUNNER="" ;;
    aarch64)
      ARGS=(-DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/aarch64-linux-gnu.cmake)
      R="${TCR:-}"; Q="$(command -v qemu-aarch64-static || command -v qemu-aarch64)"
      RUNNER="env LD_LIBRARY_PATH=${R}/usr/lib/aarch64-linux-gnu $Q -L ${R:-/}/usr/aarch64-linux-gnu" ;;
    armhf)
      ARGS=(-DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/arm-linux-gnueabihf.cmake)
      R="${TCR:-}"; Q="$(command -v qemu-arm-static || command -v qemu-arm)"
      RUNNER="env LD_LIBRARY_PATH=${R}/usr/lib/arm-linux-gnueabihf $Q -L ${R:-/}/usr/arm-linux-gnueabihf" ;;
    *) echo "alvo desconhecido: $t"; exit 1 ;;
  esac
  cmake -S . -B "$B" -DCMAKE_BUILD_TYPE=Release "${ARGS[@]}" >/dev/null
  cmake --build "$B" -j"$(nproc)" 2>&1 | grep -E 'error|warning:|Built target' || true
  [[ -x "$B/ohboyscan" ]] || { echo "build falhou para $t"; exit 1; }
  file "$B/ohboyscan" | sed "s|$ROOT/||"
  ( cd "$B" && ctest --output-on-failure ) | tail -3
  $RUNNER "$B/ohboyscan" version
  if (( SCEN )); then
    RUNNER="$RUNNER" tests/scenarios.sh "$B/ohboyscan" "${SCEN_ARGS[@]}" | tail -9
  fi
  SUMMARY+=("$t: OK  ($(file -b "$B/ohboyscan" | cut -d, -f1-2), $(du -h "$B/ohboyscan" | cut -f1))")
done
echo; echo "================ resumo ================"
printf '  %s\n' "${SUMMARY[@]}"
