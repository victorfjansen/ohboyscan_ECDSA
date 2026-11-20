#!/usr/bin/env bash
# Prepara toolchains de compilação cruzada SEM ROOT, extraindo os pacotes .deb oficiais
# do Ubuntu/Debian em ./.toolchain (útil quando não há sudo/docker).
# Com sudo, prefira: sudo apt install g++-aarch64-linux-gnu qemu-user-static ... (ver README).
#
# Uso: scripts/bootstrap-toolchain.sh [arm64] [armhf]      (padrão: arm64 armhf)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TC="$ROOT/.toolchain"
DEBS="$TC/debs"
ARCHS=("${@:-arm64 armhf}")
read -r -a ARCHS <<< "${ARCHS[*]}"
mkdir -p "$DEBS"
cd "$DEBS"

. /etc/os-release
CODENAME="${UBUNTU_CODENAME:-${VERSION_CODENAME}}"
PORTS="http://ports.ubuntu.com/ubuntu-ports"
[[ "${ID_LIKE:-}${ID}" == *ubuntu* ]] || PORTS="http://deb.debian.org/debian"

deps_of() {  # dependências recursivas que pertencem ao toolchain cruzado
  apt-cache depends --recurse --no-recommends --no-suggests --no-conflicts --no-breaks \
    --no-replaces --no-enhances --no-pre-depends "$1" 2>/dev/null \
    | grep -E '^[a-z]' | grep -v ':' | grep -E "cross|$2" | sort -u
}

# OpenSSL do host (headers + libs de desenvolvimento) e qemu user-mode
PKGS=(libssl-dev qemu-user-static)
for a in "${ARCHS[@]}"; do
  case "$a" in
    arm64) T=aarch64-linux-gnu ;;
    armhf) T=arm-linux-gnueabihf ;;
    *) echo "arquitetura desconhecida: $a"; exit 1 ;;
  esac
  mapfile -t D < <(deps_of "g++-$T" "$T")
  PKGS+=("${D[@]}")
done
echo ">> baixando ${#PKGS[@]} pacotes do repositório do host"
apt-get download "${PKGS[@]}" >/dev/null
# libssl3 do host (o .so de desenvolvimento aponta para ele)
apt-get download "$(apt-cache depends libssl-dev | awk '/Depends: libssl3/{print $2; exit}')" >/dev/null

# OpenSSL da arquitetura alvo (multiarch) — versão idêntica à do host
SSLV="$(dpkg-deb -f libssl-dev_*_amd64.deb Version)"
SSLV_URL="${SSLV//:/%3a}"
LIBSSL="$(apt-cache depends libssl-dev | awk '/Depends: libssl3/{print $2; exit}')"
for a in "${ARCHS[@]}"; do
  for p in libssl-dev "$LIBSSL"; do
    f="${p}_${SSLV_URL}_${a}.deb"
    [[ -f "$f" ]] || { echo ">> $f"; curl -fsSLO "$PORTS/pool/main/o/openssl/$f"; }
  done
done

echo ">> extraindo em $TC"
for f in *.deb; do dpkg-deb -x "$f" "$TC"; done

# Scripts de linker da glibc (libc.so, libm.so...) usam caminhos absolutos /usr/<triple>/lib;
# como a extração não é em /, redireciona-os para o prefixo local.
for t in aarch64-linux-gnu arm-linux-gnueabihf; do
  [[ -d "$TC/usr/$t/lib" ]] || continue
  grep -l "GNU ld script" "$TC/usr/$t/lib/"*.so 2>/dev/null | while read -r f; do
    sed -i "s| /usr/$t/| $TC/usr/$t/|g" "$f"
  done
done

cat > "$TC/env.sh" <<ENV
# source .toolchain/env.sh
export OHBOY_TOOLCHAIN_ROOT="$TC"
export PATH="$TC/usr/bin:\$PATH"
export LD_LIBRARY_PATH="$TC/usr/lib/x86_64-linux-gnu\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
ENV
echo ">> pronto. Toolchains:"
ls "$TC/usr/bin" | grep -E -- '-g\+\+$|qemu-(aarch64|arm)-static$' | sed 's/^/   /'
