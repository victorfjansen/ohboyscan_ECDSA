# Lógica comum dos toolchains Debian/Ubuntu (pacotes g++-<triple> + libssl-dev:<arch>).
# Variável opcional OHBOY_TOOLCHAIN_ROOT: prefixo onde os .deb foram extraídos
# sem root (scripts/bootstrap-toolchain.sh). Se ausente, usa o sistema (/usr).
if(NOT DEFINED OHBOY_TOOLCHAIN_ROOT AND DEFINED ENV{OHBOY_TOOLCHAIN_ROOT})
  set(OHBOY_TOOLCHAIN_ROOT "$ENV{OHBOY_TOOLCHAIN_ROOT}")
endif()
if(OHBOY_TOOLCHAIN_ROOT)
  set(_bin "${OHBOY_TOOLCHAIN_ROOT}/usr/bin/")
  set(_root "${OHBOY_TOOLCHAIN_ROOT}")
else()
  set(_bin "")
  set(_root "/")
endif()

set(CMAKE_C_COMPILER   ${_bin}${TRIPLE}-gcc)
set(CMAKE_CXX_COMPILER ${_bin}${TRIPLE}-g++)

# OpenSSL da arquitetura alvo (multiarch Debian: /usr/lib/<triple>, /usr/include/<triple>)
set(OPENSSL_INCLUDE_DIR    "${_root}/usr/include")
set(OPENSSL_CRYPTO_LIBRARY "${_root}/usr/lib/${TRIPLE}/libcrypto.so")
set(OPENSSL_SSL_LIBRARY    "${_root}/usr/lib/${TRIPLE}/libssl.so")
include_directories(SYSTEM "${_root}/usr/include/${TRIPLE}")
set(CMAKE_EXE_LINKER_FLAGS_INIT "-Wl,-rpath-link,${_root}/usr/lib/${TRIPLE}")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

# Permite rodar os testes (ctest) via emulação de usuário.
find_program(_qemu NAMES ${OHBOY_QEMU} HINTS "${_root}/usr/bin")
if(_qemu)
  set(CMAKE_CROSSCOMPILING_EMULATOR env "LD_LIBRARY_PATH=${_root}/usr/lib/${TRIPLE}"
      ${_qemu} -L ${_root}/usr/${TRIPLE})
endif()
