# Raspberry Pi 3B+ (Cortex-A53) em modo 64 bits — Yocto MACHINE=raspberrypi3-64
# Uso: cmake -B build-aarch64 -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/aarch64-linux-gnu.cmake
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)
set(TRIPLE aarch64-linux-gnu)
set(OHBOY_QEMU qemu-aarch64-static)
include(${CMAKE_CURRENT_LIST_DIR}/common-cross.cmake)
set(CMAKE_CXX_FLAGS_INIT "-mcpu=cortex-a53")
