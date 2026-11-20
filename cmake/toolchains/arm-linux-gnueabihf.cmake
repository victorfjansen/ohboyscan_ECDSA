# Raspberry Pi 3B+ em modo 32 bits (armv7-a hard-float) — Yocto MACHINE=raspberrypi3
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR armv7l)
set(TRIPLE arm-linux-gnueabihf)
set(OHBOY_QEMU qemu-arm-static)
include(${CMAKE_CURRENT_LIST_DIR}/common-cross.cmake)
set(CMAKE_CXX_FLAGS_INIT "-mcpu=cortex-a53 -mfpu=neon-fp-armv8 -mfloat-abi=hard")
