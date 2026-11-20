SUMMARY = "Imagem mínima do OhBoyScan para Raspberry Pi 3B+"
require recipes-core/images/core-image-minimal.bb

IMAGE_INSTALL:append = " ohboyscan openssl-bin curl cronie chrony"
IMAGE_FEATURES += "ssh-server-dropbear"
