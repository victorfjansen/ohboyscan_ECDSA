SUMMARY = "OhBoyScan - auditoria de integridade de roteadores MikroTik com ECDSA P-256"
DESCRIPTION = "CLI/daemon que verifica baseline de configuração e scripts do RouterOS \
via API, com assinaturas ECDSA (NIST P-256 + SHA-256)."
LICENSE = "CLOSED"

# Desenvolvimento: aponte para o checkout local em conf/local.conf:
#   INHERIT += "externalsrc"
#   EXTERNALSRC:pn-ohboyscan = "/caminho/para/ohboyscan_cli"
# Produção: troque por SRC_URI = "git://...;branch=main;protocol=https" + SRCREV.

inherit cmake systemd

DEPENDS = "openssl"
RDEPENDS:${PN} = "cronie"
RRECOMMENDS:${PN} = "curl"

EXTRA_OECMAKE = "-DOHBOY_BUILD_TESTS=OFF"

SYSTEMD_SERVICE:${PN} = "ohboyscan.service"
SYSTEMD_AUTO_ENABLE = "disable"

do_install:append() {
    install -d ${D}${sysconfdir}/ohboyscan ${D}${sysconfdir}/cron.d
    install -m 0600 ${S}/deploy/ohboyscan.conf.example ${D}${sysconfdir}/ohboyscan/ohboyscan.conf
    install -m 0644 ${S}/deploy/ohboyscan.cron ${D}${sysconfdir}/cron.d/ohboyscan
    install -d ${D}${systemd_system_unitdir}
    install -m 0644 ${S}/deploy/systemd/ohboyscan.service ${D}${systemd_system_unitdir}/
    install -d -m 0755 ${D}${localstatedir}/lib/ohboyscan
}

FILES:${PN} += "${systemd_system_unitdir}/ohboyscan.service ${localstatedir}/lib/ohboyscan"
CONFFILES:${PN} = "${sysconfdir}/ohboyscan/ohboyscan.conf"
