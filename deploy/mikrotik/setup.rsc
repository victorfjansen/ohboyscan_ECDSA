# OhBoyScan — preparação do MikroTik (RouterOS v7). Ajuste interface/endereços.
# Importar: /import file-name=setup.rsc   (ou colar no terminal)
#
# Topologia: RPi eth0 10.99.0.2/30  <--RJ45-->  MikroTik ether5 10.99.0.1/30

# 1) Porta dedicada ao enlace de auditoria (fora da bridge LAN)
/interface bridge port remove [find interface=ether5]
/ip address add address=10.99.0.1/30 interface=ether5 comment="ohboyscan audit link"

# 2) Certificado para API-SSL (autoassinado por uma CA local)
/certificate add name=ohboyscan-ca common-name=ohboyscan-ca key-usage=key-cert-sign,crl-sign days-valid=3650
/certificate sign ohboyscan-ca
:delay 5s
/certificate add name=api-cert common-name=10.99.0.1 subject-alt-name=IP:10.99.0.1 days-valid=3650
/certificate sign api-cert ca=ohboyscan-ca
:delay 5s

# 3) Serviços: API-SSL apenas a partir do auditor; API em texto claro desabilitada
/ip service set api-ssl certificate=api-cert address=10.99.0.2/32 disabled=no
/ip service set api address=10.99.0.2/32 disabled=yes

# 4) Grupo somente leitura para o auditor (read + api; sensitive para ler o source dos scripts)
/user group add name=audit policy=read,api,sensitive comment="ohboyscan"
/user add name=ohboyscan group=audit address=10.99.0.2/32 password="ohboyscan2026!" comment="auditor read-only"

# 5) Firewall: aceitar API-SSL do auditor antes das regras de drop
/ip firewall filter add chain=input in-interface=ether5 src-address=10.99.0.2 protocol=tcp dst-port=8729 action=accept comment="ohboyscan audit link" place-before=0

# 6) Fingerprint para tls_fingerprint no ohboyscan.conf
/certificate print detail where name=api-cert
