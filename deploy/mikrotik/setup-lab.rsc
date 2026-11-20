# OhBoyScan - setup de LABORATORIO (RouterOS v7, RB750Gr3 / hEX)
# Auditor = notebook na LAN padrao (192.168.88.254). Nao altera bridge/interfaces.
# Idempotente: pode ser executado mais de uma vez.
# Uso: Winbox > Files > arraste o arquivo > New Terminal:
#   /import file-name=setup-lab.rsc verbose=yes
# Obs.: sem variaveis (:local), pois com verbose=yes cada linha roda isolada.

# 1) Certificados para API-SSL (CA local + certificado do roteador)
:if ([:len [/certificate find name=ohboyscan-ca]] = 0) do={ /certificate add name=ohboyscan-ca common-name=ohboyscan-ca key-usage=key-cert-sign,crl-sign days-valid=3650; /certificate sign ohboyscan-ca; :delay 10s }
:if ([:len [/certificate find name=api-cert]] = 0) do={ /certificate add name=api-cert common-name=192.168.88.1 subject-alt-name=IP:192.168.88.1 days-valid=3650; /certificate sign api-cert ca=ohboyscan-ca; :delay 10s }

# 2) Servicos de API apenas a partir do auditor (8728 so para os primeiros testes)
/ip service set api-ssl certificate=api-cert address=192.168.88.254/32 disabled=no
/ip service set api address=192.168.88.254/32 disabled=no

# 3) Grupo somente leitura + usuario do auditor
:if ([:len [/user group find name=audit]] = 0) do={ /user group add name=audit policy=read,api,sensitive comment="ohboyscan read-only" }
:if ([:len [/user find name=ohboyscan]] = 0) do={ /user add name=ohboyscan group=audit address=192.168.88.254/32 password="ohboyscan2026!" comment="auditor read-only" }

# 4) Script de exemplo para os cenarios 3a/3b
:if ([:len [/system script find name=daily-backup]] = 0) do={ /system script add name=daily-backup policy=ftp,read,write,policy,test source=":log info \"ohboyscan: backup diario\"\r\n/system backup save name=daily" }

# 5) Conferencia + fingerprint SHA-256 do certificado (para tls_fingerprint)
/ip service print where name~"api"
/user print where name=ohboyscan
/certificate print detail where name=api-cert
:put "OK - setup-lab concluido"
