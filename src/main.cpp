// OhBoyScan — auditoria de roteadores MikroTik com ECDSA P-256.
#include <cctype>
#include <cstdio>
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <map>
#include <sys/file.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "alert.hpp"
#include "audit.hpp"
#include "config.hpp"
#include "crypto.hpp"
#include "history.hpp"
#include "preset.hpp"
#include "routeros_api.hpp"
#include "snapshot.hpp"
#include "util.hpp"

using namespace ohb;

namespace {

const char* kUsage = R"(OhBoyScan )" OHBOY_VERSION R"( — auditoria de integridade MikroTik com ECDSA P-256/SHA-256

Uso: ohboyscan [opções globais] <comando> [opções]

Opções globais:
  -c, --config ARQ        arquivo de configuração (padrão: /etc/ohboyscan/ohboyscan.conf
                          ou $OHBOY_CONFIG)
  -d, --data-dir DIR      sobrescreve paths.data_dir

Comandos:
  init --operator NOME [--force] [--passphrase-file ARQ]
        Gera o par de chaves ECDSA P-256 do operador. Kpr -> keys/NOME.key.pem
        (PKCS#8 cifrado, scrypt + AES-256), Kpub -> keys/NOME.pub.pem (somente leitura).
  keys
        Lista as chaves públicas confiáveis.
  preset save --operator NOME [--comment TXT] [--passphrase-file ARQ]
        Coleta a configuração atual (estado confiável), gera preset.json canônico e
        assina o arquivo e cada script ativo com Kpr do operador.
  preset verify
        Verifica apenas a integridade local de preset.json (sem acessar o roteador).
  preset show
        Exibe o resumo do baseline.
  audit [--json] [--no-alert] [--quiet]
        Auditoria completa (usa apenas Kpub). Saída: 0 íntegro, 1 alerta, 2 erro.
  daemon [--interval SEG] [--detach] [--pidfile ARQ]
        Executa audit periodicamente (padrão 300 s).
  history [--no-verify]
        Mostra e verifica a trilha assinada de alterações autorizadas.
  probe
        Testa conexão/login na API e lista as seções coletadas.
  doctor
        Diagnóstico do ambiente (OpenSSL, fonte de entropia, permissões).
  version
)";

struct Args {
    std::vector<std::string> pos;
    std::map<std::string, std::string> opt;
    bool has(const std::string& k) const { return opt.count(k) > 0; }
    std::string get(const std::string& k, const std::string& d = "") const {
        auto it = opt.find(k);
        return it == opt.end() ? d : it->second;
    }
};

const std::vector<std::string> kFlags = {"--force", "--json", "--no-alert", "--quiet", "--detach",
                                         "--no-verify", "-h", "--help"};

Args parse_args(int argc, char** argv) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        if (s == "-c") s = "--config";
        if (s == "-d") s = "--data-dir";
        if (s.rfind("--", 0) == 0 || s == "-h") {
            auto eq = s.find('=');
            if (eq != std::string::npos) {
                a.opt[s.substr(0, eq)] = s.substr(eq + 1);
            } else if (std::find(kFlags.begin(), kFlags.end(), s) != kFlags.end()) {
                a.opt[s] = "1";
            } else {
                if (i + 1 >= argc) throw Error("opção " + s + " requer um valor");
                a.opt[s] = argv[++i];
            }
        } else {
            a.pos.push_back(s);
        }
    }
    return a;
}

std::atomic<bool> g_stop{false};
void on_signal(int) { g_stop = true; }

// Evita auditorias concorrentes (cron + daemon). Retorna fd ou -1 se ocupado.
int take_lock(const Config& cfg) {
    if (cfg.lock_file.empty()) return -2;
    int fd = ::open(cfg.lock_file.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0644);
    if (fd < 0) return -2;  // sem permissão: segue sem lock
    if (::flock(fd, LOCK_EX | LOCK_NB) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

int cmd_audit(const Config& cfg, const Args& a) {
    int lk = take_lock(cfg);
    if (lk == -1) {
        std::cerr << "outra auditoria em andamento; ignorando\n";
        return 0;
    }
    auto rep = run_audit(cfg);
    if (!a.has("--no-alert")) emit_alerts(cfg, rep);
    if (a.has("--json")) std::cout << json::dump(rep.to_json(), true);
    else if (!a.has("--quiet") || !rep.clean()) std::cout << rep.to_text();
    if (lk >= 0) ::close(lk);
    return rep.exit_code();
}

int cmd_daemon(const Config& cfg, const Args& a) {
    int interval = std::stoi(a.get("--interval", "300"));
    if (interval < 5) throw Error("intervalo mínimo: 5 s");
    if (a.has("--detach")) {
        if (::fork() > 0) return 0;
        ::setsid();
        if (::fork() > 0) ::_exit(0);
        if (::chdir("/") != 0) { /* ignora */ }
        int nul = ::open("/dev/null", O_RDWR);
        ::dup2(nul, 0);
        ::dup2(nul, 1);
        ::dup2(nul, 2);
    }
    if (a.has("--pidfile")) write_file_atomic(a.get("--pidfile"), std::to_string(::getpid()) + "\n", 0644);
    std::signal(SIGTERM, on_signal);
    std::signal(SIGINT, on_signal);
    std::cerr << "ohboyscan daemon: auditoria a cada " << interval << " s (pid " << ::getpid() << ")\n";
    while (!g_stop) {
        try {
            Args quiet;
            quiet.opt["--quiet"] = "1";
            cmd_audit(cfg, quiet);
        } catch (const std::exception& e) {
            std::cerr << "erro na auditoria: " << e.what() << "\n";
        }
        for (int i = 0; i < interval * 10 && !g_stop; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    if (a.has("--pidfile")) ::unlink(a.get("--pidfile").c_str());
    return 0;
}

int cmd_init(const Config& cfg, const Args& a) {
    auto op = a.get("--operator");
    if (op.empty()) throw Error("informe --operator NOME");
    validate_operator_name(op);
    auto pass = read_passphrase("Nova passphrase para '" + op + "': ", a.get("--passphrase-file"), true);
    auto kid = init_keys(cfg, op, pass, a.has("--force"));
    std::cout << "Par de chaves ECDSA P-256 criado para '" << op << "'\n"
              << "  Kpr (PKCS#8 cifrado): " << privkey_path(cfg, op) << "\n"
              << "  Kpub              : " << pubkey_path(cfg, op) << "\n"
              << "  key_id            : " << kid << "\n";
    return 0;
}

int cmd_keys(const Config& cfg) {
    std::string dir = cfg.keys_dir();
    std::string out;
    FILE* p = ::popen(("ls -1 '" + dir + "' 2>/dev/null").c_str(), "r");
    if (p) {
        char buf[512];
        while (std::fgets(buf, sizeof buf, p)) {
            std::string f = trim(buf);
            const std::string suf = ".pub.pem";
            if (f.size() > suf.size() && f.compare(f.size() - suf.size(), suf.size(), suf) == 0) {
                std::string op = f.substr(0, f.size() - suf.size());
                try {
                    auto k = load_operator_public(cfg, op);
                    std::cout << op << "\tkey_id=" << crypto::key_id(k)
                              << (file_exists(privkey_path(cfg, op)) ? "\t(Kpr presente)" : "") << "\n";
                } catch (const std::exception& e) {
                    std::cout << op << "\tERRO: " << e.what() << "\n";
                }
            }
        }
        ::pclose(p);
    }
    return 0;
}

int cmd_preset(const Config& cfg, const Args& a) {
    std::string sub = a.pos.size() > 1 ? a.pos[1] : "";
    if (sub == "save") {
        auto op = a.get("--operator");
        if (op.empty()) throw Error("informe --operator NOME");
        auto pass = read_passphrase("Passphrase de '" + op + "': ", a.get("--passphrase-file"), false);
        auto key = load_operator_private(cfg, op, pass);
        if (crypto::key_id(key) != crypto::key_id(load_operator_public(cfg, op)))
            throw Error("Kpr não corresponde à Kpub confiável de " + op);
        ros::ApiClient api(cfg);
        api.connect();
        auto snap = collect_snapshot(api, cfg, cfg.sections, cfg.ignore_fields);
        auto r = save_preset(cfg, snap, op, key, a.get("--comment"));
        std::cout << "Baseline assinado por '" << op << "' (key_id " << r.key_id << ")\n"
                  << "  " << r.path << "  sha256=" << r.sha256 << "\n"
                  << "  " << r.sig_path << "\n"
                  << "  seções=" << r.n_sections << " itens=" << r.n_items << " scripts assinados=" << r.n_scripts
                  << "  (assinatura do preset: " << r.sign_ms << " ms)\n";
        if (!api.peer_cert_sha256().empty() && cfg.tls_fingerprint.empty())
            std::cout << "  dica: fixe o certificado do roteador com tls_fingerprint = " << api.peer_cert_sha256()
                      << "\n";
        return 0;
    }
    if (sub == "verify" || sub == "show") {
        auto v = verify_local_preset(cfg);
        if (!v.valid) {
            std::cout << "preset.json: INVÁLIDO — " << v.reason << "\n";
            return 1;
        }
        std::cout << "preset.json: assinatura VÁLIDA (operador " << v.op << ", key_id " << v.key_id << ", "
                  << v.verify_ms << " ms)\n  sha256=" << v.sha256 << "\n";
        if (sub == "show") {
            auto& m = v.doc.at("meta");
            std::cout << "  criado em " << m.get_str("created_at") << "  comentário: " << m.get_str("comment") << "\n"
                      << "  roteador: " << json::dump(m.at("router"), false) << "\n";
            for (auto& [k, val] : v.doc.at("sections").obj())
                std::cout << "  " << k << ": " << val.arr().size() << " itens\n";
            for (auto& s : v.doc.at("scripts").arr()) {
                auto rs = crypto::sig_rs_hex(crypto::b64decode(s.get_str("signature")));
                std::cout << "  script " << s.get_str("name") << "  sha256=" << s.get_str("sha256").substr(0, 16)
                          << "…  r=" << rs.first.substr(0, 16) << "… s=" << rs.second.substr(0, 16) << "…\n";
            }
        }
        return 0;
    }
    throw Error("uso: preset save|verify|show");
}

int cmd_probe(const Config& cfg) {
    ros::ApiClient api(cfg);
    double t = monotonic_ms();
    api.connect();
    std::cout << "login OK em " << cfg.host << ":" << cfg.effective_port() << (cfg.tls ? " (API-SSL)" : " (API)")
              << " em " << monotonic_ms() - t << " ms\n";
    if (!api.peer_cert_sha256().empty()) std::cout << "certificado SHA-256: " << api.peer_cert_sha256() << "\n";
    auto snap = collect_snapshot(api, cfg, cfg.sections, cfg.ignore_fields);
    std::cout << "roteador: " << json::dump(snap.router, false) << "\n";
    for (auto& [k, v] : snap.sections) std::cout << "  " << k << ": " << v.arr().size() << " itens\n";
    if (cfg.audit_scripts) std::cout << "  " << cfg.scripts_path << ": " << snap.scripts.size() << " scripts\n";
    return 0;
}

int cmd_doctor(const Config& cfg) {
    std::cout << "OhBoyScan " << OHBOY_VERSION << "\n"
              << "OpenSSL: " << crypto::openssl_version() << "\n"
              << "RFC 6979 (nonce determinístico) disponível: "
              << (crypto::deterministic_nonce_supported() ? "sim" : "não (requer OpenSSL >= 3.2)") << "\n";
    std::string rng = "(indisponível)";
    try {
        rng = trim(read_file("/sys/class/misc/hw_random/rng_current"));
    } catch (...) {
    }
    std::cout << "TRNG de hardware (rng_current): " << rng << "\n";
    try {
        std::cout << "entropia disponível no kernel: " << trim(read_file("/proc/sys/kernel/random/entropy_avail"))
                  << " bits\n";
    } catch (...) {
    }
    std::cout << "data_dir: " << cfg.data_dir << (file_exists(cfg.data_dir) ? "" : " (não existe)") << "\n";
    struct stat st{};
    for (auto& p : {cfg.preset_path(), cfg.preset_sig_path(), cfg.keys_dir()}) {
        if (::stat(p.c_str(), &st) == 0)
            std::printf("  %-50s modo %04o uid %u\n", p.c_str(), st.st_mode & 07777, st.st_uid);
    }
    auto t = monotonic_ms();
    auto k = crypto::generate_p256();
    auto sig = crypto::sign(k, "ohboyscan-selftest");
    bool ok = crypto::verify(k, "ohboyscan-selftest", sig) && !crypto::verify(k, "ohboyscan-selftesT", sig);
    std::cout << "autoteste ECDSA P-256: " << (ok ? "OK" : "FALHOU") << " (" << monotonic_ms() - t << " ms)\n";
    std::cout << "roteador: " << cfg.host << ":" << cfg.effective_port() << (cfg.tls ? " API-SSL" : " API (texto claro)")
              << (cfg.tls && cfg.tls_fingerprint.empty() && cfg.tls_ca_file.empty() ? "  AVISO: TLS sem pinning/CA"
                                                                                      : "")
              << "\n";
    return ok ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
    std::signal(SIGPIPE, SIG_IGN);
    try {
        Args a = parse_args(argc, argv);
        if (a.pos.empty() || a.has("-h") || a.has("--help")) {
            std::cout << kUsage;
            return a.pos.empty() && !a.has("-h") && !a.has("--help") ? 2 : 0;
        }
        const std::string& cmd = a.pos[0];
        if (cmd == "version") {
            std::cout << "ohboyscan " << OHBOY_VERSION << " (" << crypto::openssl_version() << ")\n";
            return 0;
        }
        std::string cfg_path = a.get("--config");
        bool explicit_cfg = !cfg_path.empty();
        if (!explicit_cfg) {
            const char* e = std::getenv("OHBOY_CONFIG");
            cfg_path = e ? e : "/etc/ohboyscan/ohboyscan.conf";
            explicit_cfg = e != nullptr;
        }
        Config cfg = Config::load(cfg_path, explicit_cfg);
        if (a.has("--data-dir")) cfg.data_dir = a.get("--data-dir");
        ::umask(022);

        if (cmd == "init") return cmd_init(cfg, a);
        if (cmd == "keys") return cmd_keys(cfg);
        if (cmd == "preset") return cmd_preset(cfg, a);
        if (cmd == "audit") return cmd_audit(cfg, a);
        if (cmd == "daemon") return cmd_daemon(cfg, a);
        if (cmd == "history") return print_history(cfg, !a.has("--no-verify")) ? 1 : 0;
        if (cmd == "probe") return cmd_probe(cfg);
        if (cmd == "doctor") return cmd_doctor(cfg);
        std::cerr << "comando desconhecido: " << cmd << "\n\n" << kUsage;
        return 2;
    } catch (const std::exception& e) {
        std::cerr << "erro: " << e.what() << "\n";
        return 2;
    }
}
