#include "routeros_api.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "crypto.hpp"
#include "util.hpp"

namespace ohb::ros {

std::string encode_length(uint32_t len) {
    std::string o;
    if (len < 0x80) {
        o += static_cast<char>(len);
    } else if (len < 0x4000) {
        len |= 0x8000;
        o += static_cast<char>(len >> 8);
        o += static_cast<char>(len & 0xFF);
    } else if (len < 0x200000) {
        len |= 0xC00000;
        o += static_cast<char>(len >> 16);
        o += static_cast<char>((len >> 8) & 0xFF);
        o += static_cast<char>(len & 0xFF);
    } else if (len < 0x10000000) {
        len |= 0xE0000000;
        o += static_cast<char>(len >> 24);
        o += static_cast<char>((len >> 16) & 0xFF);
        o += static_cast<char>((len >> 8) & 0xFF);
        o += static_cast<char>(len & 0xFF);
    } else {
        o += static_cast<char>(0xF0);
        o += static_cast<char>(len >> 24);
        o += static_cast<char>((len >> 16) & 0xFF);
        o += static_cast<char>((len >> 8) & 0xFF);
        o += static_cast<char>(len & 0xFF);
    }
    return o;
}

size_t decode_length(const unsigned char* p, size_t n, uint32_t& len) {
    if (n < 1) return 0;
    unsigned char c = p[0];
    size_t need;
    if ((c & 0x80) == 0x00) need = 1;
    else if ((c & 0xC0) == 0x80) need = 2;
    else if ((c & 0xE0) == 0xC0) need = 3;
    else if ((c & 0xF0) == 0xE0) need = 4;
    else if (c == 0xF0) need = 5;
    else throw Error("API: byte de controle reservado no comprimento");
    if (n < need) return 0;
    switch (need) {
        case 1: len = c; break;
        case 2: len = ((c & 0x3Fu) << 8) | p[1]; break;
        case 3: len = ((c & 0x1Fu) << 16) | (uint32_t(p[1]) << 8) | p[2]; break;
        case 4: len = ((c & 0x0Fu) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3]; break;
        default: len = (uint32_t(p[1]) << 24) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 8) | p[4];
    }
    return need;
}

std::string encode_sentence(const Sentence& words) {
    std::string o;
    for (auto& w : words) {
        o += encode_length(static_cast<uint32_t>(w.size()));
        o += w;
    }
    o += '\0';
    return o;
}

ApiClient::ApiClient(const Config& cfg) : cfg_(cfg) {}
ApiClient::~ApiClient() { close(); }

void ApiClient::close() {
    if (ssl_) {
        SSL_shutdown(ssl_);
        SSL_free(ssl_);
        ssl_ = nullptr;
    }
    if (ctx_) {
        SSL_CTX_free(ctx_);
        ctx_ = nullptr;
    }
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

static int tcp_connect(const std::string& host, int port, int timeout_ms) {
    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    addrinfo* res = nullptr;
    std::string ps = std::to_string(port);
    int rc = ::getaddrinfo(host.c_str(), ps.c_str(), &hints, &res);
    if (rc != 0) throw Error("resolução de " + host + ": " + gai_strerror(rc));
    std::string last = "sem endereços";
    for (addrinfo* ai = res; ai; ai = ai->ai_next) {
        int fd = ::socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
        if (fd < 0) continue;
        int fl = ::fcntl(fd, F_GETFL);
        ::fcntl(fd, F_SETFL, fl | O_NONBLOCK);
        int r = ::connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (r != 0 && errno == EINPROGRESS) {
            pollfd pfd{fd, POLLOUT, 0};
            r = ::poll(&pfd, 1, timeout_ms);
            if (r == 1) {
                int err = 0;
                socklen_t l = sizeof err;
                ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &l);
                r = err ? -1 : 0;
                errno = err;
            } else {
                errno = (r == 0 || errno == 0) ? ETIMEDOUT : errno;
                r = -1;
            }
        }
        if (r == 0) {
            ::fcntl(fd, F_SETFL, fl);
            timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
            ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
            ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
            int one = 1;  // sentenças pequenas: evita Nagle + ACK atrasado (~40 ms/ida-e-volta)
            ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
            ::freeaddrinfo(res);
            return fd;
        }
        last = std::strerror(errno ? errno : ETIMEDOUT);
        ::close(fd);
    }
    ::freeaddrinfo(res);
    throw Error("conexão com " + host + ":" + ps + " falhou: " + last);
}

void ApiClient::connect() {
    close();
    fd_ = tcp_connect(cfg_.host, cfg_.effective_port(), cfg_.timeout_ms);
    if (cfg_.tls) {
        ctx_ = SSL_CTX_new(TLS_client_method());
        if (!ctx_) throw Error("SSL_CTX_new: " + crypto::last_error());
        SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION);
        if (!cfg_.tls_ca_file.empty()) {
            if (SSL_CTX_load_verify_locations(ctx_, cfg_.tls_ca_file.c_str(), nullptr) != 1)
                throw Error("CA inválida: " + crypto::last_error());
            SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER, nullptr);
        } else {
            // Sem CA: a autenticidade do roteador depende do pinning (tls_fingerprint).
            SSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, nullptr);
        }
        ssl_ = SSL_new(ctx_);
        SSL_set_fd(ssl_, fd_);
        SSL_set_tlsext_host_name(ssl_, cfg_.host.c_str());
        if (SSL_connect(ssl_) != 1) throw Error("handshake TLS falhou: " + crypto::last_error());
        X509* cert = SSL_get1_peer_certificate(ssl_);
        if (!cert) throw Error("o roteador não apresentou certificado TLS");
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int mdlen = 0;
        X509_digest(cert, EVP_sha256(), md, &mdlen);
        X509_free(cert);
        peer_fp_ = to_hex(md, mdlen);
        if (!cfg_.tls_fingerprint.empty() && cfg_.tls_fingerprint != peer_fp_)
            throw Error("fingerprint TLS do roteador não confere (esperado " + cfg_.tls_fingerprint +
                        ", recebido " + peer_fp_ + ") — possível MITM");
    }
    login();
}

void ApiClient::write_all(const std::string& s) {
    size_t off = 0;
    while (off < s.size()) {
        ssize_t n;
        if (ssl_) n = SSL_write(ssl_, s.data() + off, static_cast<int>(s.size() - off));
        else n = ::send(fd_, s.data() + off, s.size() - off, MSG_NOSIGNAL);
        if (n <= 0) {
            if (!ssl_ && errno == EINTR) continue;
            throw Error("API: falha de escrita no socket");
        }
        off += static_cast<size_t>(n);
    }
}

void ApiClient::read_exact(void* buf, size_t n) {
    auto p = static_cast<char*>(buf);
    size_t off = 0;
    while (off < n) {
        ssize_t r;
        if (ssl_) r = SSL_read(ssl_, p + off, static_cast<int>(n - off));
        else r = ::recv(fd_, p + off, n - off, 0);
        if (r == 0) throw Error("API: conexão encerrada pelo roteador");
        if (r < 0) {
            if (!ssl_ && errno == EINTR) continue;
            if (!ssl_ && (errno == EAGAIN || errno == EWOULDBLOCK)) throw Error("API: timeout de leitura");
            throw Error("API: falha de leitura");
        }
        off += static_cast<size_t>(r);
    }
}

std::string ApiClient::read_word() {
    unsigned char hdr[5];
    read_exact(hdr, 1);
    size_t need = 1;
    if ((hdr[0] & 0x80) == 0x00) need = 1;
    else if ((hdr[0] & 0xC0) == 0x80) need = 2;
    else if ((hdr[0] & 0xE0) == 0xC0) need = 3;
    else if ((hdr[0] & 0xF0) == 0xE0) need = 4;
    else need = 5;
    if (need > 1) read_exact(hdr + 1, need - 1);
    uint32_t len = 0;
    decode_length(hdr, need, len);
    if (len > (64u << 20)) throw Error("API: palavra excessivamente longa");
    std::string w(len, '\0');
    if (len) read_exact(w.data(), len);
    return w;
}

void ApiClient::send_sentence(const Sentence& s) { write_all(encode_sentence(s)); }

Sentence ApiClient::read_sentence() {
    Sentence s;
    while (true) {
        std::string w = read_word();
        if (w.empty()) break;
        s.push_back(std::move(w));
    }
    return s;
}

static Record attrs_of(const Sentence& s) {
    Record r;
    for (size_t i = 1; i < s.size(); ++i) {
        const std::string& w = s[i];
        if (w.size() > 1 && w[0] == '=') {
            auto eq = w.find('=', 1);
            if (eq == std::string::npos) r[w.substr(1)] = "";
            else r[w.substr(1, eq - 1)] = w.substr(eq + 1);
        }
    }
    return r;
}

std::vector<Record> ApiClient::talk(const Sentence& cmd) {
    send_sentence(cmd);
    std::vector<Record> out;
    std::string trap;
    while (true) {
        Sentence s = read_sentence();
        if (s.empty()) continue;
        const std::string& t = s[0];
        if (t == "!re") out.push_back(attrs_of(s));
        else if (t == "!trap") {
            auto a = attrs_of(s);
            trap = a.count("message") ? a["message"] : "erro desconhecido";
        } else if (t == "!fatal") {
            throw Error("API !fatal: " + (s.size() > 1 ? s[1] : std::string()));
        } else if (t == "!done" || t == "!empty") {
            if (t == "!done") {
                auto a = attrs_of(s);
                if (a.count("ret")) out.push_back(a);  // login legado
            }
            if (t == "!empty") continue;  // v7.18+: segue-se !done
            break;
        }
    }
    if (!trap.empty()) throw Error("API !trap em " + cmd[0] + ": " + trap);
    return out;
}

void ApiClient::login() {
    // RouterOS >= 6.43: login direto. Versões antigas devolvem um desafio (=ret=).
    auto r = talk({"/login", "=name=" + cfg_.user, "=password=" + cfg_.password});
    if (!r.empty() && r[0].count("ret")) {
        std::string chal_hex = r[0]["ret"];
        std::string chal;
        for (size_t i = 0; i + 1 < chal_hex.size(); i += 2)
            chal += static_cast<char>(std::stoi(chal_hex.substr(i, 2), nullptr, 16));
        std::string msg = std::string(1, '\0') + cfg_.password + chal;
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int n = 0;
        EVP_Digest(msg.data(), msg.size(), md, &n, EVP_md5(), nullptr);
        talk({"/login", "=name=" + cfg_.user, "=response=00" + to_hex(md, n)});
    }
}

std::vector<Record> ApiClient::print(const std::string& path) {
    std::string p = path;
    if (p.empty() || p[0] != '/') p = "/" + p;
    if (p.back() == '/') p.pop_back();
    return talk({p + "/print"});
}

}  // namespace ohb::ros
