#pragma once
// Cliente do protocolo binário da API do RouterOS (porta 8728 / API-SSL 8729).
// Ref.: https://help.mikrotik.com/docs/display/ROS/API
//  - Palavra = <comprimento codificado (1..5 bytes)> + bytes
//  - Sentença = palavras terminadas por palavra vazia
//  - Respostas: !re (registro), !done, !trap (erro), !fatal, !empty (v7.18+)
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "config.hpp"

typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;

namespace ohb::ros {

using Record = std::map<std::string, std::string>;
using Sentence = std::vector<std::string>;

std::string encode_length(uint32_t len);
// Decodifica o comprimento a partir de um buffer; retorna bytes consumidos (0 se incompleto).
size_t decode_length(const unsigned char* p, size_t n, uint32_t& len);
std::string encode_sentence(const Sentence& words);

class ApiClient {
public:
    explicit ApiClient(const Config& cfg);
    ~ApiClient();
    ApiClient(const ApiClient&) = delete;
    ApiClient& operator=(const ApiClient&) = delete;

    void connect();  // TCP (+TLS) + /login
    void close();
    // Envia um comando e coleta todos os !re até !done. Lança em !trap/!fatal.
    std::vector<Record> talk(const Sentence& cmd);
    std::vector<Record> print(const std::string& menu_path);  // ex.: "/ip/service"
    std::string peer_cert_sha256() const { return peer_fp_; }

private:
    void send_sentence(const Sentence& s);
    Sentence read_sentence();
    std::string read_word();
    void read_exact(void* buf, size_t n);
    void write_all(const std::string& s);
    void login();

    const Config& cfg_;
    int fd_ = -1;
    SSL_CTX* ctx_ = nullptr;
    SSL* ssl_ = nullptr;
    std::string peer_fp_;
};

}  // namespace ohb::ros
