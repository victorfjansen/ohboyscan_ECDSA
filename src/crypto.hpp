#pragma once
// ECDSA sobre NIST P-256 (secp256r1) + SHA-256, via OpenSSL 3 (libcrypto).
// O nonce efêmero k é gerado pelo DRBG do OpenSSL, semeado pelo CSPRNG do kernel
// (getrandom), que no RPi é alimentado pelo TRNG bcm2835 (/dev/hwrng).
// Opcionalmente (OpenSSL >= 3.2) o nonce pode ser determinístico (RFC 6979).
#include <string>
#include <string_view>
#include <vector>

typedef struct evp_pkey_st EVP_PKEY;

namespace ohb::crypto {

using Bytes = std::vector<unsigned char>;

class Key {
public:
    Key() = default;
    explicit Key(EVP_PKEY* p) : p_(p) {}
    Key(const Key&) = delete;
    Key& operator=(const Key&) = delete;
    Key(Key&& o) noexcept : p_(o.p_) { o.p_ = nullptr; }
    Key& operator=(Key&& o) noexcept;
    ~Key();
    EVP_PKEY* get() const { return p_; }
    explicit operator bool() const { return p_ != nullptr; }

private:
    EVP_PKEY* p_ = nullptr;
};

Key generate_p256();
// PKCS#8 cifrado: PBES2 (scrypt N=2^14,r=8,p=1 + AES-256-CBC), PEM.
std::string private_pem_encrypted(const Key& k, const std::string& passphrase);
std::string public_pem(const Key& k);
Key load_private_pem(const std::string& pem, const std::string& passphrase);
Key load_public_pem(const std::string& pem);
// Identificador: SHA-256 do SubjectPublicKeyInfo (DER), 16 primeiros hex.
std::string key_id(const Key& k);
// Verifica se a chave é EC P-256.
void require_p256(const Key& k);

// Assinatura DER (X9.62 ECDSA-Sig-Value) sobre SHA-256(msg).
Bytes sign(const Key& k, std::string_view msg, bool deterministic_nonce = false);
bool verify(const Key& k, std::string_view msg, const Bytes& der_sig);
// Extrai (r, s) em hexadecimal de uma assinatura DER (para relatórios/artigo).
std::pair<std::string, std::string> sig_rs_hex(const Bytes& der_sig);

Bytes sha256(std::string_view data);
std::string sha256_hex(std::string_view data);
std::string b64encode(const Bytes& b);
Bytes b64decode(const std::string& s);

std::string openssl_version();
bool deterministic_nonce_supported();
std::string last_error();

}  // namespace ohb::crypto
