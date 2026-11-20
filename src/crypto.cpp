#include "crypto.hpp"

#include <cctype>
#include <cstdio>
#include <algorithm>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include <memory>

#include "util.hpp"

namespace ohb::crypto {

std::string last_error() {
    unsigned long e = ERR_get_error();
    if (!e) return "erro OpenSSL desconhecido";
    char buf[256];
    ERR_error_string_n(e, buf, sizeof buf);
    ERR_clear_error();
    return buf;
}

[[noreturn]] static void fail(const std::string& what) { throw Error(what + ": " + last_error()); }

Key& Key::operator=(Key&& o) noexcept {
    if (this != &o) {
        EVP_PKEY_free(p_);
        p_ = o.p_;
        o.p_ = nullptr;
    }
    return *this;
}
Key::~Key() { EVP_PKEY_free(p_); }

using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
static BioPtr mem_bio() { return BioPtr(BIO_new(BIO_s_mem()), BIO_free); }
static std::string bio_str(BIO* b) {
    char* p = nullptr;
    long n = BIO_get_mem_data(b, &p);
    return std::string(p, static_cast<size_t>(n));
}

Key generate_p256() {
    EVP_PKEY* p = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256");
    if (!p) fail("geração de chave P-256");
    return Key(p);
}

std::string private_pem_encrypted(const Key& k, const std::string& pass) {
    unsigned char salt[16];
    if (RAND_bytes(salt, sizeof salt) != 1) fail("RAND_bytes");
    X509_ALGOR* pbe = PKCS5_pbe2_set_scrypt(EVP_aes_256_cbc(), salt, sizeof salt, nullptr,
                                            1u << 14, 8, 1);
    if (!pbe) fail("PBES2/scrypt");
    PKCS8_PRIV_KEY_INFO* p8 = EVP_PKEY2PKCS8(k.get());
    if (!p8) { X509_ALGOR_free(pbe); fail("EVP_PKEY2PKCS8"); }
    X509_SIG* enc = PKCS8_set0_pbe(pass.data(), static_cast<int>(pass.size()), p8, pbe);
    PKCS8_PRIV_KEY_INFO_free(p8);
    if (!enc) { X509_ALGOR_free(pbe); fail("PKCS8_set0_pbe"); }
    auto b = mem_bio();
    int ok = PEM_write_bio_PKCS8(b.get(), enc);
    X509_SIG_free(enc);
    if (!ok) fail("PEM_write_bio_PKCS8");
    return bio_str(b.get());
}

std::string public_pem(const Key& k) {
    auto b = mem_bio();
    if (!PEM_write_bio_PUBKEY(b.get(), k.get())) fail("PEM_write_bio_PUBKEY");
    return bio_str(b.get());
}

Key load_private_pem(const std::string& pem, const std::string& pass) {
    BioPtr b(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
    EVP_PKEY* p = PEM_read_bio_PrivateKey(b.get(), nullptr, nullptr, const_cast<char*>(pass.c_str()));
    if (!p) {
        ERR_clear_error();
        throw Error("não foi possível decifrar a chave privada (passphrase incorreta?)");
    }
    Key k(p);
    require_p256(k);
    return k;
}

Key load_public_pem(const std::string& pem) {
    BioPtr b(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
    EVP_PKEY* p = PEM_read_bio_PUBKEY(b.get(), nullptr, nullptr, nullptr);
    if (!p) fail("leitura da chave pública");
    Key k(p);
    require_p256(k);
    return k;
}

void require_p256(const Key& k) {
    char name[64] = {0};
    size_t len = 0;
    if (!EVP_PKEY_is_a(k.get(), "EC") ||
        !EVP_PKEY_get_utf8_string_param(k.get(), OSSL_PKEY_PARAM_GROUP_NAME, name, sizeof name, &len) ||
        std::string(name) != "prime256v1")
        throw Error("a chave não é ECDSA P-256 (secp256r1)");
}

std::string key_id(const Key& k) {
    unsigned char* der = nullptr;
    int n = i2d_PUBKEY(k.get(), &der);
    if (n <= 0) fail("i2d_PUBKEY");
    std::string h = sha256_hex(std::string_view(reinterpret_cast<char*>(der), static_cast<size_t>(n)));
    OPENSSL_free(der);
    return h.substr(0, 16);
}

bool deterministic_nonce_supported() {
#if OPENSSL_VERSION_NUMBER >= 0x30200000L
    return true;
#else
    return false;
#endif
}

Bytes sign(const Key& k, std::string_view msg, bool deterministic) {
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    EVP_PKEY_CTX* pctx = nullptr;
    if (EVP_DigestSignInit(ctx.get(), &pctx, EVP_sha256(), nullptr, k.get()) != 1) fail("DigestSignInit");
    if (deterministic) {
#if OPENSSL_VERSION_NUMBER >= 0x30200000L
        unsigned int nonce_type = 1;  // RFC 6979
        OSSL_PARAM params[] = {OSSL_PARAM_construct_uint(OSSL_SIGNATURE_PARAM_NONCE_TYPE, &nonce_type),
                               OSSL_PARAM_construct_end()};
        if (EVP_PKEY_CTX_set_params(pctx, params) != 1) fail("nonce determinístico");
#else
        throw Error("nonce determinístico (RFC 6979) requer OpenSSL >= 3.2");
#endif
    }
    size_t len = 0;
    auto data = reinterpret_cast<const unsigned char*>(msg.data());
    if (EVP_DigestSign(ctx.get(), nullptr, &len, data, msg.size()) != 1) fail("DigestSign (tamanho)");
    Bytes sig(len);
    if (EVP_DigestSign(ctx.get(), sig.data(), &len, data, msg.size()) != 1) fail("DigestSign");
    sig.resize(len);
    return sig;
}

bool verify(const Key& k, std::string_view msg, const Bytes& sig) {
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, k.get()) != 1) fail("DigestVerifyInit");
    int r = EVP_DigestVerify(ctx.get(), sig.data(), sig.size(),
                             reinterpret_cast<const unsigned char*>(msg.data()), msg.size());
    ERR_clear_error();
    return r == 1;
}

std::pair<std::string, std::string> sig_rs_hex(const Bytes& der) {
    const unsigned char* p = der.data();
    ECDSA_SIG* s = d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(der.size()));
    if (!s) return {"?", "?"};
    const BIGNUM *r = nullptr, *ss = nullptr;
    ECDSA_SIG_get0(s, &r, &ss);
    char* rh = BN_bn2hex(r);
    char* sh = BN_bn2hex(ss);
    std::pair<std::string, std::string> out{rh, sh};
    OPENSSL_free(rh);
    OPENSSL_free(sh);
    ECDSA_SIG_free(s);
    return out;
}

Bytes sha256(std::string_view data) {
    Bytes out(32);
    unsigned int n = 0;
    if (EVP_Digest(data.data(), data.size(), out.data(), &n, EVP_sha256(), nullptr) != 1) fail("SHA-256");
    return out;
}

std::string sha256_hex(std::string_view data) {
    auto h = sha256(data);
    return to_hex(h.data(), h.size());
}

std::string b64encode(const Bytes& b) {
    std::string out(4 * ((b.size() + 2) / 3) + 1, '\0');
    int n = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()), b.data(), static_cast<int>(b.size()));
    out.resize(static_cast<size_t>(n));
    return out;
}

Bytes b64decode(const std::string& in) {
    std::string s;
    for (char c : in)
        if (!std::isspace(static_cast<unsigned char>(c))) s += c;
    if (s.size() % 4) throw Error("base64 inválido");
    Bytes out(s.size() / 4 * 3);
    int n = EVP_DecodeBlock(out.data(), reinterpret_cast<const unsigned char*>(s.data()), static_cast<int>(s.size()));
    if (n < 0) throw Error("base64 inválido");
    size_t pad = 0;
    if (!s.empty() && s.back() == '=') ++pad;
    if (s.size() > 1 && s[s.size() - 2] == '=') ++pad;
    out.resize(static_cast<size_t>(n) - pad);
    return out;
}

std::string openssl_version() { return OpenSSL_version(OPENSSL_VERSION); }

}  // namespace ohb::crypto
