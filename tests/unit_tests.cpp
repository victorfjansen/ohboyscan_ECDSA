// Testes unitários sem framework externo (rodam nativamente e sob qemu).
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <string>
#include <unistd.h>
#include <vector>

#include "audit.hpp"
#include "crypto.hpp"
#include "json.hpp"
#include "preset.hpp"
#include "routeros_api.hpp"
#include "util.hpp"

using namespace ohb;

static int g_fail = 0, g_pass = 0;
#define CHECK(cond)                                                              \
    do {                                                                         \
        if (cond) ++g_pass;                                                      \
        else {                                                                   \
            ++g_fail;                                                            \
            std::cerr << "  FALHA " << __FILE__ << ":" << __LINE__ << ": " #cond "\n"; \
        }                                                                        \
    } while (0)

static void test(const char* name, const std::function<void()>& fn) {
    std::cout << "- " << name << "\n";
    try {
        fn();
    } catch (const std::exception& e) {
        ++g_fail;
        std::cerr << "  EXCEÇÃO: " << e.what() << "\n";
    }
}

int main() {
    test("API: codificação de comprimento (fronteiras do protocolo)", [] {
        struct C { uint32_t len; std::string enc; };
        std::vector<C> cases = {
            {0, std::string("\x00", 1)},
            {0x7F, "\x7F"},
            {0x80, "\x80\x80"},
            {0x3FFF, "\xBF\xFF"},
            {0x4000, std::string("\xC0\x40\x00", 3)},
            {0x1FFFFF, "\xDF\xFF\xFF"},
            {0x200000, std::string("\xE0\x20\x00\x00", 4)},
            {0xFFFFFFF, "\xEF\xFF\xFF\xFF"},
            {0x10000000, std::string("\xF0\x10\x00\x00\x00", 5)},
        };
        for (auto& c : cases) {
            CHECK(ros::encode_length(c.len) == c.enc);
            uint32_t back = 0;
            auto n = ros::decode_length(reinterpret_cast<const unsigned char*>(c.enc.data()), c.enc.size(), back);
            CHECK(n == c.enc.size());
            CHECK(back == c.len);
        }
        auto s = ros::encode_sentence({"/login", "=name=a"});
        CHECK(s == std::string("\x06/login\x07=name=a\x00", 16));
    });

    test("JSON: serialização canônica é determinística e reversível", [] {
        json::Object o{{"z", "1"}, {"a", json::Array{"x", "\n\"\\\x01"}}, {"m", json::Object{{"b", 2}, {"a", true}}}};
        std::string d1 = json::dump(o);
        json::Value back = json::parse(d1);
        CHECK(back == json::Value(o));
        CHECK(json::dump(back) == d1);
        CHECK(d1.find("\"a\"") < d1.find("\"m\""));  // chaves ordenadas
        CHECK(json::dump(json::Value("\x01"), false) == "\"\\u0001\"");
        CHECK(json::parse("\"\\u00e7\\ud83d\\ude00\"").str() == "ç\xF0\x9F\x98\x80");
        CHECK(json::to_valid_utf8("a\xE7o") == "a\xC3\xA7o");  // Latin-1 -> UTF-8
        CHECK(json::to_valid_utf8("ação") == "ação");
        bool threw = false;
        try { json::parse("{\"a\":1,}"); } catch (...) { threw = true; }
        CHECK(threw);
    });

    test("Crypto: ECDSA P-256 assina/verifica e detecta 1 bit alterado", [] {
        auto k = crypto::generate_p256();
        std::string msg = ":log info \"backup\"; /system backup save name=daily";
        auto sig = crypto::sign(k, msg);
        CHECK(crypto::verify(k, msg, sig));
        std::string m2 = msg;
        m2[5] ^= 0x01;
        CHECK(!crypto::verify(k, m2, sig));
        auto bad = sig;
        bad[bad.size() - 1] ^= 0x01;
        CHECK(!crypto::verify(k, msg, bad));
        // Nonces aleatórios: duas assinaturas da mesma mensagem diferem em r
        auto sig2 = crypto::sign(k, msg);
        CHECK(crypto::sig_rs_hex(sig).first != crypto::sig_rs_hex(sig2).first);
        if (crypto::deterministic_nonce_supported()) {
            CHECK(crypto::sign(k, msg, true) == crypto::sign(k, msg, true));  // RFC 6979
        }
    });

    test("Crypto: PKCS#8 cifrado — passphrase correta/incorreta, Kpub, key_id", [] {
        auto k = crypto::generate_p256();
        auto pem = crypto::private_pem_encrypted(k, "correct horse battery");
        CHECK(pem.find("BEGIN ENCRYPTED PRIVATE KEY") != std::string::npos);
        auto k2 = crypto::load_private_pem(pem, "correct horse battery");
        CHECK(crypto::key_id(k2) == crypto::key_id(k));
        bool threw = false;
        try { crypto::load_private_pem(pem, "wrong"); } catch (...) { threw = true; }
        CHECK(threw);
        auto pub = crypto::load_public_pem(crypto::public_pem(k));
        CHECK(crypto::verify(pub, "m", crypto::sign(k2, "m")));
        CHECK(crypto::b64decode(crypto::b64encode({1, 2, 3, 4})) == crypto::Bytes({1, 2, 3, 4}));
        CHECK(crypto::sha256_hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    });

    test("Diff: detecta campo alterado, item adicionado/removido e reordenação", [] {
        json::Object base{{"/ip/service", json::Array{json::Object{{"name", "telnet"}, {"disabled", "true"}},
                                                      json::Object{{"name", "ssh"}, {"disabled", "false"}}}},
                          {"/ip/firewall/filter",
                           json::Array{json::Object{{".id", "*1"}, {"chain", "input"}, {"action", "accept"}},
                                       json::Object{{".id", "*2"}, {"chain", "input"}, {"action", "drop"}}}}};
        auto none = diff_sections(base, base);
        CHECK(none.empty());

        json::Object cur = base;
        cur["/ip/service"].arr()[0].obj()["disabled"] = "false";
        auto f = diff_sections(base, cur);
        CHECK(f.size() == 1 && f[0].path == "/ip/service[telnet].disabled" && f[0].before == "true" &&
              f[0].after == "false");

        json::Object cur2 = base;
        std::swap(cur2["/ip/firewall/filter"].arr()[0], cur2["/ip/firewall/filter"].arr()[1]);
        auto f2 = diff_sections(base, cur2);
        CHECK(f2.size() == 1 && f2[0].message == "ordem dos itens alterada");

        json::Object cur3 = base;
        cur3["/ip/firewall/filter"].arr().push_back(json::Object{{".id", "*3"}, {"chain", "input"}});
        cur3["/ip/service"].arr().pop_back();
        auto f3 = diff_sections(base, cur3);
        CHECK(f3.size() == 2);
    });

    test("Preset: adulteração local de 1 byte invalida a assinatura", [] {
        char tmpl[] = "/tmp/ohboy-test-XXXXXX";
        std::string dir = ::mkdtemp(tmpl);
        Config cfg;
        cfg.data_dir = dir;
        ::setenv("OHBOY_TEST", "1", 1);
        init_keys(cfg, "alice", "passphrase-123", false);
        auto key = load_operator_private(cfg, "alice", "passphrase-123");
        Snapshot snap;
        snap.sections["/ip/service"] = json::Array{json::Object{{"name", "api"}, {"disabled", "false"}}};
        snap.scripts.push_back(json::Object{{"name", "backup"}, {"source", "/system backup save"}, {"policy", "read"}});
        save_preset(cfg, snap, "alice", key, "teste");
        auto v = verify_local_preset(cfg);
        CHECK(v.valid);
        std::string bytes = read_file(cfg.preset_path());
        auto pos = bytes.find("\"false\"");
        bytes.replace(pos, 7, "\"true\" ");
        write_file_atomic(cfg.preset_path(), bytes);
        auto v2 = verify_local_preset(cfg);
        CHECK(!v2.valid);
        (void)!std::system(("rm -rf '" + dir + "'").c_str());
    });

    std::cout << "\n" << g_pass << " verificações OK, " << g_fail << " falhas\n";
    return g_fail ? 1 : 0;
}
