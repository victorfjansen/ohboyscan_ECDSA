#include "json.hpp"

#include "util.hpp"

namespace ohb::json {

const std::string& Value::str() const {
    if (auto p = std::get_if<std::string>(&v)) return *p;
    throw Error("JSON: string esperada");
}
int64_t Value::integer() const {
    if (auto p = std::get_if<int64_t>(&v)) return *p;
    throw Error("JSON: inteiro esperado");
}
bool Value::boolean() const {
    if (auto p = std::get_if<bool>(&v)) return *p;
    throw Error("JSON: booleano esperado");
}
const Array& Value::arr() const {
    if (auto p = std::get_if<Array>(&v)) return *p;
    throw Error("JSON: array esperado");
}
Array& Value::arr() {
    if (auto p = std::get_if<Array>(&v)) return *p;
    throw Error("JSON: array esperado");
}
const Object& Value::obj() const {
    if (auto p = std::get_if<Object>(&v)) return *p;
    throw Error("JSON: objeto esperado");
}
Object& Value::obj() {
    if (auto p = std::get_if<Object>(&v)) return *p;
    throw Error("JSON: objeto esperado");
}
const Value* Value::find(const std::string& k) const {
    auto& o = obj();
    auto it = o.find(k);
    return it == o.end() ? nullptr : &it->second;
}
const Value& Value::at(const std::string& k) const {
    if (auto p = find(k)) return *p;
    throw Error("JSON: chave ausente: " + k);
}
std::string Value::get_str(const std::string& k, const std::string& def) const {
    auto p = is_object() ? find(k) : nullptr;
    return (p && p->is_string()) ? p->str() : def;
}

std::string escape_string(const std::string& s) {
    std::string o = "\"";
    for (unsigned char c : s) {
        switch (c) {
            case '"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\b': o += "\\b"; break;
            case '\f': o += "\\f"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof buf, "\\u%04x", c);
                    o += buf;
                } else {
                    o += static_cast<char>(c);
                }
        }
    }
    return o + "\"";
}

static void dump_rec(const Value& v, std::string& out, bool pretty, int depth) {
    auto nl = [&](int d) {
        if (!pretty) return;
        out += '\n';
        out.append(static_cast<size_t>(d) * 2, ' ');
    };
    std::visit(
        [&](auto&& x) {
            using T = std::decay_t<decltype(x)>;
            if constexpr (std::is_same_v<T, std::nullptr_t>) out += "null";
            else if constexpr (std::is_same_v<T, bool>) out += x ? "true" : "false";
            else if constexpr (std::is_same_v<T, int64_t>) out += std::to_string(x);
            else if constexpr (std::is_same_v<T, std::string>) out += escape_string(x);
            else if constexpr (std::is_same_v<T, Array>) {
                if (x.empty()) { out += "[]"; return; }
                out += '[';
                for (size_t i = 0; i < x.size(); ++i) {
                    if (i) out += ',';
                    nl(depth + 1);
                    dump_rec(x[i], out, pretty, depth + 1);
                }
                nl(depth);
                out += ']';
            } else {
                if (x.empty()) { out += "{}"; return; }
                out += '{';
                bool first = true;
                for (auto& [k, val] : x) {
                    if (!first) out += ',';
                    first = false;
                    nl(depth + 1);
                    out += escape_string(k);
                    out += pretty ? ": " : ":";
                    dump_rec(val, out, pretty, depth + 1);
                }
                nl(depth);
                out += '}';
            }
        },
        v.v);
}

std::string dump(const Value& v, bool pretty) {
    std::string out;
    dump_rec(v, out, pretty, 0);
    if (pretty) out += '\n';
    return out;
}

namespace {
struct Parser {
    const std::string& s;
    size_t i = 0;

    [[noreturn]] void fail(const char* what) {
        throw Error(std::string("JSON inválido (") + what + ") na posição " + std::to_string(i));
    }
    void ws() {
        while (i < s.size() && (s[i] == ' ' || s[i] == '\n' || s[i] == '\r' || s[i] == '\t')) ++i;
    }
    bool lit(const char* w) {
        size_t n = std::char_traits<char>::length(w);
        if (s.compare(i, n, w) == 0) { i += n; return true; }
        return false;
    }
    static void put_utf8(std::string& o, uint32_t cp) {
        if (cp < 0x80) o += static_cast<char>(cp);
        else if (cp < 0x800) {
            o += static_cast<char>(0xC0 | (cp >> 6));
            o += static_cast<char>(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            o += static_cast<char>(0xE0 | (cp >> 12));
            o += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            o += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            o += static_cast<char>(0xF0 | (cp >> 18));
            o += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            o += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            o += static_cast<char>(0x80 | (cp & 0x3F));
        }
    }
    uint32_t hex4() {
        if (i + 4 > s.size()) fail("escape \\u truncado");
        uint32_t v = 0;
        for (int k = 0; k < 4; ++k) {
            char c = s[i++];
            v <<= 4;
            if (c >= '0' && c <= '9') v |= static_cast<uint32_t>(c - '0');
            else if (c >= 'a' && c <= 'f') v |= static_cast<uint32_t>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') v |= static_cast<uint32_t>(c - 'A' + 10);
            else fail("hex inválido");
        }
        return v;
    }
    std::string string() {
        if (s[i] != '"') fail("string esperada");
        ++i;
        std::string o;
        while (true) {
            if (i >= s.size()) fail("string não terminada");
            char c = s[i++];
            if (c == '"') break;
            if (static_cast<unsigned char>(c) < 0x20) fail("caractere de controle em string");
            if (c != '\\') { o += c; continue; }
            if (i >= s.size()) fail("escape truncado");
            char e = s[i++];
            switch (e) {
                case '"': o += '"'; break;
                case '\\': o += '\\'; break;
                case '/': o += '/'; break;
                case 'b': o += '\b'; break;
                case 'f': o += '\f'; break;
                case 'n': o += '\n'; break;
                case 'r': o += '\r'; break;
                case 't': o += '\t'; break;
                case 'u': {
                    uint32_t cp = hex4();
                    if (cp >= 0xD800 && cp < 0xDC00 && lit("\\u")) {
                        uint32_t lo = hex4();
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    }
                    put_utf8(o, cp);
                    break;
                }
                default: fail("escape desconhecido");
            }
        }
        return o;
    }
    Value value(int depth) {
        if (depth > 64) fail("aninhamento excessivo");
        ws();
        if (i >= s.size()) fail("fim inesperado");
        char c = s[i];
        if (c == '{') {
            ++i;
            Object o;
            ws();
            if (s[i] == '}') { ++i; return o; }
            while (true) {
                ws();
                std::string k = string();
                ws();
                if (s[i++] != ':') fail("':' esperado");
                o[k] = value(depth + 1);
                ws();
                if (s[i] == ',') { ++i; continue; }
                if (s[i] == '}') { ++i; break; }
                fail("',' ou '}' esperado");
            }
            return o;
        }
        if (c == '[') {
            ++i;
            Array a;
            ws();
            if (s[i] == ']') { ++i; return a; }
            while (true) {
                a.push_back(value(depth + 1));
                ws();
                if (s[i] == ',') { ++i; continue; }
                if (s[i] == ']') { ++i; break; }
                fail("',' ou ']' esperado");
            }
            return a;
        }
        if (c == '"') return string();
        if (lit("true")) return true;
        if (lit("false")) return false;
        if (lit("null")) return nullptr;
        if (c == '-' || (c >= '0' && c <= '9')) {
            size_t st = i;
            if (s[i] == '-') ++i;
            while (i < s.size() && s[i] >= '0' && s[i] <= '9') ++i;
            if (i < s.size() && (s[i] == '.' || s[i] == 'e' || s[i] == 'E')) fail("apenas inteiros são suportados");
            return static_cast<int64_t>(std::stoll(s.substr(st, i - st)));
        }
        fail("valor esperado");
    }
};
}  // namespace

Value parse(const std::string& text) {
    Parser p{text};
    Value v = p.value(0);
    p.ws();
    if (p.i != text.size()) p.fail("dados após o fim");
    return v;
}

std::string to_valid_utf8(const std::string& s) {
    std::string o;
    o.reserve(s.size());
    size_t i = 0;
    auto cont = [&](size_t k) { return k < s.size() && (static_cast<unsigned char>(s[k]) & 0xC0) == 0x80; };
    while (i < s.size()) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        size_t len = 0;
        if (c < 0x80) len = 1;
        else if ((c & 0xE0) == 0xC0 && c >= 0xC2) len = 2;
        else if ((c & 0xF0) == 0xE0) len = 3;
        else if ((c & 0xF8) == 0xF0 && c <= 0xF4) len = 4;
        bool ok = len > 0;
        for (size_t k = 1; ok && k < len; ++k) ok = cont(i + k);
        if (ok) {
            o.append(s, i, len);
            i += len;
        } else {  // Latin-1 -> UTF-8
            o += static_cast<char>(0xC0 | (c >> 6));
            o += static_cast<char>(0x80 | (c & 0x3F));
            ++i;
        }
    }
    return o;
}

}  // namespace ohb::json
