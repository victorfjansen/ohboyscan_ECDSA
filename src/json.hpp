#pragma once
// JSON mínimo com serialização canônica:
//  - chaves de objetos ordenadas por bytes (std::map)
//  - indentação fixa de 2 espaços, separador ": ", LF, sem espaço final
//  - strings UTF-8; escapes fixos (\" \\ \b \f \n \r \t e \u00xx para < 0x20)
//  - números inteiros (int64) apenas
// O mesmo valor lógico produz sempre os mesmos bytes, o que permite assinar o arquivo.
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <variant>
#include <vector>

namespace ohb::json {

struct Value;
using Array = std::vector<Value>;
using Object = std::map<std::string, Value>;

struct Value {
    std::variant<std::nullptr_t, bool, int64_t, std::string, Array, Object> v;

    Value() : v(nullptr) {}
    Value(std::nullptr_t) : v(nullptr) {}
    Value(bool b) : v(b) {}
    Value(int i) : v(static_cast<int64_t>(i)) {}
    Value(int64_t i) : v(i) {}
    Value(const char* s) : v(std::string(s)) {}
    Value(std::string s) : v(std::move(s)) {}
    Value(Array a) : v(std::move(a)) {}
    Value(Object o) : v(std::move(o)) {}

    bool is_null() const { return std::holds_alternative<std::nullptr_t>(v); }
    bool is_string() const { return std::holds_alternative<std::string>(v); }
    bool is_array() const { return std::holds_alternative<Array>(v); }
    bool is_object() const { return std::holds_alternative<Object>(v); }

    const std::string& str() const;
    int64_t integer() const;
    bool boolean() const;
    const Array& arr() const;
    Array& arr();
    const Object& obj() const;
    Object& obj();

    const Value& at(const std::string& k) const;   // lança se ausente
    const Value* find(const std::string& k) const; // nullptr se ausente
    std::string get_str(const std::string& k, const std::string& def = "") const;

    bool operator==(const Value& o) const { return v == o.v; }
    bool operator!=(const Value& o) const { return !(*this == o); }
};

std::string dump(const Value& v, bool pretty = true);
Value parse(const std::string& text);
std::string escape_string(const std::string& s);
// Converte bytes arbitrários em UTF-8 válido (bytes inválidos interpretados como Latin-1).
std::string to_valid_utf8(const std::string& s);

}  // namespace ohb::json
