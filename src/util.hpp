#pragma once
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace ohb {

struct Error : std::runtime_error {
    using std::runtime_error::runtime_error;
};

std::string read_file(const std::string& path);
bool file_exists(const std::string& path);
// Escrita atômica: grava em <path>.tmp, fsync e rename.
void write_file_atomic(const std::string& path, std::string_view data, unsigned mode = 0644);
void append_file(const std::string& path, std::string_view data, unsigned mode = 0640);
void make_dirs(const std::string& path, unsigned mode = 0755);
std::string dirname_of(const std::string& path);
std::string join_path(const std::string& a, const std::string& b);

std::string now_iso8601();          // UTC, segundos
double monotonic_ms();

std::string to_hex(const unsigned char* p, size_t n);
std::string trim(std::string_view s);
std::vector<std::string> split(std::string_view s, char sep);
bool parse_bool(const std::string& s);

// Lê a passphrase: env OHBOY_PASSPHRASE > arquivo > /dev/tty (sem eco).
std::string read_passphrase(const std::string& prompt, const std::string& file, bool confirm);

}  // namespace ohb
