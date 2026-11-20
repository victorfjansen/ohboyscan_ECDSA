#include "util.hpp"

#include <cctype>
#include <cstdio>
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

namespace ohb {

std::string read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw Error("não foi possível ler " + path + ": " + std::strerror(errno));
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

bool file_exists(const std::string& path) {
    struct stat st{};
    return ::stat(path.c_str(), &st) == 0;
}

static void write_all(int fd, std::string_view data, const std::string& path) {
    size_t off = 0;
    while (off < data.size()) {
        ssize_t n = ::write(fd, data.data() + off, data.size() - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            throw Error("falha ao escrever " + path + ": " + std::strerror(errno));
        }
        off += static_cast<size_t>(n);
    }
}

void write_file_atomic(const std::string& path, std::string_view data, unsigned mode) {
    std::string tmp = path + ".tmp";
    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0) throw Error("não foi possível criar " + tmp + ": " + std::strerror(errno));
    write_all(fd, data, tmp);
    ::fchmod(fd, mode);
    ::fsync(fd);
    ::close(fd);
    if (::rename(tmp.c_str(), path.c_str()) != 0)
        throw Error("falha no rename para " + path + ": " + std::strerror(errno));
}

void append_file(const std::string& path, std::string_view data, unsigned mode) {
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, mode);
    if (fd < 0) throw Error("não foi possível abrir " + path + ": " + std::strerror(errno));
    write_all(fd, data, path);
    ::fsync(fd);
    ::close(fd);
}

void make_dirs(const std::string& path, unsigned mode) {
    if (path.empty()) return;
    std::string cur;
    for (size_t i = 0; i <= path.size(); ++i) {
        if (i == path.size() || path[i] == '/') {
            if (!cur.empty() && !file_exists(cur)) {
                if (::mkdir(cur.c_str(), mode) != 0 && errno != EEXIST)
                    throw Error("mkdir " + cur + ": " + std::strerror(errno));
            }
        }
        if (i < path.size()) cur += path[i];
    }
}

std::string dirname_of(const std::string& path) {
    auto p = path.find_last_of('/');
    if (p == std::string::npos) return ".";
    if (p == 0) return "/";
    return path.substr(0, p);
}

std::string join_path(const std::string& a, const std::string& b) {
    if (a.empty()) return b;
    if (a.back() == '/') return a + b;
    return a + "/" + b;
}

std::string now_iso8601() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

double monotonic_ms() {
    using namespace std::chrono;
    return duration<double, std::milli>(steady_clock::now().time_since_epoch()).count();
}

std::string to_hex(const unsigned char* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        s += d[p[i] >> 4];
        s += d[p[i] & 0xf];
    }
    return s;
}

std::string trim(std::string_view s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return std::string(s.substr(b, e - b));
}

std::vector<std::string> split(std::string_view s, char sep) {
    std::vector<std::string> out;
    size_t start = 0;
    for (size_t i = 0; i <= s.size(); ++i) {
        if (i == s.size() || s[i] == sep) {
            auto t = trim(s.substr(start, i - start));
            if (!t.empty()) out.push_back(t);
            start = i + 1;
        }
    }
    return out;
}

bool parse_bool(const std::string& s) {
    return s == "1" || s == "true" || s == "yes" || s == "on";
}

static std::string read_tty_line(const std::string& prompt) {
    int fd = ::open("/dev/tty", O_RDWR | O_CLOEXEC);
    if (fd < 0) throw Error("sem terminal para ler a passphrase (use --passphrase-file ou OHBOY_PASSPHRASE)");
    (void)!::write(fd, prompt.data(), prompt.size());
    termios old{};
    bool have_tc = ::tcgetattr(fd, &old) == 0;
    if (have_tc) {
        termios noecho = old;
        noecho.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        ::tcsetattr(fd, TCSAFLUSH, &noecho);
    }
    std::string line;
    char c;
    while (::read(fd, &c, 1) == 1 && c != '\n') line += c;
    if (have_tc) ::tcsetattr(fd, TCSAFLUSH, &old);
    (void)!::write(fd, "\n", 1);
    ::close(fd);
    return line;
}

std::string read_passphrase(const std::string& prompt, const std::string& file, bool confirm) {
    if (const char* env = std::getenv("OHBOY_PASSPHRASE")) return env;
    if (!file.empty()) {
        std::string s = read_file(file);
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
        return s;
    }
    std::string p = read_tty_line(prompt);
    if (confirm) {
        if (p.size() < 8) throw Error("a passphrase deve ter ao menos 8 caracteres");
        if (read_tty_line("Confirme a passphrase: ") != p) throw Error("as passphrases não conferem");
    }
    return p;
}

}  // namespace ohb
