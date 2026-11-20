#include "alert.hpp"

#include <csignal>
#include <cstdlib>
#include <iostream>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

#include "util.hpp"

namespace ohb {

static void run_command(const std::string& cmd, const std::string& payload, const AuditReport& rep) {
    int pipefd[2];
    if (::pipe(pipefd) != 0) return;
    pid_t pid = ::fork();
    if (pid < 0) return;
    if (pid == 0) {
        ::dup2(pipefd[0], STDIN_FILENO);
        ::close(pipefd[0]);
        ::close(pipefd[1]);
        ::setenv("OHBOY_STATUS", rep.clean() ? "OK" : "ALERT", 1);
        ::setenv("OHBOY_HOST", rep.host.c_str(), 1);
        ::setenv("OHBOY_FINDINGS", std::to_string(rep.findings.size()).c_str(), 1);
        ::execl("/bin/sh", "sh", "-c", cmd.c_str(), static_cast<char*>(nullptr));
        ::_exit(127);
    }
    ::close(pipefd[0]);
    auto old = std::signal(SIGPIPE, SIG_IGN);
    (void)!::write(pipefd[1], payload.data(), payload.size());
    ::close(pipefd[1]);
    int st = 0;
    ::waitpid(pid, &st, 0);
    std::signal(SIGPIPE, old);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
        std::cerr << "aviso: alert.command terminou com status " << WEXITSTATUS(st) << "\n";
}

void emit_alerts(const Config& cfg, const AuditReport& rep) {
    std::string line = json::dump(rep.to_json(), false);
    if (!cfg.log_file.empty()) {
        try {
            make_dirs(dirname_of(cfg.log_file), 0750);
            append_file(cfg.log_file, line + "\n", 0640);
        } catch (const std::exception& e) {
            std::cerr << "aviso: não foi possível gravar log: " << e.what() << "\n";
        }
    }
    if (cfg.alert_syslog) {
        ::openlog("ohboyscan", LOG_PID, LOG_AUTHPRIV);
        if (rep.clean()) {
            ::syslog(LOG_INFO, "audit OK host=%s items=%zu scripts=%zu", rep.host.c_str(), rep.items_checked,
                     rep.scripts_checked);
        } else {
            for (auto& f : rep.findings)
                ::syslog(f.severity == Severity::Critical ? LOG_ALERT : LOG_WARNING, "%s %s: %s %s",
                         severity_name(f.severity), f.category.c_str(), f.message.c_str(), f.path.c_str());
        }
        ::closelog();
    }
    if (!cfg.alert_command.empty() && (!rep.clean() || cfg.alert_on_ok)) run_command(cfg.alert_command, line + "\n", rep);
}

}  // namespace ohb
