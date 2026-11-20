#!/usr/bin/env python3
"""Servidor simulado da API do RouterOS (protocolo binário, porta 8728/8729).

Permite validar o OhBoyScan sem hardware (e em binários ARM sob qemu).
O estado é lido de um arquivo JSON a CADA comando, de modo que os cenários de
teste alteram o "roteador" simplesmente reescrevendo esse arquivo.

Formato do estado: {"/ip/service": [{".id": "*1", "name": "telnet", ...}], ...}
Uso: mock_routeros.py --state estado.json [--port 18728] [--user u --password p]
                      [--tls-cert cert.pem --tls-key key.pem]
"""
import argparse
import json
import socket
import socketserver
import ssl
import sys
import threading


def enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x4000:
        return (n | 0x8000).to_bytes(2, "big")
    if n < 0x200000:
        return (n | 0xC00000).to_bytes(3, "big")
    if n < 0x10000000:
        return (n | 0xE0000000).to_bytes(4, "big")
    return b"\xF0" + n.to_bytes(4, "big")


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError
        buf += chunk
    return buf


def read_word(sock) -> bytes:
    c = recv_exact(sock, 1)[0]
    if c < 0x80:
        n = c
    elif c < 0xC0:
        n = ((c & 0x3F) << 8) | recv_exact(sock, 1)[0]
    elif c < 0xE0:
        n = ((c & 0x1F) << 16) | int.from_bytes(recv_exact(sock, 2), "big")
    elif c < 0xF0:
        n = ((c & 0x0F) << 24) | int.from_bytes(recv_exact(sock, 3), "big")
    else:
        n = int.from_bytes(recv_exact(sock, 4), "big")
    return recv_exact(sock, n) if n else b""


def read_sentence(sock):
    words = []
    while True:
        w = read_word(sock)
        if not w:
            return words
        words.append(w.decode("utf-8", "surrogateescape"))


def send_sentence(sock, words):
    out = b""
    for w in words:
        b = w.encode("utf-8", "surrogateescape")
        out += enc_len(len(b)) + b
    sock.sendall(out + b"\x00")


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        cfg = self.server.cfg
        sock = self.request
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        logged = False
        try:
            while True:
                s = read_sentence(sock)
                if not s:
                    continue
                cmd = s[0]
                attrs = {w[1:].split("=", 1)[0]: w[1:].split("=", 1)[1] for w in s[1:] if w.startswith("=")}
                if cmd == "/login":
                    if attrs.get("name") == cfg.user and attrs.get("password") == cfg.password:
                        logged = True
                        send_sentence(sock, ["!done"])
                    else:
                        send_sentence(sock, ["!trap", "=message=invalid user name or password (6)"])
                        send_sentence(sock, ["!done"])
                    continue
                if not logged:
                    send_sentence(sock, ["!fatal", "not logged in"])
                    return
                if cmd.endswith("/print"):
                    path = cmd[: -len("/print")]
                    with open(cfg.state) as f:
                        state = json.load(f)
                    if path not in state:
                        send_sentence(sock, ["!trap", "=message=no such command prefix"])
                        send_sentence(sock, ["!done"])
                        continue
                    for item in state[path]:
                        send_sentence(sock, ["!re"] + [f"={k}={v}" for k, v in item.items()])
                    send_sentence(sock, ["!done"])
                else:
                    send_sentence(sock, ["!trap", "=message=no such command"])
                    send_sentence(sock, ["!done"])
        except (EOFError, ConnectionError, ssl.SSLError):
            return


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, cfg):
        self.cfg = cfg
        super().__init__((cfg.bind, cfg.port), Handler)
        if cfg.tls_cert:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cfg.tls_cert, cfg.tls_key)
            self.socket = ctx.wrap_socket(self.socket, server_side=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--state", required=True)
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18728)
    ap.add_argument("--user", default="ohboyscan")
    ap.add_argument("--password", default="audit-pass")
    ap.add_argument("--tls-cert")
    ap.add_argument("--tls-key")
    cfg = ap.parse_args()
    srv = Server(cfg)
    print(f"mock RouterOS API em {cfg.bind}:{cfg.port}{' (TLS)' if cfg.tls_cert else ''}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
