#!/usr/bin/env python3
"""Local CONNECT proxy used only for the bridge integration harness."""

from __future__ import annotations

import argparse
import logging
import select
import socket
import socketserver


class ProxyError(Exception):
    pass


def read_headers(sock: socket.socket, max_bytes: int) -> bytes:
    received = bytearray()
    while b"\r\n\r\n" not in received:
        if len(received) >= max_bytes:
            raise ProxyError("headers too large")
        chunk = sock.recv(min(4096, max_bytes - len(received)))
        if not chunk:
            raise ProxyError("client closed before headers")
        received.extend(chunk)
    return bytes(received)


def parse_connect(request: bytes) -> tuple[str, int]:
    line = request.split(b"\r\n", 1)[0].decode("ascii")
    method, authority, version = line.split()
    if method != "CONNECT" or version not in {"HTTP/1.0", "HTTP/1.1"}:
        raise ProxyError("only HTTP CONNECT is supported")
    host, separator, port_text = authority.rpartition(":")
    if not separator or not host or not port_text.isdecimal():
        raise ProxyError("target must be host:port")
    port = int(port_text)
    if port != 443:
        raise ProxyError("only port 443 is allowed")
    return host, port


def relay(left: socket.socket, right: socket.socket) -> None:
    sockets = [left, right]
    while sockets:
        readable, _, exceptional = select.select(sockets, [], sockets)
        if exceptional:
            return
        for source in readable:
            data = source.recv(65536)
            if not data:
                peer = right if source is left else left
                try:
                    peer.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                sockets.remove(source)
                continue
            (right if source is left else left).sendall(data)


class Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        upstream = None
        try:
            host, port = parse_connect(read_headers(self.request, 16384))
            logging.info("CONNECT target=%s:%d", host, port)
            upstream = socket.create_connection((host, port), timeout=10)
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self.request.settimeout(None)
            upstream.settimeout(None)
            relay(self.request, upstream)
        except Exception as exc:
            logging.info("CONNECT failed: %s", type(exc).__name__)
            try:
                self.request.sendall(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
        finally:
            if upstream is not None:
                upstream.close()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", type=int, default=8080)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    with Server((args.listen_host, args.listen_port), Handler) as server:
        logging.info("local CONNECT proxy listening on %s:%d", args.listen_host, args.listen_port)
        server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
