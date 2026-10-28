#!/usr/bin/env python3
"""Run a local raw-TLS bridge through a scripted HTTP CONNECT proxy."""

from __future__ import annotations

import argparse
import socket
import socketserver
import threading
from contextlib import contextmanager

from dcp_connect_bridge import ProxyConfig, TlsPassthroughServer


class ScriptedConnectProxyHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        request = self._read_headers()
        if not request.startswith(b"CONNECT "):
            self.request.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            return
        self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        while True:
            payload = self.request.recv(65536)
            if not payload:
                return
            self.request.sendall(payload)

    def _read_headers(self) -> bytes:
        data = bytearray()
        while b"\r\n\r\n" not in data:
            chunk = self.request.recv(4096)
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data)


class LocalServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


@contextmanager
def running_server(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def make_tls_client_hello(hostname: str) -> bytes:
    host_bytes = hostname.encode("ascii")
    server_name = b"\x00" + len(host_bytes).to_bytes(2, "big") + host_bytes
    server_names = len(server_name).to_bytes(2, "big") + server_name
    extension = b"\x00\x00" + len(server_names).to_bytes(2, "big") + server_names
    extensions = len(extension).to_bytes(2, "big") + extension
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + extensions
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="dcp.example.test")
    args = parser.parse_args()

    proxy = LocalServer(("127.0.0.1", 0), ScriptedConnectProxyHandler)
    with running_server(proxy) as proxy_address:
        bridge = TlsPassthroughServer(
            ("127.0.0.1", 0),
            proxy=ProxyConfig(*proxy_address),
            connect_timeout=2,
            header_timeout=2,
            max_header_bytes=4096,
            max_tls_client_hello_bytes=4096,
            allowed_port=443,
            raw_target=None,
        )
        with running_server(bridge) as bridge_address:
            client_hello = make_tls_client_hello(args.target)
            with socket.create_connection(bridge_address, timeout=2) as client:
                client.sendall(client_hello)
                received = client.recv(len(client_hello))
            if received != client_hello:
                raise SystemExit("raw TLS bridge did not preserve the ClientHello")
            print(f"raw TLS ClientHello preserved through local CONNECT proxy; target={args.target}:443")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
