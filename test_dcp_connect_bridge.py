from __future__ import annotations

import socket
import socketserver
import threading
import unittest
from contextlib import contextmanager

from dcp_connect_bridge import (
    BridgeError,
    ConnectBridgeServer,
    ProxyConfig,
    TlsPassthroughServer,
    parse_connect_request,
    parse_proxy_url,
    parse_target_authority,
)


class ScriptedProxyHandler(socketserver.BaseRequestHandler):
    response_status = 200
    response_headers = b""
    payload_prefix = b""
    received_connect = None

    def handle(self):
        request = read_until_headers(self.request)
        self.__class__.received_connect = request
        response = f"HTTP/1.1 {self.response_status} Test\r\n".encode("ascii") + self.response_headers + b"\r\n"
        self.request.sendall(response)
        if self.response_status // 100 == 2:
            payload = self.request.recv(4096)
            self.request.sendall(self.payload_prefix + payload)


def read_until_headers(sock: socket.socket) -> bytes:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
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
    body = (
        b"\x03\x03"
        + b"\x00" * 32
        + b"\x00"
        + b"\x00\x02\x13\x01"
        + b"\x01\x00"
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


class BridgeTests(unittest.TestCase):
    def test_parse_proxy_url_rejects_non_http_and_accepts_auth(self):
        self.assertEqual(parse_proxy_url("http://proxy.example.com:8080"), ProxyConfig("proxy.example.com", 8080))
        self.assertEqual(parse_proxy_url("http://user:pass@localhost"), ProxyConfig("localhost", 8080, "user", "pass"))
        with self.assertRaises(ValueError):
            parse_proxy_url("https://proxy.example.com:8080")
        with self.assertRaises(ValueError):
            parse_proxy_url("http://proxy.example.com:8080/path")

    def test_target_parser_allows_only_443(self):
        self.assertEqual(parse_target_authority("example.com:443"), ("example.com", 443))
        self.assertEqual(parse_target_authority("[::1]:443"), ("::1", 443))
        with self.assertRaises(BridgeError):
            parse_target_authority("example.com:27017")
        with self.assertRaises(BridgeError):
            parse_target_authority("example.com")

    def test_connect_request_requires_connect(self):
        authority = parse_connect_request(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        self.assertEqual(authority, "example.com:443")
        with self.assertRaises(BridgeError):
            parse_connect_request(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

    def test_bridge_preserves_opaque_payload(self):
        ScriptedProxyHandler.response_status = 200
        ScriptedProxyHandler.response_headers = b""
        ScriptedProxyHandler.payload_prefix = b"upstream:"
        ScriptedProxyHandler.received_connect = None
        proxy_server = LocalServer(("127.0.0.1", 0), ScriptedProxyHandler)
        with running_server(proxy_server) as proxy_address:
            bridge_server = ConnectBridgeServer(
                ("127.0.0.1", 0),
                ProxyConfig(*proxy_address),
                connect_timeout=2,
                header_timeout=2,
                max_header_bytes=4096,
                allowed_port=443,
            )
            with running_server(bridge_server) as bridge_address:
                with socket.create_connection(bridge_address, timeout=2) as client:
                    client.sendall(b"CONNECT dcp.example.test:443 HTTP/1.1\r\nHost: dcp.example.test:443\r\n\r\n")
                    self.assertTrue(read_until_headers(client).startswith(b"HTTP/1.1 200"))
                    opaque = b"\x00\x01TLS-like\xff"
                    client.sendall(opaque)
                    client.shutdown(socket.SHUT_WR)
                    self.assertEqual(client.recv(4096), b"upstream:" + opaque)
        self.assertIsNotNone(ScriptedProxyHandler.received_connect)
        self.assertTrue(ScriptedProxyHandler.received_connect.startswith(b"CONNECT dcp.example.test:443 HTTP/1.1"))

    def test_tls_mode_extracts_sni_and_preserves_client_hello(self):
        ScriptedProxyHandler.response_status = 200
        ScriptedProxyHandler.response_headers = b""
        ScriptedProxyHandler.payload_prefix = b"proxy:"
        ScriptedProxyHandler.received_connect = None
        proxy_server = LocalServer(("127.0.0.1", 0), ScriptedProxyHandler)
        client_hello = make_tls_client_hello("dcp.example.test")
        with running_server(proxy_server) as proxy_address:
            bridge_server = TlsPassthroughServer(
                ("127.0.0.1", 0),
                ProxyConfig(*proxy_address),
                connect_timeout=2,
                header_timeout=2,
                max_header_bytes=4096,
                max_tls_client_hello_bytes=4096,
                allowed_port=443,
                raw_target=None,
            )
            with running_server(bridge_server) as bridge_address:
                with socket.create_connection(bridge_address, timeout=2) as client:
                    client.sendall(client_hello)
                    self.assertEqual(client.recv(4096), b"proxy:" + client_hello)
        self.assertIsNotNone(ScriptedProxyHandler.received_connect)
        self.assertTrue(ScriptedProxyHandler.received_connect.startswith(b"CONNECT dcp.example.test:443 HTTP/1.1"))

    def test_bridge_rejects_non_443_without_contacting_proxy(self):
        ScriptedProxyHandler.received_connect = None
        proxy_server = LocalServer(("127.0.0.1", 0), ScriptedProxyHandler)
        with running_server(proxy_server) as proxy_address:
            bridge_server = ConnectBridgeServer(
                ("127.0.0.1", 0),
                ProxyConfig(*proxy_address),
                connect_timeout=2,
                header_timeout=2,
                max_header_bytes=4096,
                allowed_port=443,
            )
            with running_server(bridge_server) as bridge_address:
                with socket.create_connection(bridge_address, timeout=2) as client:
                    client.sendall(b"CONNECT db.example.test:27017 HTTP/1.1\r\nHost: db.example.test:27017\r\n\r\n")
                    self.assertTrue(read_until_headers(client).startswith(b"HTTP/1.1 403"))
        self.assertIsNone(ScriptedProxyHandler.received_connect)

    def test_bridge_maps_upstream_407_to_bad_gateway(self):
        ScriptedProxyHandler.response_status = 407
        ScriptedProxyHandler.response_headers = b"Proxy-Authenticate: Basic realm=test\r\n"
        ScriptedProxyHandler.received_connect = None
        proxy_server = LocalServer(("127.0.0.1", 0), ScriptedProxyHandler)
        with running_server(proxy_server) as proxy_address:
            bridge_server = ConnectBridgeServer(
                ("127.0.0.1", 0),
                ProxyConfig(*proxy_address),
                connect_timeout=2,
                header_timeout=2,
                max_header_bytes=4096,
                allowed_port=443,
            )
            with running_server(bridge_server) as bridge_address:
                with socket.create_connection(bridge_address, timeout=2) as client:
                    client.sendall(b"CONNECT dcp.example.test:443 HTTP/1.1\r\nHost: dcp.example.test:443\r\n\r\n")
                    self.assertTrue(read_until_headers(client).startswith(b"HTTP/1.1 502"))
        self.assertIsNotNone(ScriptedProxyHandler.received_connect)

    def test_bridge_rejects_oversized_headers(self):
        proxy_server = LocalServer(("127.0.0.1", 0), ScriptedProxyHandler)
        with running_server(proxy_server) as proxy_address:
            bridge_server = ConnectBridgeServer(
                ("127.0.0.1", 0),
                ProxyConfig(*proxy_address),
                connect_timeout=2,
                header_timeout=2,
                max_header_bytes=1024,
                allowed_port=443,
            )
            with running_server(bridge_server) as bridge_address:
                with socket.create_connection(bridge_address, timeout=2) as client:
                    client.sendall(b"CONNECT dcp.example.test:443 HTTP/1.1\r\nX-Long: " + b"a" * 2000 + b"\r\n\r\n")
                    self.assertTrue(read_until_headers(client).startswith(b"HTTP/1.1 502"))


if __name__ == "__main__":
    unittest.main()
