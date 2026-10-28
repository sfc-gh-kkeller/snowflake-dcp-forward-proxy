#!/usr/bin/env python3
"""Byte-preserving HTTP CONNECT and raw-TLS adapters for a TLS client."""

from __future__ import annotations

import argparse
import base64
import logging
import os
import select
import socket
import socketserver
import sys
from dataclasses import dataclass
from http import HTTPStatus
from urllib.parse import urlsplit

DEFAULT_PROXY_URL = "http://proxy.example.com:8080"
DEFAULT_LISTEN_HOST = "127.0.0.1"
DEFAULT_LISTEN_PORT = 18080
DEFAULT_CONNECT_TIMEOUT = 10.0
DEFAULT_HEADER_TIMEOUT = 10.0
DEFAULT_MAX_HEADER_BYTES = 16 * 1024
DEFAULT_MAX_TARGET_LENGTH = 255
DEFAULT_MAX_TLS_CLIENT_HELLO_BYTES = 64 * 1024


class BridgeError(Exception):
    """A client-facing bridge error."""


class UpstreamProxyError(BridgeError):
    """The enterprise proxy rejected the CONNECT request."""

    def __init__(self, status: int) -> None:
        super().__init__(f"upstream proxy returned HTTP {status}")
        self.status = status


@dataclass(frozen=True)
class ProxyConfig:
    host: str
    port: int
    username: str | None = None
    password: str | None = None


def parse_proxy_url(proxy_url: str) -> ProxyConfig:
    parsed = urlsplit(proxy_url)
    if parsed.scheme.lower() not in {"http"}:
        raise ValueError("proxy URL must use http://")
    if parsed.query or parsed.fragment or not parsed.hostname:
        raise ValueError("proxy URL must contain only an HTTP proxy authority")
    port = parsed.port or 8080
    if not 1 <= port <= 65535:
        raise ValueError("proxy port must be between 1 and 65535")
    if parsed.path not in {"", "/"}:
        raise ValueError("proxy URL must not contain a path")
    return ProxyConfig(
        host=parsed.hostname,
        port=port,
        username=parsed.username,
        password=parsed.password,
    )


def format_authority(host: str, port: int) -> str:
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{host}:{port}"


def parse_target_authority(authority: str, *, allowed_port: int = 443) -> tuple[str, int]:
    authority = authority.strip()
    if not authority or len(authority) > DEFAULT_MAX_TARGET_LENGTH:
        raise BridgeError("invalid CONNECT target")
    if any(char in authority for char in " \t\r\n/@"):
        raise BridgeError("invalid CONNECT target")

    if authority.startswith("["):
        closing = authority.find("]")
        if closing < 0 or closing + 1 >= len(authority) or authority[closing + 1] != ":":
            raise BridgeError("CONNECT target must be host:port")
        host = authority[1:closing]
        port_text = authority[closing + 2 :]
    else:
        host, separator, port_text = authority.rpartition(":")
        if not separator:
            raise BridgeError("CONNECT target must be host:port")

    if not host or not port_text.isdecimal():
        raise BridgeError("CONNECT target must be host:port")
    try:
        port = int(port_text, 10)
    except ValueError as exc:
        raise BridgeError("invalid CONNECT port") from exc
    if port != allowed_port:
        raise BridgeError(f"only port {allowed_port} is allowed")
    if len(host) > 253 or any(ord(char) < 33 or ord(char) > 126 for char in host):
        raise BridgeError("invalid CONNECT host")
    return host, port


def read_headers(sock: socket.socket, *, timeout: float, max_bytes: int) -> bytes:
    sock.settimeout(timeout)
    received = bytearray()
    while b"\r\n\r\n" not in received:
        if len(received) >= max_bytes:
            raise BridgeError("request headers exceed configured limit")
        try:
            chunk = sock.recv(min(4096, max_bytes - len(received)))
        except socket.timeout as exc:
            raise BridgeError("request header timeout") from exc
        if not chunk:
            raise BridgeError("client closed before request headers")
        received.extend(chunk)
    header_end = received.find(b"\r\n\r\n") + 4
    if header_end > max_bytes:
        raise BridgeError("request headers exceed configured limit")
    return bytes(received[:header_end])


def parse_connect_request(request: bytes, *, allowed_port: int = 443) -> str:
    try:
        text = request.decode("iso-8859-1")
    except UnicodeDecodeError as exc:
        raise BridgeError("request headers are not valid HTTP") from exc
    lines = text.split("\r\n")
    if not lines or len(lines[0].split()) != 3:
        raise BridgeError("malformed HTTP request line")
    method, authority, version = lines[0].split()
    if method.upper() != "CONNECT":
        raise BridgeError("only CONNECT is supported")
    if version not in {"HTTP/1.0", "HTTP/1.1"}:
        raise BridgeError("unsupported HTTP version")
    parse_target_authority(authority, allowed_port=allowed_port)
    for line in lines[1:]:
        if not line:
            continue
        if ":" not in line:
            raise BridgeError("malformed HTTP header")
        name, _ = line.split(":", 1)
        if not name or any(ord(char) < 33 or ord(char) > 126 for char in name):
            raise BridgeError("malformed HTTP header")
    return authority


def read_upstream_response(sock: socket.socket, *, timeout: float, max_bytes: int) -> tuple[int, bytes]:
    response = read_headers(sock, timeout=timeout, max_bytes=max_bytes)
    try:
        text = response.decode("iso-8859-1")
    except UnicodeDecodeError as exc:
        raise BridgeError("proxy response is not valid HTTP") from exc
    lines = text.split("\r\n")
    if not lines or len(lines[0].split()) < 2:
        raise BridgeError("malformed proxy response")
    parts = lines[0].split()
    if parts[0] not in {"HTTP/1.0", "HTTP/1.1"} or not parts[1].isdigit():
        raise BridgeError("malformed proxy response")
    return int(parts[1]), response


def _extract_sni_from_client_hello(data: bytes) -> str | None:
    """Return SNI, None for an incomplete ClientHello, or an empty string for no SNI."""
    handshake = bytearray()
    record_offset = 0
    while True:
        if len(data) - record_offset < 5:
            return None
        content_type = data[record_offset]
        record_length = int.from_bytes(data[record_offset + 3 : record_offset + 5], "big")
        record_end = record_offset + 5 + record_length
        if record_end > len(data):
            return None
        if content_type != 0x16:
            raise BridgeError("raw listener expected a TLS handshake record")
        handshake.extend(data[record_offset + 5 : record_end])
        record_offset = record_end

        if len(handshake) < 4:
            continue
        if handshake[0] != 0x01:
            raise BridgeError("raw listener expected a TLS ClientHello")
        hello_length = int.from_bytes(handshake[1:4], "big")
        if len(handshake) < 4 + hello_length:
            continue
        break

    body = handshake[4 : 4 + hello_length]
    if len(body) < 2 + 32 + 1:
        raise BridgeError("malformed TLS ClientHello")

    cursor = 2 + 32
    session_id_length = body[cursor]
    cursor += 1
    if cursor + session_id_length > len(body):
        raise BridgeError("malformed TLS ClientHello session ID")
    cursor += session_id_length
    if cursor + 2 > len(body):
        raise BridgeError("malformed TLS ClientHello cipher suites")
    cipher_suites_length = int.from_bytes(body[cursor : cursor + 2], "big")
    cursor += 2 + cipher_suites_length
    if cursor + 1 > len(body):
        raise BridgeError("malformed TLS ClientHello compression methods")
    compression_methods_length = body[cursor]
    cursor += 1 + compression_methods_length
    if cursor + 2 > len(body):
        raise BridgeError("malformed TLS ClientHello extensions")
    extensions_length = int.from_bytes(body[cursor : cursor + 2], "big")
    cursor += 2
    extensions_end = cursor + extensions_length
    if extensions_end > len(body):
        raise BridgeError("malformed TLS ClientHello extensions")

    while cursor + 4 <= extensions_end:
        extension_type = int.from_bytes(body[cursor : cursor + 2], "big")
        extension_length = int.from_bytes(body[cursor + 2 : cursor + 4], "big")
        cursor += 4
        extension_end = cursor + extension_length
        if extension_end > extensions_end:
            raise BridgeError("malformed TLS ClientHello extension")
        if extension_type == 0x0000:
            server_names = body[cursor:extension_end]
            if len(server_names) < 2:
                raise BridgeError("malformed TLS server name extension")
            names_end = 2 + int.from_bytes(server_names[:2], "big")
            if names_end > len(server_names):
                raise BridgeError("malformed TLS server name list")
            name_cursor = 2
            while name_cursor + 3 <= names_end:
                name_type = server_names[name_cursor]
                name_length = int.from_bytes(server_names[name_cursor + 1 : name_cursor + 3], "big")
                name_cursor += 3
                name_end = name_cursor + name_length
                if name_end > names_end:
                    raise BridgeError("malformed TLS server name")
                if name_type == 0:
                    try:
                        hostname = server_names[name_cursor:name_end].decode("ascii")
                    except UnicodeDecodeError as exc:
                        raise BridgeError("TLS SNI is not ASCII") from exc
                    parse_target_authority(format_authority(hostname, 443))
                    return hostname
                name_cursor = name_end
        cursor = extension_end
    return ""


def read_tls_client_hello(
    sock: socket.socket,
    *,
    timeout: float,
    max_bytes: int,
) -> tuple[bytes, str | None]:
    sock.settimeout(timeout)
    received = bytearray()
    while len(received) < max_bytes:
        try:
            chunk = sock.recv(min(4096, max_bytes - len(received)))
        except socket.timeout as exc:
            raise BridgeError("TLS ClientHello timeout") from exc
        if not chunk:
            raise BridgeError("client closed before TLS ClientHello")
        received.extend(chunk)
        sni = _extract_sni_from_client_hello(bytes(received))
        if sni is not None:
            return bytes(received), sni or None
    raise BridgeError("TLS ClientHello exceeds configured limit")


def open_proxy_tunnel(
    proxy: ProxyConfig,
    authority: str,
    *,
    connect_timeout: float,
    header_timeout: float,
    max_header_bytes: int,
) -> socket.socket:
    upstream = socket.create_connection((proxy.host, proxy.port), timeout=connect_timeout)
    try:
        upstream.settimeout(header_timeout)
        proxy_request = (
            f"CONNECT {authority} HTTP/1.1\r\n"
            f"Host: {authority}\r\n"
            "Connection: keep-alive\r\n"
        )
        if proxy.username is not None:
            credentials = f"{proxy.username}:{proxy.password or ''}".encode("utf-8")
            proxy_request += f"Proxy-Authorization: Basic {base64.b64encode(credentials).decode('ascii')}\r\n"
        upstream.sendall((proxy_request + "\r\n").encode("ascii"))
        status, _ = read_upstream_response(upstream, timeout=header_timeout, max_bytes=max_header_bytes)
        if not 200 <= status < 300:
            raise UpstreamProxyError(status)
        return upstream
    except Exception:
        upstream.close()
        raise


def send_error(client: socket.socket, status: HTTPStatus, message: str) -> None:
    body = f"{status.value} {status.phrase}\n".encode("ascii")
    response = (
        f"HTTP/1.1 {status.value} {status.phrase}\r\n"
        "Connection: close\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Content-Type: text/plain; charset=us-ascii\r\n"
        "\r\n"
    ).encode("ascii") + body
    try:
        client.sendall(response)
    except OSError:
        logging.debug("client disconnected while sending bridge error: %s", message)


def relay_bidirectionally(left: socket.socket, right: socket.socket) -> None:
    sockets = [left, right]
    while sockets:
        readable, _, exceptional = select.select(sockets, [], sockets)
        if exceptional:
            return
        for source in readable:
            try:
                payload = source.recv(64 * 1024)
            except OSError:
                return
            if not payload:
                peer = right if source is left else left
                try:
                    peer.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                sockets.remove(source)
                continue
            destination = right if source is left else left
            try:
                destination.sendall(payload)
            except OSError:
                return


class ConnectBridgeHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        bridge: ConnectBridgeServer = self.server  # type: ignore[assignment]
        client = self.request
        upstream: socket.socket | None = None
        try:
            request = read_headers(
                client,
                timeout=bridge.header_timeout,
                max_bytes=bridge.max_header_bytes,
            )
            authority = parse_connect_request(request, allowed_port=bridge.allowed_port)
            upstream = open_proxy_tunnel(
                bridge.proxy,
                authority,
                connect_timeout=bridge.connect_timeout,
                header_timeout=bridge.header_timeout,
                max_header_bytes=bridge.max_header_bytes,
            )
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            client.settimeout(None)
            upstream.settimeout(None)
            relay_bidirectionally(client, upstream)
        except (BridgeError, OSError, ValueError) as exc:
            logging.info("CONNECT request rejected: %s", type(exc).__name__)
            if isinstance(exc, BridgeError) and str(exc).startswith("only port"):
                send_error(client, HTTPStatus.FORBIDDEN, "CONNECT target is not allowed")
            elif isinstance(exc, BridgeError) and "only CONNECT" in str(exc):
                send_error(client, HTTPStatus.NOT_IMPLEMENTED, "only CONNECT is supported")
            else:
                send_error(client, HTTPStatus.BAD_GATEWAY, "CONNECT bridge failure")
        finally:
            if upstream is not None:
                try:
                    upstream.close()
                except OSError:
                    pass


class TlsPassthroughHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        bridge: TlsPassthroughServer = self.server  # type: ignore[assignment]
        client = self.request
        upstream: socket.socket | None = None
        try:
            initial_bytes, sni = read_tls_client_hello(
                client,
                timeout=bridge.header_timeout,
                max_bytes=bridge.max_tls_client_hello_bytes,
            )
            target = bridge.raw_target or sni
            if not target:
                raise BridgeError("TLS ClientHello did not contain SNI and no raw target was configured")
            target_host, target_port = parse_target_authority(
                format_authority(target, bridge.allowed_port),
                allowed_port=bridge.allowed_port,
            )
            authority = format_authority(target_host, target_port)
            upstream = open_proxy_tunnel(
                bridge.proxy,
                authority,
                connect_timeout=bridge.connect_timeout,
                header_timeout=bridge.header_timeout,
                max_header_bytes=bridge.max_header_bytes,
            )
            upstream.settimeout(None)
            client.settimeout(None)
            upstream.sendall(initial_bytes)
            relay_bidirectionally(client, upstream)
        except (BridgeError, OSError, ValueError) as exc:
            logging.info("raw TLS request rejected: %s", type(exc).__name__)
        finally:
            if upstream is not None:
                try:
                    upstream.close()
                except OSError:
                    pass


class _BridgeServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class ConnectBridgeServer(_BridgeServer):
    def __init__(
        self,
        server_address: tuple[str, int],
        proxy: ProxyConfig,
        *,
        connect_timeout: float,
        header_timeout: float,
        max_header_bytes: int,
        allowed_port: int,
    ) -> None:
        super().__init__(server_address, ConnectBridgeHandler)
        self.proxy = proxy
        self.connect_timeout = connect_timeout
        self.header_timeout = header_timeout
        self.max_header_bytes = max_header_bytes
        self.allowed_port = allowed_port


class TlsPassthroughServer(_BridgeServer):
    def __init__(
        self,
        server_address: tuple[str, int],
        proxy: ProxyConfig,
        *,
        connect_timeout: float,
        header_timeout: float,
        max_header_bytes: int,
        max_tls_client_hello_bytes: int,
        allowed_port: int,
        raw_target: str | None,
    ) -> None:
        super().__init__(server_address, TlsPassthroughHandler)
        self.proxy = proxy
        self.connect_timeout = connect_timeout
        self.header_timeout = header_timeout
        self.max_header_bytes = max_header_bytes
        self.max_tls_client_hello_bytes = max_tls_client_hello_bytes
        self.allowed_port = allowed_port
        self.raw_target = raw_target


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("connect", "tls"), default=os.getenv("DCP_BRIDGE_MODE", "connect"))
    parser.add_argument("--listen-host", default=os.getenv("DCP_BRIDGE_LISTEN_HOST", DEFAULT_LISTEN_HOST))
    parser.add_argument(
        "--listen-port",
        type=int,
        default=int(os.getenv("DCP_BRIDGE_LISTEN_PORT", str(DEFAULT_LISTEN_PORT))),
    )
    parser.add_argument("--proxy-url", default=os.getenv("DCP_BRIDGE_PROXY_URL", DEFAULT_PROXY_URL))
    parser.add_argument("--raw-target", default=os.getenv("DCP_BRIDGE_RAW_TARGET"))
    parser.add_argument("--connect-timeout", type=float, default=DEFAULT_CONNECT_TIMEOUT)
    parser.add_argument("--header-timeout", type=float, default=DEFAULT_HEADER_TIMEOUT)
    parser.add_argument("--max-header-bytes", type=int, default=DEFAULT_MAX_HEADER_BYTES)
    parser.add_argument("--max-tls-client-hello-bytes", type=int, default=DEFAULT_MAX_TLS_CLIENT_HELLO_BYTES)
    parser.add_argument("--allowed-port", type=int, default=443)
    parser.add_argument("--log-level", default=os.getenv("DCP_BRIDGE_LOG_LEVEL", "INFO"))
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not 1 <= args.listen_port <= 65535:
        parser.error("listen port must be between 1 and 65535")
    if args.max_header_bytes < 1024:
        parser.error("max header bytes must be at least 1024")
    if args.max_tls_client_hello_bytes < 4096:
        parser.error("max TLS ClientHello bytes must be at least 4096")
    try:
        proxy = parse_proxy_url(args.proxy_url)
    except ValueError as exc:
        parser.error(str(exc))
    if args.raw_target:
        parse_target_authority(format_authority(args.raw_target, args.allowed_port), allowed_port=args.allowed_port)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
    )
    server: _BridgeServer
    if args.mode == "tls":
        server = TlsPassthroughServer(
            (args.listen_host, args.listen_port),
            proxy,
            connect_timeout=args.connect_timeout,
            header_timeout=args.header_timeout,
            max_header_bytes=args.max_header_bytes,
            max_tls_client_hello_bytes=args.max_tls_client_hello_bytes,
            allowed_port=args.allowed_port,
            raw_target=args.raw_target,
        )
    else:
        server = ConnectBridgeServer(
            (args.listen_host, args.listen_port),
            proxy,
            connect_timeout=args.connect_timeout,
            header_timeout=args.header_timeout,
            max_header_bytes=args.max_header_bytes,
            allowed_port=args.allowed_port,
        )
    logging.info("%s bridge listening on %s:%d", args.mode, args.listen_host, args.listen_port)
    try:
        with server:
            server.serve_forever()
    except KeyboardInterrupt:
        logging.info("bridge stopping")
    return 0


if __name__ == "__main__":
    sys.exit(main())
