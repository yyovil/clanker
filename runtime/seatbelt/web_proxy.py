"""Local web egress broker: resolves and pins public IPs, never serves files."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import select
import socket
import socketserver
import time
from urllib.parse import urlsplit


def public_address(value):
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped:
            address = address.ipv4_mapped
        elif address in ipaddress.ip_network('64:ff9b::/96') or address in ipaddress.ip_network('::ffff:0:0:0/96'):
            address = ipaddress.IPv4Address(int(address) & 0xffffffff)
    return address.is_global and not address.is_multicast and not address.is_reserved


def public_connection(host, port):
    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not addresses or any(not public_address(item[4][0]) for item in addresses):
        raise PermissionError("Private, loopback and special-use destinations are unavailable")
    for family, kind, protocol, _, address in addresses:
        connection = socket.socket(family, kind, protocol)
        connection.settimeout(20)
        try:
            connection.connect(address)
            return connection
        except OSError:
            connection.close()
    raise ConnectionError("Public destination is unavailable")


class Proxy(socketserver.StreamRequestHandler):
    rbufsize = 0
    def handle(self):
        upstream = None
        try:
            line = self.rfile.readline(8193)
            if len(line) > 8192:
                return
            method, target, version = line.decode("ascii").strip().split(" ", 2)
            headers, total = [], 0
            while True:
                line = self.rfile.readline(8193)
                total += len(line)
                if total > 65536 or len(line) > 8192:
                    return
                if line in (b"\r\n", b"\n", b""):
                    break
                headers.append(line)
            if method == "GET" and target == "/__clanker_health":
                body = json.dumps({"pid": os.getpid(), "generation": self.server.generation}).encode()
                self.connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
                return
            parsed = urlsplit("//" + target if method == "CONNECT" else target)
            if not parsed.hostname or parsed.username or parsed.password:
                raise ValueError("Invalid destination")
            if method != "CONNECT" and parsed.scheme != "http":
                raise ValueError("HTTP or CONNECT is required")
            port = parsed.port or (443 if method == "CONNECT" else 80)
            upstream = public_connection(parsed.hostname, port)
            if method == "CONNECT":
                self.connection.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            else:
                path = parsed.path or "/"
                if parsed.query:
                    path += "?" + parsed.query
                kept = [h for h in headers if not h.lower().startswith((b"proxy-", b"connection:"))]
                upstream.sendall(f"{method} {path} {version}\r\n".encode("ascii") + b"".join(kept) + b"Connection: close\r\n\r\n")
            # Avoid buffering request bodies before switching to the tunnel.
            for stream in (self.connection, upstream):
                stream.setblocking(False)
            deadline = time.monotonic() + 300
            while time.monotonic() < deadline:
                readable, _, _ = select.select([self.connection, upstream], [], [], 30)
                if not readable:
                    continue
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        return
                    dest = upstream if source is self.connection else self.connection
                    dest.setblocking(True)
                    dest.settimeout(30)
                    dest.sendall(data)
                    dest.setblocking(False)
        except (OSError, ValueError, PermissionError):
            try:
                self.connection.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
        finally:
            if upstream is not None:
                upstream.close()


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--generation", required=True)
    args = parser.parse_args()
    with Server(("127.0.0.1", 0), Proxy) as server:
        server.generation = args.generation
        value = {"pid": os.getpid(), "port": server.server_address[1], "generation": args.generation}
        args.state.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = args.state.with_suffix(".tmp")
        temporary.write_text(json.dumps(value))
        temporary.chmod(0o600)
        os.replace(temporary, args.state)
        server.serve_forever()


if __name__ == "__main__":
    main()
