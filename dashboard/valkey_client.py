"""
valkey_client.py — Minimal synchronous RESP2 client for Valkey/Redis.
No external dependencies; uses only stdlib socket.
Thread-safe via per-call connection pooling.
"""
import socket
import threading
from typing import Any

_lock = threading.Lock()
_pool: list = []
_MAX_POOL = 4


class ValkeyError(Exception):
    pass


class _Conn:
    def __init__(self, host: str, port: int, password: str = ""):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(5)
        self.sock.connect((host, port))
        self._buf = b""
        if password:
            self._cmd("AUTH", password)

    def _send(self, *args):
        parts = [f"*{len(args)}\r\n".encode()]
        for a in args:
            s = str(a).encode()
            parts.append(f"${len(s)}\r\n".encode())
            parts.append(s)
            parts.append(b"\r\n")
        self.sock.sendall(b"".join(parts))

    def _read_line(self) -> bytes:
        while b"\r\n" not in self._buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ValkeyError("Connection closed")
            self._buf += chunk
        line, self._buf = self._buf.split(b"\r\n", 1)
        return line

    def _parse(self) -> Any:
        line = self._read_line()
        t, data = chr(line[0]), line[1:].decode()
        if t == "+":
            return data
        if t == "-":
            raise ValkeyError(data)
        if t == ":":
            return int(data)
        if t == "$":
            n = int(data)
            if n == -1:
                return None
            val = b""
            while len(val) < n + 2:
                val += self.sock.recv(n + 2 - len(val))
            return val[:-2].decode(errors="replace")
        if t == "*":
            n = int(data)
            if n == -1:
                return None
            return [self._parse() for _ in range(n)]
        raise ValkeyError(f"Unknown type: {t}")

    def _cmd(self, *args) -> Any:
        self._send(*args)
        return self._parse()

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


class ValkeyClient:
    def __init__(self, host="127.0.0.1", port=6379, password=""):
        self.host = host
        self.port = port
        self.password = password
        self._local = threading.local()

    def _get_conn(self) -> _Conn:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = _Conn(self.host, self.port, self.password)
            self._local.conn = conn
        return conn

    def _exec(self, *args) -> Any:
        try:
            return self._get_conn()._cmd(*args)
        except Exception:
            # Reconnect once on failure
            try:
                self._local.conn = _Conn(self.host, self.port, self.password)
                return self._local.conn._cmd(*args)
            except Exception as e:
                raise ValkeyError(str(e))

    # ── High-level API ────────────────────────────────────────────────────
    def ping(self) -> bool:
        try:
            return self._exec("PING") == "PONG"
        except Exception:
            return False

    def get(self, key: str) -> str | None:
        return self._exec("GET", key)

    def set(self, key: str, value: str, ex: int = 0) -> bool:
        if ex:
            return self._exec("SET", key, value, "EX", ex) == "OK"
        return self._exec("SET", key, value) == "OK"

    def delete(self, *keys: str) -> int:
        return self._exec("DEL", *keys)

    def keys(self, pattern: str = "*") -> list[str]:
        result = self._exec("KEYS", pattern)
        return result or []

    def ttl(self, key: str) -> int:
        return self._exec("TTL", key)

    def lrange(self, key: str, start=0, stop=-1) -> list[str]:
        result = self._exec("LRANGE", key, start, stop)
        return result or []

    def llen(self, key: str) -> int:
        return self._exec("LLEN", key)

    def info(self) -> dict:
        raw = self._exec("INFO", "all")
        result = {}
        if not raw:
            return result
        for line in raw.splitlines():
            if ":" in line and not line.startswith("#"):
                k, _, v = line.partition(":")
                result[k.strip()] = v.strip()
        return result

    def dbsize(self) -> int:
        return self._exec("DBSIZE")

    def scan_match(self, pattern: str) -> list[str]:
        """SCAN-based key iteration — safe for large keyspaces."""
        cursor = 0
        found = []
        while True:
            cursor, batch = self._exec("SCAN", cursor, "MATCH", pattern, "COUNT", 100)
            cursor = int(cursor)
            found.extend(batch or [])
            if cursor == 0:
                break
        return found

    def mget(self, keys: list[str]) -> list[str | None]:
        if not keys:
            return []
        return self._exec("MGET", *keys) or []
