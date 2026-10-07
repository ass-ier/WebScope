import ipaddress
import re
from urllib.parse import unquote, urlsplit, urlunsplit

from app.schemas import Configuration, ScopeInput


class PolicyError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def hostname(value: str) -> str:
    value = value.rstrip(".").lower()
    try:
        return str(ipaddress.ip_address(value.strip("[]")))
    except ValueError:
        pass
    if not value or any(c in value for c in "/\\@%:#? \t\r\n"):
        raise PolicyError(
            "INVALID_HOST", "Scope hosts must be exact DNS names or IP addresses, without ports"
        )
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise PolicyError("INVALID_HOST", "Invalid internationalized hostname") from exc
    if len(value) > 253 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in value.split(".")
    ):
        raise PolicyError("INVALID_HOST", "Invalid hostname")
    return value


def normalized_path(value: str) -> str:
    if not value.startswith("/") or value.startswith("//"):
        raise PolicyError("INVALID_PATH", "Paths must start with one slash")
    for _ in range(5):
        decoded = unquote(value, errors="strict")
        if decoded == value:
            break
        value = decoded
    if "%" in value or "\\" in value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise PolicyError("INVALID_PATH", "Ambiguous or malformed encoded path")
    parts = []
    for part in value.split("/"):
        if part == "..":
            if parts:
                parts.pop()
        elif part not in ("", "."):
            parts.append(part.split(";", 1)[0])
    return "/" + "/".join(parts)


def canonical_url(value: str) -> str:
    if len(value) > 4096 or "\\" in value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise PolicyError("INVALID_URL", "Malformed URL")
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise PolicyError("INVALID_URL", "Only absolute HTTP and HTTPS URLs are supported")
        if parsed.username is not None or parsed.password is not None:
            raise PolicyError("CREDENTIALS_BLOCKED", "Embedded URL credentials are prohibited")
        host = hostname(parsed.hostname)
        port = parsed.port
        path = normalized_path(parsed.path or "/")
        authority = f"[{host}]" if ":" in host else host
        if port and port != (443 if parsed.scheme == "https" else 80):
            authority += f":{port}"
        # Validate decoded aliases, but preserve the encoded spelling sent to the server.
        if "?" in path or "#" in path:
            raise PolicyError("INVALID_PATH", "Encoded path delimiters are prohibited")
        return urlunsplit((parsed.scheme, authority, parsed.path or "/", parsed.query, ""))
    except (ValueError, UnicodeError) as exc:
        if isinstance(exc, PolicyError):
            raise
        raise PolicyError("INVALID_URL", "Malformed URL") from exc


class Scope:
    def __init__(self, target: str, rules: ScopeInput, config: Configuration, authorized: bool):
        self.target = canonical_url(target)
        self.rules = rules
        self.config = config
        self.authorized = authorized
        self.allowed = {hostname(v) for v in rules.allowed_hosts}
        self.excluded = {hostname(v) for v in rules.excluded_hosts}
        self.paths = [normalized_path(v) for v in rules.excluded_paths]
        target_parts = urlsplit(self.target)
        self.ports = {target_parts.port or (443 if target_parts.scheme == "https" else 80), 80, 443}
        self.ports.update(config.allowed_ports)

    def validate(self, value: str) -> str:
        value = canonical_url(value)
        parsed = urlsplit(value)
        host = hostname(parsed.hostname)
        if host not in self.allowed or host in self.excluded:
            raise PolicyError("HOST_BLOCKED", "Destination host is outside the explicit assessment scope")
        path = normalized_path(parsed.path)
        if any(path == p or path.startswith(p.rstrip("/") + "/") for p in self.paths):
            raise PolicyError("PATH_BLOCKED", "Destination path is explicitly excluded")
        if (parsed.port or (443 if parsed.scheme == "https" else 80)) not in self.ports:
            raise PolicyError("PORT_BLOCKED", "Destination port is not authorized")
        return value

    def network_allowed(self, value: str):
        self.validate(value)
        if not self.authorized:
            raise PolicyError(
                "AUTHORIZATION_REQUIRED", "Explicit authorization is required before collection"
            )
        if self.config.mode != "SAFE_HTTP":
            raise PolicyError("PASSIVE_MODE", "Passive mode never makes network requests")

    def address(self, value: str):
        ip = ipaddress.ip_address(value)
        mapped = getattr(ip, "ipv4_mapped", None)
        if mapped:
            ip = mapped
        if ip.is_unspecified or ip.is_multicast or ip.is_link_local or ip.is_reserved:
            raise PolicyError(
                "ADDRESS_BLOCKED", "Unspecified, multicast, link-local, and reserved addresses are denied"
            )
        if not ip.is_global and not self.config.allow_private_network:
            raise PolicyError(
                "PRIVATE_NETWORK_BLOCKED", "Private/loopback addresses require explicit configuration"
            )
        return str(ip)
