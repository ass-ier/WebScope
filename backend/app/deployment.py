import os
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Deployment:
    mode: str = "local"
    public_origin: str = ""
    allowed_hosts: tuple[str, ...] = ()
    max_sessions: int = 25
    max_assessments: int = 10
    max_storage_bytes: int = 20_000_000
    session_hours: int = 24
    secure_cookies: bool = True

    @property
    def hosted(self):
        return self.mode == "hosted"

    @property
    def network_enabled(self):
        return not self.hosted

    @classmethod
    def from_env(cls):
        mode = os.environ.get("WEBSCOPE_DEPLOYMENT", "local")
        if mode not in ("local", "hosted"):
            raise ValueError("WEBSCOPE_DEPLOYMENT must be local or hosted")
        if os.environ.get("RENDER") and mode != "hosted":
            raise ValueError("Render deployments must explicitly use WEBSCOPE_DEPLOYMENT=hosted")
        if mode == "local":
            return cls(secure_cookies=False)
        origin = os.environ.get("WEBSCOPE_PUBLIC_ORIGIN", "").rstrip("/")
        parsed = urlsplit(origin)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.path
            or parsed.query
            or parsed.fragment
            or parsed.username
        ):
            raise ValueError("WEBSCOPE_PUBLIC_ORIGIN must be the exact HTTPS frontend origin")
        hosts = tuple(
            filter(
                None,
                (
                    parsed.hostname,
                    os.environ.get("RENDER_EXTERNAL_HOSTNAME", ""),
                    *os.environ.get("WEBSCOPE_ALLOWED_HOSTS", "").split(","),
                ),
            )
        )
        if any("/" in host or "*" in host or ":" in host or host != host.strip() for host in hosts):
            raise ValueError(
                "WEBSCOPE_ALLOWED_HOSTS must contain exact hostnames, without wildcards or ports"
            )
        if not os.environ.get("WEBSCOPE_DATA_DIR"):
            raise ValueError("Hosted deployment requires an explicit temporary WEBSCOPE_DATA_DIR")
        return cls(mode="hosted", public_origin=origin, allowed_hosts=hosts)
