import json
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

MASK = "[REDACTED]"
SECRET_KEY = re.compile(
    r"(?:authorization|proxy.authorization|cookie|set.cookie|"
    r".*(?:password|passwd|secret|token|api.?key|access.?key|credential|session.?id|private.?key).*)$",
    re.I,
)
ASSIGNMENT = re.compile(
    r"""((?:["']?[\w.-]*(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|credential|session[_-]?id)[\w.-]*["']?)\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s<>,;&}]+)""",
    re.I,
)


def sensitive(key: str):
    if key.lower() in ("access-control-allow-credentials", "allow_credentials"):
        return False
    return bool(SECRET_KEY.fullmatch(key))


def cookie_header(value: str) -> str:
    parts = value.split(";")
    name = parts[0].split("=", 1)[0].strip()
    return f"{name}={MASK}" + "".join(f";{part}" for part in parts[1:])


def url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        host = parsed.netloc.rsplit("@", 1)[-1]
        query = urlencode(
            [
                (k, MASK if sensitive(k) else text(v))
                for k, v in parse_qsl(parsed.query, keep_blank_values=True)
            ]
        )
        path = re.sub(r"(?i)(/(?:token|secret|password|api[_-]?key)/)[^/]+", rf"\1{MASK}", parsed.path)
        return urlunsplit((parsed.scheme, host, path, query, ""))
    except ValueError:
        return "[INVALID URL]"


def text(value: str) -> str:
    value = re.sub(r"(?i)\b(Bearer|Basic)\s+[a-z0-9+/_.=-]+", rf"\1 {MASK}", value)
    value = re.sub(
        r"(?im)^((?:authorization|proxy-authorization|x-api-key|api-key|cookie)\s*:).*$",
        rf"\1 {MASK}",
        value,
    )
    value = re.sub(r"(?im)^(set-cookie\s*:)\s*(.*)$", lambda m: f"{m[1]} {cookie_header(m[2])}", value)
    value = re.sub(r"https?://[^\s<>\"']+", lambda m: url(m[0]), value) if "://" in value else value
    value = ASSIGNMENT.sub(lambda m: m[1] + f'"{MASK}"', value)
    value = re.sub(
        r"""(?is)(<input\b[^>]*\bvalue\s*=\s*)(?:"[^"]*"|'[^']*'|[^\s>]+)""",
        lambda m: m[1] + f'"{MASK}"',
        value,
    )
    value = re.sub(r"(?is)(<textarea\b[^>]*>).*?(</textarea>)", rf"\1{MASK}\2", value)
    value = re.sub(
        r"(?is)(<((?:[\w.-]+:)?(?:password|secret|token|api[_-]?key|access[_-]?token))\b[^>]*>).*?(</\2>)",
        lambda m: m[1] + MASK + m[3],
        value,
    )
    value = re.sub(
        r"""(?is)(<meta\b[^>]*\bname\s*=\s*["'][^"']*(?:token|secret|api[_-]?key)[^"']*["'][^>]*\bcontent\s*=\s*)(?:"[^"]*"|'[^']*'|[^\s>]+)""",
        lambda m: m[1] + f'"{MASK}"',
        value,
    )
    value = re.sub(r"(?s)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", MASK, value)
    return value


def clean(value):
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            key = str(key)
            if key.lower() == "set-cookie" and isinstance(item, str):
                result[key] = cookie_header(item)
            elif sensitive(key):
                result[key] = MASK
            else:
                result[key] = clean(item)
        return result
    if isinstance(value, (list, tuple)):
        return [clean(item) for item in value]
    if isinstance(value, str):
        return text(value)
    return value


def body(value: str, content_type: str) -> str:
    if "json" in content_type:
        try:
            return json.dumps(clean(json.loads(value)), ensure_ascii=True, indent=2)
        except (ValueError, RecursionError):
            return text(value)
    if "x-www-form-urlencoded" in content_type:
        return urlencode([(k, MASK if sensitive(k) else text(v)) for k, v in parse_qsl(value)])
    return text(value)


def headers(items) -> dict[str, str]:
    result = {}
    for key, value in items:
        key = key.lower()
        safe = cookie_header(value) if key == "set-cookie" else MASK if sensitive(key) else text(value)
        result[key] = result[key] + "\n" + safe if key in result else safe
    return result
