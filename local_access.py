"""Browser/network boundary for Attacca's explicitly login-free local mode.

Local access is not authentication. These checks prevent a web page on another
origin from using a local server through CSRF or DNS rebinding. They do not
distinguish users or programs already able to connect to the trusted machine.
Forwarded headers are deliberately never a source of local authority.
"""

import ipaddress
import urllib.parse


class LocalAccessError(ValueError):
    """The request cannot safely use a login-free local endpoint."""


def _ip_address(value):
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped
    return address


def is_loopback_address(value):
    address = _ip_address(value)
    return bool(address is not None and address.is_loopback)


def network_exposed(server_address):
    """Wildcard, LAN and unknown binds are exposed; only loopback is local."""
    return not is_loopback_address(server_address[0])


def setup_allowed(handler):
    """First-run authority comes from the actual TCP peer, not HTTP headers."""
    return is_loopback_address(handler.client_address[0])


def _one_header(headers, name, required=False):
    values = headers.get_all(name) or []
    if len(values) > 1 or (required and len(values) != 1):
        raise LocalAccessError("local_access_denied: exactly one %s header is required" % name)
    if not values:
        return None
    value = values[0]
    if not value or any(char.isspace() or ord(char) < 32 or ord(char) == 127
                        for char in value):
        raise LocalAccessError("local_access_denied: invalid %s header" % name)
    return value


def _authority(value):
    if any(char in value for char in "\\/@?#%,"):
        raise LocalAccessError("local_access_denied: invalid HTTP authority")
    if value.startswith("["):
        close = value.find("]")
        suffix = value[close + 1:] if close >= 0 else "invalid"
        if close < 0 or (suffix and not (suffix.startswith(":") and suffix[1:].isdigit())):
            raise LocalAccessError("local_access_denied: invalid IPv6 authority")
    elif "[" in value or "]" in value:
        raise LocalAccessError("local_access_denied: invalid HTTP authority")
    try:
        parsed = urllib.parse.urlsplit("//" + value)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        raise LocalAccessError("local_access_denied: invalid HTTP authority") from None
    if not host or parsed.username is not None or parsed.password is not None \
            or parsed.path or parsed.query or parsed.fragment:
        raise LocalAccessError("local_access_denied: invalid HTTP authority")
    # A missing port is meaningful: HTTP's default is 80, not this process's
    # arbitrary listen port. This also rejects an empty explicit ':'.
    if value.endswith(":") or (port is not None and not 1 <= port <= 65535):
        raise LocalAccessError("local_access_denied: invalid HTTP port")
    return host.lower(), 80 if port is None else port


def validate_request(handler, require_loopback=False):
    """Validate Host, browser origin and first-run scope; never authenticate.

    Call for pending/local-mode routes and first-owner bootstrap. Protected
    deployments retain their session/token checks and configured proxy use.
    Login-free access through a remote bind uses the actual destination IP,
    not an arbitrary DNS name. A local SSH tunnel can initialize a remote
    installation without exposing first-owner setup to other network users.
    """
    if require_loopback and not setup_allowed(handler):
        raise LocalAccessError(
            "local_setup_only: open setup on the server's localhost or through a local tunnel")

    host = _one_header(handler.headers, "Host", required=True)
    host_name, host_port = _authority(host)
    try:
        destination = handler.connection.getsockname()
        destination_ip = _ip_address(destination[0])
        destination_port = int(destination[1])
    except (AttributeError, IndexError, TypeError, ValueError, OSError):
        raise LocalAccessError("local_access_denied: socket destination is unavailable") from None
    if destination_ip is None or host_port != destination_port:
        raise LocalAccessError("local_access_denied: Host must match the server's address and port")
    host_ip = _ip_address(host_name)
    localhost = host_name == "localhost" and destination_ip.is_loopback
    if not localhost and host_ip != destination_ip:
        raise LocalAccessError(
            "local_access_denied: use localhost or the server's actual IP address")

    fetch_site = _one_header(handler.headers, "Sec-Fetch-Site")
    if fetch_site and fetch_site.lower() not in ("same-origin", "same-site", "none"):
        raise LocalAccessError("local_access_denied: cross-site browser access is not allowed")
    origin = _one_header(handler.headers, "Origin")
    if origin is not None:
        try:
            parsed = urllib.parse.urlsplit(origin)
        except ValueError:
            raise LocalAccessError("local_access_denied: invalid browser Origin") from None
        if parsed.scheme != "http" or not parsed.netloc or parsed.path \
                or parsed.query or parsed.fragment:
            raise LocalAccessError("local_access_denied: browser Origin must match this HTTP server")
        if _authority(parsed.netloc) != (host_name, host_port):
            raise LocalAccessError("local_access_denied: browser Origin must match Host")

    if handler.command in ("POST", "PUT", "PATCH", "DELETE"):
        lengths = handler.headers.get_all("Content-Length") or []
        try:
            length = int(lengths[0]) if len(lengths) == 1 else 0
        except ValueError:
            raise LocalAccessError("local_access_denied: invalid Content-Length") from None
        if len(lengths) > 1 or length < 0:
            raise LocalAccessError("local_access_denied: invalid Content-Length")
        if handler.command in ("POST", "PUT", "PATCH") or length:
            media_types = handler.headers.get_all("Content-Type") or []
            if len(media_types) != 1 or media_types[0].split(";", 1)[0].strip().lower() \
                    != "application/json":
                raise LocalAccessError("local_access_denied: writes require application/json")
