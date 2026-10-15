"""Tests du helper d'URL publique derrière un reverse proxy (RFC 9449 §4.3)."""

from __future__ import annotations

from urllib.parse import urlsplit

from fastapi import Request

from puridentityserver.interfaces.api.forwarded import public_url


def _request(url: str, headers: dict[str, str] | None = None) -> Request:
    """Fabrique une ``Request`` ASGI dont ``request.url`` reproduit ``url``."""
    parts = urlsplit(url)
    host = parts.hostname or "testserver"
    port = parts.port or (443 if parts.scheme == "https" else 80)
    provided = {name.lower(): value for name, value in (headers or {}).items()}
    asgi_headers = [
        (name.encode("ascii"), value.encode("ascii")) for name, value in provided.items()
    ]
    if "host" not in provided:
        default_port = 443 if parts.scheme == "https" else 80
        authority = host if port == default_port else f"{host}:{port}"
        asgi_headers.insert(0, (b"host", authority.encode("ascii")))
    scope: dict[str, object] = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.1"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": parts.scheme,
        "path": parts.path,
        "raw_path": parts.path.encode("ascii"),
        "query_string": b"",
        "root_path": "",
        "headers": asgi_headers,
        "client": ("127.0.0.1", 4242),
        "server": (host, port),
    }
    return Request(scope)


class TestPublicUrl:
    """Couvre public_url (reconstruction X-Forwarded-*, confiance conditionnelle)."""

    def test_returns_internal_url_without_trust(self) -> None:
        request = _request(
            "http://testserver/protected-resource",
            {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "op:9443"},
        )

        result = public_url(request, trust_proxy_headers=False)

        assert result == "http://testserver/protected-resource"

    def test_ignores_forwarded_headers_when_trust_is_off(self) -> None:
        request = _request(
            "http://backend:8000/protected-resource",
            {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "op:9443"},
        )

        result = public_url(request, trust_proxy_headers=False)

        assert result == "http://backend:8000/protected-resource"

    def test_rebuilds_scheme_and_authority_behind_trusted_proxy(self) -> None:
        request = _request(
            "http://backend:8000/protected-resource",
            {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "op:9443"},
        )

        result = public_url(request, trust_proxy_headers=True)

        assert result == "https://op:9443/protected-resource"

    def test_falls_back_to_host_header_when_forwarded_host_is_absent(self) -> None:
        request = _request(
            "http://backend:8000/userinfo",
            {"X-Forwarded-Proto": "https", "Host": "op.example"},
        )

        result = public_url(request, trust_proxy_headers=True)

        assert result == "https://op.example/userinfo"

    def test_applies_forwarded_port_to_authority_without_port(self) -> None:
        request = _request(
            "http://backend:8000/protected-resource",
            {
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": "op.example",
                "X-Forwarded-Port": "9443",
            },
        )

        result = public_url(request, trust_proxy_headers=True)

        assert result == "https://op.example:9443/protected-resource"

    def test_strips_query_and_fragment(self) -> None:
        request = _request(
            "http://backend:8000/protected-resource",
            {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "op:9443"},
        )
        request.scope["query_string"] = b"access_token=xyz"

        result = public_url(request, trust_proxy_headers=True)

        assert result == "https://op:9443/protected-resource"

    def test_uses_first_value_of_multi_valued_forwarded_headers(self) -> None:
        request = _request(
            "http://backend:8000/protected-resource",
            {"X-Forwarded-Proto": "https, http", "X-Forwarded-Host": "op:9443, internal"},
        )

        result = public_url(request, trust_proxy_headers=True)

        assert result == "https://op:9443/protected-resource"
