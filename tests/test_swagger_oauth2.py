"""Tests de l'authentification OIDC de Swagger UI (bouton Authorize).

Couvre les réglages `swagger_ui_oauth2_*` : déclaration du schéma OAuth2 sur
les CRUD d'administration (rôles `admin` et `full`), configuration du redirect
et de `initOAuth`, comportement de code inchangé sans configuration
(document OpenAPI sans `securitySchemes`), documentation masquée, et appel des
CRUD avec le jeton émis par le flow authorization code.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import puridentityadmin
import puridentityfull
import puridentityprotocol
from puridentityserver.infrastructure.settings import Settings

_ISSUER = "https://id.example"

_AppFactory = Callable[[Settings | None], FastAPI]

# Trois points d'entrée (rôle, fabrique `create_app`) couverts par les tests.
_ENTRY_POINTS: tuple[tuple[str, _AppFactory], ...] = (
    ("protocol", puridentityprotocol.server.create_app),
    ("admin", puridentityadmin.server.create_app),
    ("full", puridentityfull.server.create_app),
)

_FACTORIES: dict[str, _AppFactory] = dict(_ENTRY_POINTS)

# Cas « défaut inchangé » : une fabrique par rôle, identifiant nommé.
_FACTORY_CASES = [pytest.param(factory, id=name) for name, factory in _ENTRY_POINTS]

# Rôles exposant les CRUD d'administration : les seuls où le schéma est déclaré.
_ADMIN_ROLES = ("admin", "full")

_ADMIN_API: dict[str, object] = {"name": "management", "scopes": ["admin"]}

_ADMIN_CLIENT: dict[str, object] = {
    "client_id": "admin-app",
    "client_secret": "admin-secret",
    "scopes": "openid admin",
    "client_type": "confidential",
}

_INIT_OAUTH: dict[str, object] = {
    "clientId": "admin-app",
    "scopes": ["openid", "admin"],
    "usePkceWithAuthorizationCodeGrant": True,
}


def _settings(*, enabled: bool = False, **overrides: object) -> Settings:
    """Settings de test dont les réglages Swagger sont fixés explicitement.

    Les valeurs passées en argument priment sur le `config.toml` du dépôt :
    le test reste déterminant quelle que soit la configuration livrée.
    """
    return Settings(
        issuer=_ISSUER,
        jwks_algorithms=("RS256",),
        swagger_ui_oauth2_enabled=enabled,
        swagger_ui_init_oauth=dict(_INIT_OAUTH) if enabled else {},
        **overrides,
    )


def _admin_token(client: TestClient) -> str:
    """Émet un access token `client_credentials` portant le scope `admin`."""
    response = client.post(
        "/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "admin-app",
            "client_secret": "admin-secret",
            "scope": "openid admin",
        },
    )
    assert response.status_code == 200, response.text
    return str(response.json()["access_token"])


class TestOpenApiSecurityScheme:
    """Couvre la déclaration du schéma OAuth2 dans le document OpenAPI."""

    @pytest.mark.parametrize("factory", _FACTORY_CASES)
    def test_default_configuration_declares_no_scheme(self, factory: _AppFactory) -> None:
        """Sans configuration, aucun schéma OAuth2 n'est publié (défaut inchangé)."""
        with TestClient(factory(_settings())) as client:
            schema = client.get("/openapi.json").json()

        assert "oidc" not in schema.get("components", {}).get("securitySchemes", {})

    @pytest.mark.parametrize("role", _ADMIN_ROLES)
    def test_enabled_declares_oauth2_scheme_on_crud(self, role: str) -> None:
        """Activé, les CRUD portent le schéma authorization code et leurs scopes."""
        with TestClient(_FACTORIES[role](_settings(enabled=True))) as client:
            schema = client.get("/openapi.json").json()

        scheme = schema["components"]["securitySchemes"]["oidc"]
        assert scheme["type"] == "oauth2"
        flow = scheme["flows"]["authorizationCode"]
        assert flow["authorizationUrl"] == f"{_ISSUER}/authorize"
        assert flow["tokenUrl"] == f"{_ISSUER}/token"
        assert set(flow["scopes"]) == {"openid", "admin"}
        expected = [{"oidc": ["openid", "admin"]}]
        assert schema["paths"]["/api-resources"]["get"]["security"] == expected
        assert schema["paths"]["/identity-resources"]["post"]["security"] == expected

    def test_protocol_role_never_declares_scheme(self) -> None:
        """Le rôle `protocol` n'expose aucun CRUD : aucun schéma, même activé."""
        with TestClient(_FACTORIES["protocol"](_settings(enabled=True))) as client:
            schema = client.get("/openapi.json").json()

        assert "oidc" not in schema.get("components", {}).get("securitySchemes", {})

    def test_open_routes_have_no_security_requirement(self) -> None:
        """Le discovery reste sans `security` : seul le schéma des CRUD est ajouté."""
        with TestClient(_FACTORIES["full"](_settings(enabled=True))) as client:
            schema = client.get("/openapi.json").json()

        discovery = schema["paths"]["/.well-known/openid-configuration"]["get"]
        assert "security" not in discovery

    def test_scheme_urls_follow_base_url(self) -> None:
        """Les URL du flow suivent `base_url` (URL publique) quand elle est renseignée."""
        settings = _settings(enabled=True, base_url="https://public.example")
        with TestClient(_FACTORIES["admin"](settings)) as client:
            schema = client.get("/openapi.json").json()

        flow = schema["components"]["securitySchemes"]["oidc"]["flows"]["authorizationCode"]
        assert flow["authorizationUrl"] == "https://public.example/authorize"
        assert flow["tokenUrl"] == "https://public.example/token"


class TestSwaggerUiHtml:
    """Couvre le rendu de Swagger UI (`/docs`) et du redirect OAuth2."""

    def test_docs_renders_init_oauth_and_redirect(self) -> None:
        """Activé, `/docs` configure `initOAuth` et le redirect répond 200."""
        with TestClient(_FACTORIES["admin"](_settings(enabled=True))) as client:
            html = client.get("/docs").text

            assert "ui.initOAuth(" in html
            assert '"clientId": "admin-app"' in html
            assert "usePkceWithAuthorizationCodeGrant" in html
            assert "oauth2RedirectUrl: window.location.origin + '/docs/oauth2-redirect'" in html
            assert client.get("/docs/oauth2-redirect").status_code == 200

    def test_docs_without_init_oauth_by_default(self) -> None:
        """Défaut : aucun `initOAuth`, le redirect FastAPI est inchangé."""
        with TestClient(_FACTORIES["admin"](_settings())) as client:
            html = client.get("/docs").text

            assert "ui.initOAuth(" not in html
            assert "oauth2RedirectUrl: window.location.origin + '/docs/oauth2-redirect'" in html
            assert client.get("/docs/oauth2-redirect").status_code == 200

    def test_settings_apply_to_every_role(self) -> None:
        """Les réglages Swagger s'appliquent aux trois rôles (affichage de `/docs`)."""
        with TestClient(_FACTORIES["protocol"](_settings(enabled=True))) as client:
            assert "ui.initOAuth(" in client.get("/docs").text

    def test_custom_redirect_url_moves_route(self) -> None:
        """Un redirect personnalisé déplace la route et l'URL annoncée à Swagger."""
        settings = _settings(enabled=True, swagger_ui_oauth2_redirect_url="/custom/oauth2-redirect")
        with TestClient(_FACTORIES["admin"](settings)) as client:
            html = client.get("/docs").text

            assert "window.location.origin + '/custom/oauth2-redirect'" in html
            assert client.get("/custom/oauth2-redirect").status_code == 200
            assert client.get("/docs/oauth2-redirect").status_code == 404

    def test_masked_documentation_removes_redirect(self) -> None:
        """`docs_enabled = false` retire aussi le redirect OAuth2 (routes 404)."""
        settings = _settings(enabled=True, docs_enabled=False)
        with TestClient(_FACTORIES["admin"](settings)) as client:
            assert client.get("/docs").status_code == 404
            assert client.get("/docs/oauth2-redirect").status_code == 404
            assert client.get("/openapi.json").status_code == 404


class TestCrudAuthentication:
    """Couvre l'appel des CRUD : la protection JWT ne change pas, schéma ou non."""

    def _app_settings(self) -> Settings:
        """Settings d'activation avec le client et la resource de gestion seedés."""
        return _settings(
            enabled=True,
            api_resources_seed=(_ADMIN_API,),
            clients_seed=(_ADMIN_CLIENT,),
        )

    def test_crud_rejects_request_without_token(self) -> None:
        """Le schéma Swagger ne dispense pas d'un jeton : 401 sans Bearer."""
        with TestClient(_FACTORIES["full"](self._app_settings())) as client:
            response = client.get("/api-resources")

        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"

    def test_crud_accepts_admin_token(self) -> None:
        """Le jeton `scope=admin` passé à Swagger autorise les CRUD (200/201)."""
        with TestClient(_FACTORIES["full"](self._app_settings())) as client:
            headers = {"Authorization": f"Bearer {_admin_token(client)}"}

            assert client.get("/api-resources", headers=headers).status_code == 200
            created = client.post(
                "/identity-resources",
                headers=headers,
                json={"name": "from-swagger", "user_claims": ["name"]},
            )

        assert created.status_code == 201


class TestSettings:
    """Couvre les réglages `swagger_ui_oauth2_*` (code, config, environnement)."""

    def test_code_defaults_are_disabled(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Sans `config.toml`, la fonctionnalité reste désactivée (défaut de code)."""
        config = tmp_path / "config.toml"
        config.write_text("[settings]\n", encoding="utf-8")
        monkeypatch.setenv("PURIDENTITYSERVER_SETTINGS_FILE", str(config))
        settings = Settings(_env_file=None)

        assert settings.swagger_ui_oauth2_enabled is False
        assert settings.swagger_ui_init_oauth == {}
        assert settings.swagger_ui_oauth2_redirect_url == "/docs/oauth2-redirect"

    def test_repo_config_enables_feature(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """La configuration livrée active la fonctionnalité avec le client de démo."""
        config = Path(__file__).resolve().parents[1] / "config.toml"
        monkeypatch.setenv("PURIDENTITYSERVER_SETTINGS_FILE", str(config))
        settings = Settings(_env_file=None)

        assert settings.swagger_ui_oauth2_enabled is True
        assert settings.swagger_ui_init_oauth["clientId"] == "sample-swagger-client"
        assert settings.swagger_ui_init_oauth["usePkceWithAuthorizationCodeGrant"] is True
        assert "sample-swagger-client" in {client.client_id for client in settings.seed_clients}

    def test_environment_json_provides_init_oauth(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """`PURIDENTITYSERVER_SWAGGER_UI_INIT_OAUTH` accepte un objet JSON."""
        monkeypatch.setenv(
            "PURIDENTITYSERVER_SWAGGER_UI_INIT_OAUTH",
            '{"clientId": "env-client", "scopes": ["openid"]}',
        )
        monkeypatch.setenv("PURIDENTITYSERVER_SWAGGER_UI_OAUTH2_ENABLED", "true")
        settings = Settings(_env_file=None)

        assert settings.swagger_ui_oauth2_enabled is True
        assert settings.swagger_ui_init_oauth == {"clientId": "env-client", "scopes": ["openid"]}

    @pytest.mark.parametrize("value", ["[]", '"clientId"', "not-json"])
    def test_environment_rejects_non_object_json(
        self, value: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Une valeur qui n'est pas un objet JSON est refusée au chargement."""
        monkeypatch.setenv("PURIDENTITYSERVER_SWAGGER_UI_INIT_OAUTH", value)

        with pytest.raises(ValueError):
            Settings(_env_file=None)

    def test_environment_disables_feature_from_config(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """L'environnement l'emporte sur `config.toml` (désactivation du bouton)."""
        config = tmp_path / "config.toml"
        config.write_text("[settings]\nswagger_ui_oauth2_enabled = true\n", encoding="utf-8")
        monkeypatch.setenv("PURIDENTITYSERVER_SETTINGS_FILE", str(config))
        monkeypatch.setenv("PURIDENTITYSERVER_SWAGGER_UI_OAUTH2_ENABLED", "false")
        settings = Settings(_env_file=None)

        assert settings.swagger_ui_oauth2_enabled is False
