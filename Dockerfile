# Image minimale de production pour PurIdentityServer (instance de
# certification déployée sur Render). L'application tourne en mémoire
# (`storage_type = "memory"`) : aucune dépendance native ni base de données.
#
# ${PORT} (injecté par Render) fixe le port d'écoute ; défaut 8000.

FROM python:3.13-slim

COPY --from=ghcr.io/astral-sh/uv:0.6.14 /uv /uvx /usr/local/bin/

WORKDIR /app
ENV UV_LINK_MODE=copy \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PURIDENTITYSERVER_SETTINGS_FILE=/app/certification/config.render.toml

COPY pyproject.toml uv.lock README.md ./
COPY src ./src
COPY certification ./certification

RUN uv sync --extra sql --frozen --no-dev

EXPOSE 8000

CMD ["sh", "-c", "uv run --no-sync uvicorn puridentityserver.server:app --host 0.0.0.0 --port ${PORT:-8000}"]