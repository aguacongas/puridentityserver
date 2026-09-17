"""Point d'entrée local : `uv run python -m puridentityserver`."""

import uvicorn

from puridentityserver.infrastructure.settings import Settings
from puridentityserver.server import create_app


def main() -> None:
    """Lance le serveur Uvicorn avec les réglages d'environnement (PURIDENTITYSERVER_*)."""
    settings = Settings()
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port)


if __name__ == "__main__":
    main()
