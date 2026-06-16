# Single, optional image. The Navigator layer JSON is the product's UI contract,
# so there is no web UI and no docker-compose — just a headless runner you can
# invoke as the CLI or as the MCP server.
#
# Build:  docker build -t tenable-attack-mapper .
# CLI:    docker run --rm --env-file .env -v "$PWD:/work" tenable-attack-mapper \
#             run --repo 1 --out /work/layer.json
# MCP:    docker run --rm -i --env-file .env tenable-attack-mapper \
#             python -m tenable_attack_mapper.mcp.server

FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY data ./data

RUN pip install --no-cache-dir ".[mcp]"

# Default to the CLI; override the command for the MCP server (see header).
ENTRYPOINT ["tenable-attack-mapper"]
CMD ["--help"]
