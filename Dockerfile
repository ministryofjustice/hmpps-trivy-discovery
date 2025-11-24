FROM ghcr.io/ministryofjustice/hmpps-python:python3.13-alpine AS base

# initialise uv
COPY pyproject.toml .
RUN uv sync

# create the /app/trivy directory for the trivy cache
RUN mkdir -p /app/trivy_cache

COPY --chown=appuser:appgroup  ./trivy_discovery.py /app/trivy_discovery.py
COPY --chown=appuser:appgroup  ./includes ./includes
COPY --chown=appuser:appgroup  ./processes ./processes

CMD [ "uv", "run", "python", "-u", "/app/trivy_discovery.py" ]
