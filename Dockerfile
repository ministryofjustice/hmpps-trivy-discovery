FROM ghcr.io/ministryofjustice/hmpps-python:python3.13-alpine AS base

# initialise uv
COPY pyproject.toml .
RUN uv sync

# create the /app/trivy directory for the trivy cache
RUN mkdir -p /app/trivy_cache && chown -R appuser:appgroup /app/trivy_cache
RUN chown -R appuser:appgroup /app

COPY --chown=appuser:appgroup  ./trivy_discovery.py /app/trivy_discovery.py
COPY --chown=appuser:appgroup  ./includes ./includes
COPY --chown=appuser:appgroup  ./processes ./processes

USER 2000

CMD [ "uv", "run", "python", "-u", "/app/trivy_discovery.py" ]
