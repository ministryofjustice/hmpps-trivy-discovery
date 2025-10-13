FROM ghcr.io/astral-sh/uv:python3.13-alpine
WORKDIR /app

RUN addgroup -g 2000 appgroup && \
    adduser -u 2000 -G appgroup -h /home/appuser -D appuser

# initialise uv
COPY pyproject.toml .
RUN uv sync

# create the /app/trivy directory for the trivy cache
RUN mkdir -p /app/trivy_cache && chown -R appuser:appgroup /app/trivy_cache

COPY --chown=appuser:appgroup  ./trivy_discovery.py /app/trivy_discovery.py
COPY --chown=appuser:appgroup  ./includes ./includes
COPY --chown=appuser:appgroup  ./processes ./processes

USER 2000

CMD [ "uv", "run", "python", "-u", "/app/trivy_discovery.py" ]
