FROM python:3.13-slim AS builder
COPY requirements.txt .

RUN addgroup --gid 2000 --system appgroup && \
    adduser --uid 2000 --system appuser --gid 2000 --home /home/appuser

USER 2000

# install dependencies to the local user directory
RUN pip install --user -r requirements.txt

FROM python:3.13-slim
WORKDIR /app

RUN addgroup --gid 2000 --system appgroup && \
    adduser --uid 2000 --system appuser --gid 2000 --home /home/appuser

RUN apt-get update && apt-get install -y wget jq

# copy the dependencies from builder stage
RUN chown -R appuser:appgroup /app
COPY --chown=appuser:appgroup --from=builder /home/appuser/.local /home/appuser/.local
COPY --chown=appuser:appgroup  ./trivy_discovery.py /app/trivy_discovery.py
COPY --chown=appuser:appgroup  ./classes ./classes
COPY --chown=appuser:appgroup  ./processes ./processes
COPY --chown=appuser:appgroup  ./utilities ./utilities

# create the /app/trivy directory for the trivy cache
RUN mkdir -p /app/trivy_cache && chown -R appuser:appgroup /app/trivy_cache

# update PATH environment variable
ENV PATH=/home/appuser/.local:/app:$PATH
USER 2000

CMD [ "python", "-u", "/app/trivy_discovery.py" ]
