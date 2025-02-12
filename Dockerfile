FROM python:3.10 AS builder
COPY requirements.txt .

RUN addgroup --gid 2000 --system appgroup && \
    adduser --uid 2000 --system appuser --gid 2000 --home /home/appuser

USER 2000

# install dependencies to the local user directory
RUN pip install --user -r requirements.txt

FROM python:3.10-slim
WORKDIR /app

RUN addgroup --gid 2000 --system appgroup && \
    adduser --uid 2000 --system appuser --gid 2000 --home /home/appuser

RUN apt-get update && apt-get install -y wget jq
# Install Trivy
RUN TRIVY_VERSION=$(wget -qO- https://api.github.com/repos/aquasecurity/trivy/releases/latest | jq -r .tag_name) && \
    echo "Trivy version: ${TRIVY_VERSION}" && \
    wget https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/trivy_${TRIVY_VERSION#v}_Linux-64bit.deb || { echo "Failed to download Trivy"; exit 1; } && \
    dpkg -i trivy_${TRIVY_VERSION}_Linux-64bit.deb && \
    rm trivy_${TRIVY_VERSION}_Linux-64bit.deb

# copy the dependencies from builder stage
COPY --chown=appuser:appgroup --from=builder /home/appuser/.local /home/appuser/.local
COPY ./trivy_discovery.py .

# update PATH environment variable
ENV PATH=/home/appuser/.local:$PATH

USER 2000

CMD [ "python", "-u", "trivy_discovery.py" ]
