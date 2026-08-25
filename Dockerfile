# Image for the DRACARYS GitHub Action (referenced by action.yml at the repo root).
# GitHub requires a container action's local image file to be named `Dockerfile`,
# so this lives at the root; the api/web images stay under infra/docker/.
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY requirements.txt ./
RUN pip install -r requirements.txt
COPY pyproject.toml README.md ./
COPY dracarys ./dracarys
RUN pip install -e .
COPY infra/docker/action-entrypoint.sh /action-entrypoint.sh
RUN chmod +x /action-entrypoint.sh
ENTRYPOINT ["/action-entrypoint.sh"]
