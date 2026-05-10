FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd --system --gid 10001 mcp && \
    useradd --system --uid 10001 --gid 10001 --create-home --home-dir /home/mcp mcp

WORKDIR /app

# Install dependencies first so subsequent code changes do not bust the layer.
COPY pyproject.toml ./
RUN python -m pip install --upgrade pip && \
    python -m pip install \
        "pydantic>=2.7,<3" \
        "pyyaml>=6,<7" \
        "fastapi>=0.111,<1" \
        "starlette>=0.37,<1" \
        "uvicorn[standard]>=0.30,<1"

COPY src ./src
COPY experiments ./experiments
COPY sandbox ./sandbox
COPY tests/fixtures ./tests/fixtures
RUN mkdir -p /app/var && chown -R mcp:mcp /app

USER mcp

EXPOSE 8000

# Public Mode safe defaults: bind to 0.0.0.0 inside the container, but expect
# a reverse proxy in front. The operator must override DEMO_ADMIN_TOKEN and
# DEMO_ALLOWED_ORIGINS before flipping DEMO_PUBLIC_MODE=true.
ENV DEMO_BIND_HOST=0.0.0.0 \
    DEMO_BIND_PORT=8000 \
    DEMO_EGRESS_MODE=deny \
    DEMO_ENABLE_LOCAL_CALC_PROOF=false \
    PYTHONPATH=/app/src

CMD ["python", "-m", "uvicorn", "mcp_demo.app:create_app", "--factory", \
     "--host", "0.0.0.0", "--port", "8000", \
     "--no-access-log"]
