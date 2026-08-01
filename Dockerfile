FROM python:3.11-slim

LABEL org.opencontainers.image.title="NodeChain"
LABEL org.opencontainers.image.description="Governed local trust platform for autonomous AI chains"
LABEL org.opencontainers.image.version="1.2.1"
LABEL org.opencontainers.image.source="https://github.com/Alajmah/NodeChain"

WORKDIR /app

# Install system dependencies
# libseccomp-dev: optional, enables seccomp Python bindings for syscall filtering
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git curl \
        libseccomp-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml .
COPY src/ src/
COPY schemas/ schemas/
COPY blueprints/ blueprints/
COPY nodes/ nodes/
COPY scripts/ scripts/

# Install NodeChain
RUN pip install --no-cache-dir -e ".[dev]"

# Create data directories
RUN mkdir -p data/chroma data/traces data/memory

# Environment defaults
ENV NODECHAIN_PROVIDER=mock
ENV PYTHONIOENCODING=utf-8
ENV PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "from nodechain import __version__; print(__version__)" || exit 1

ENTRYPOINT ["python", "-m", "nodechain.cli.main"]
CMD ["--help"]
