# Aegis Gulf Compliance Kernel — Docker Container
# Alpine-based, minimal attack surface
# Build: docker build -t aegisgulf/kernel:1.0.0 .
# Run:   docker run -p 8000:8000 aegisgulf/kernel:1.0.0

FROM python:3.12-alpine

LABEL maintainer="Nvula Bontes <aegisgulf.com>"
LABEL description="Aegis Gulf POPIA Compliance Kernel v1.0.0"
LABEL version="1.0.0"


RUN pip install --no-cache-dir cryptography==42.0.8

WORKDIR /app

COPY engine.py server.py demo.py ./


RUN addgroup -S aegis && adduser -S aegis -G aegis
USER aegis

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=3s \
    CMD wget -qO- http://localhost:8000/health || exit 1

CMD ["python3", "server.py"]
