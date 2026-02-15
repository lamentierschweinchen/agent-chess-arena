FROM python:3.12-slim

WORKDIR /app

# Minimal runtime deps. (curl is useful for debugging inside the container.)
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl \
  && rm -rf /var/lib/apt/lists/*

COPY arena/requirements.lock /app/arena/requirements.lock
RUN python -m pip install --no-cache-dir -r /app/arena/requirements.lock

COPY arena/arena.py /app/arena/arena.py

ENV ARENA_DB_PATH=/data/arena.db
EXPOSE 8787

# Note: chain polling + finalization require CLAWPY_BIN + CHESS_ESCROW_CONTRACT (+ OPERATOR_PEM for writes).
CMD ["python", "/app/arena/arena.py", "run", "--db", "/data/arena.db", "--host", "0.0.0.0", "--port", "8787"]
