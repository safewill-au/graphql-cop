# Multi-stage build: resolve deps on slim, run on distroless.
# Distroless ships no shell, apt, perl, gzip, ncurses or util-linux, so the
# base-image CVE surface is near zero. Build stage matches the runtime's
# Python 3.11 (debian12) so compiled wheels stay ABI-compatible.

# --- build stage: resolve deps into an isolated prefix ---
FROM python:3.11-slim AS build
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --target=/deps -r requirements.txt

# --- runtime: distroless, nonroot, no shell/pkg-manager ---
FROM gcr.io/distroless/python3-debian12:nonroot
WORKDIR /app
ENV PYTHONPATH=/deps
COPY --from=build /deps /deps
COPY . .
ENTRYPOINT ["python3", "graphql-cop.py"]
