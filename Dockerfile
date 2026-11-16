FROM node:24-alpine AS frontend
WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY tools ./tools
COPY web ./web
RUN npm run build
FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY relay /app/relay
RUN pip install --no-cache-dir -r /app/relay/requirements.txt
COPY --from=frontend /build/relay/static/public.js /app/relay/static/public.js
RUN groupadd --gid 10001 shuttle && useradd --uid 10001 --gid shuttle --no-create-home shuttle \
    && mkdir /data && chown shuttle:shuttle /data
USER 10001:10001
ENTRYPOINT ["python3", "-m", "relay.server"]
