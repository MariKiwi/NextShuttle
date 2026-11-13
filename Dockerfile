FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY relay /app/relay
RUN groupadd --gid 10001 shuttle && useradd --uid 10001 --gid shuttle --no-create-home shuttle \
    && mkdir /data && chown shuttle:shuttle /data
USER 10001:10001
ENTRYPOINT ["python3", "-m", "relay.server"]
