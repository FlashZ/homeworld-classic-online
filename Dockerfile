FROM python:3.12-alpine3.22

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

WORKDIR /app/won_oss_server

COPY requirements-server.txt /tmp/requirements-server.txt
# The Admin dashboard runs Git against this known in-image checkout. The
# explicit trust entry keeps Git's ownership protection intact for every other
# path while allowing the non-root runtime user to inspect it.
RUN apk add --no-cache git \
    && addgroup -S -g 1001 won \
    && adduser -S -D -H -u 1001 -G won won \
    && git config --system --add safe.directory /app/won_oss_server \
    && pip install --no-cache-dir -r /tmp/requirements-server.txt

COPY --chown=1001:1001 . /app/won_oss_server

# The Compose deployment mounts a writable /data volume owned by UID 1001.
# Everything else remains read-only at runtime.
USER 1001:1001

EXPOSE 9100 15101 15100-15120 2021 8080

CMD ["python", "won_server.py"]
