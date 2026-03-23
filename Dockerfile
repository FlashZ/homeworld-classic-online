FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY requirements-server.txt /tmp/requirements-server.txt
RUN pip install --no-cache-dir -r /tmp/requirements-server.txt

COPY . /app/won_oss_server

RUN chmod +x /app/won_oss_server/docker-entrypoint.sh

EXPOSE 15101 15100-15120 2021 8080

CMD ["/app/won_oss_server/docker-entrypoint.sh"]
