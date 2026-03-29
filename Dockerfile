FROM python:3.12-alpine3.22

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

WORKDIR /app/won_oss_server

COPY requirements-server.txt /tmp/requirements-server.txt
RUN apk add --no-cache git
RUN pip install --no-cache-dir -r /tmp/requirements-server.txt

COPY . /app/won_oss_server

EXPOSE 9100 15101 15100-15120 2021 8080

CMD ["python", "won_server.py"]
