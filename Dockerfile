FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y wget && \
    wget https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb && \
    dpkg -i cloudflared-linux-amd64.deb && \
    rm cloudflared-linux-amd64.deb && \
    apt-get clean

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && python -m spacy download en_core_web_lg

COPY . .

RUN chmod +x startup.sh

ENTRYPOINT ["./startup.sh"]
