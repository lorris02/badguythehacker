FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsutils \
    nmap \
    hydra \
    smbclient \
    whois \
    git \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install searchsploit (ExploitDB CLI)
RUN git clone --depth=1 https://github.com/offensive-security/exploitdb.git /opt/exploitdb \
    && ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/reports

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
