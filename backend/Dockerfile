FROM python:3.11-slim

WORKDIR /app

# System deps + the external recon CLIs the pipeline shells out to.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nmap ca-certificates curl unzip git openssh-client dnsutils \
    && rm -rf /var/lib/apt/lists/*

# feroxbuster -- recursive content brute-forcer (releases are static binaries).
ARG FEROXBUSTER_VER=v2.13.1
RUN curl -fsSL \
        "https://github.com/epi052/feroxbuster/releases/download/${FEROXBUSTER_VER}/x86_64-linux-feroxbuster.tar.gz" \
        | tar -xz -C /usr/local/bin feroxbuster

# ProjectDiscovery binaries: nuclei (template scanner), subfinder (subdomain
# OSINT), dnsx (DNS probing). Versions pinned to issued releases.
ARG NUCLEI_VER=3.11.1
ARG SUBFINDER_VER=2.16.0
ARG DNSX_VER=1.3.1
RUN for entry in \
        "nuclei ${NUCLEI_VER} nuclei" \
        "subfinder ${SUBFINDER_VER} subfinder" \
        "dnsx ${DNSX_VER} dnsx" \
    ; do \
        set -- $entry; \
        curl -fsSL \
            "https://github.com/projectdiscovery/${1}/releases/download/v${2}/${1}_${2}_linux_amd64.zip" \
            -o "/tmp/${1}.zip" \
        && unzip -o "/tmp/${1}.zip" -d /usr/local/bin "${3}" \
        && chmod +x "/usr/local/bin/${3}" \
        && rm -f "/tmp/${1}.zip"; \
    done

COPY requirements.txt .
RUN pip install --no-cache-dir --retries 8 --timeout 60 -r requirements.txt

# Content-discovery wordlist (baked in at build time so first start never
# depends on network). Landed at the path pipeline/scanner/content.py expects.
RUN mkdir -p /root/.local/share/recon \
    && curl -fsSL \
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
        -o /root/.local/share/recon/common.txt

COPY . .

# Auto-install the content wordlist + nuclei templates on first start.
RUN chmod +x /app/docker-entrypoint.sh
ENTRYPOINT ["/app/docker-entrypoint.sh"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]