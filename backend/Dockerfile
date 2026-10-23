FROM python:3.11-slim

WORKDIR /app

# System deps + the external recon CLIs the pipeline shells out to, plus real
# exploitation tooling: sqlmap (SQLi validation/exploitation confirmation),
# nikto (webserver scanner), hydra (credential brute force), gobuster (content
# discovery — the agent gobuster-dir tool) and nfs-common (showmount — the
# nfs-probe skill). msfconsole (Metasploit) is intentionally not baked in:
# install it separately only for lab/CTF profiles.
#
# nikto is not packaged in current Debian releases, so the Perl modules it
# needs are installed from apt and nikto itself is cloned from upstream below.
RUN apt-get -o Acquire::Retries=5 update \
    && apt-get install -y --no-install-recommends \
        nmap ca-certificates curl unzip git openssh-client dnsutils \
        sqlmap hydra gobuster nfs-common \
        perl libxml-writer-perl libnet-ssleay-perl libwww-perl \
        libio-socket-ssl-perl \
    && rm -rf /var/lib/apt/lists/*

# nikto -- webserver scanner (upstream git checkout; not a Debian package).
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && chmod +x /opt/nikto/program/nikto.pl \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# ffuf -- fast web fuzzer (static release binary; agent ffuf-fuzz tool).
ARG FFUF_VER=2.1.0
RUN curl -fsSL \
        "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VER}/ffuf_${FFUF_VER}_linux_amd64.tar.gz" \
        | tar -xz -C /usr/local/bin ffuf

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
ARG KATANA_VER=1.1.2
RUN for entry in \
        "nuclei ${NUCLEI_VER} nuclei" \
        "subfinder ${SUBFINDER_VER} subfinder" \
        "dnsx ${DNSX_VER} dnsx" \
        "katana ${KATANA_VER} katana" \
    ; do \
        set -- $entry; \
        curl -fsSL \
            "https://github.com/projectdiscovery/${1}/releases/download/v${2}/${1}_${2}_linux_amd64.zip" \
            -o "/tmp/${1}.zip" \
        && unzip -o "/tmp/${1}.zip" -d /usr/local/bin "${3}" \
        && chmod +x "/usr/local/bin/${3}" \
        && rm -f "/tmp/${1}.zip"; \
    done

COPY backend/requirements.txt .
RUN pip install --no-cache-dir --retries 8 --timeout 60 -r requirements.txt

# Content-discovery wordlist (baked in at build time so first start never
# depends on network). Landed at the path pipeline/scanner/content.py expects.
RUN mkdir -p /root/.local/share/recon \
    && curl -fsSL \
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
        -o /root/.local/share/recon/common.txt

COPY backend/ .

# Website assets live in the repo-root FRONTEND/ folder; bake them into the
# image too so the container serves the UI even without the compose volume.
COPY FRONTEND/ /app/frontend/

# Auto-install the content wordlist + nuclei templates on first start.
RUN chmod +x /app/docker-entrypoint.sh
ENTRYPOINT ["/app/docker-entrypoint.sh"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]