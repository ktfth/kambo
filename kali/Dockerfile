FROM kalilinux/kali-rolling:latest

# Layer 1: Core tools (stable Kali packages)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap masscan \
    ffuf gobuster dirb \
    nikto \
    sqlmap \
    hydra \
    crackmapexec \
    impacket-scripts \
    responder \
    whatweb wafw00f \
    dnsrecon dnsenum fierce \
    theharvester \
    libimage-exiftool-perl \
    testssl.sh sslyze \
    wpscan \
    python3-pip python3-venv \
    curl wget jq netcat-openbsd unzip \
    git ca-certificates \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Layer 2: Optional apt packages (install individually, skip if unavailable)
RUN apt-get update; \
    for pkg in nuclei amass subfinder httpx-toolkit evil-winrm medusa arjun seclists; do \
        apt-get install -y --no-install-recommends "$pkg" 2>/dev/null \
        && echo "[OK] $pkg" \
        || echo "[SKIP] $pkg — not in repo, will fallback"; \
    done; \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Fallback: ProjectDiscovery Go tools from GitHub if apt missed them
RUN ARCH=$(dpkg --print-architecture) && \
    for tool in nuclei subfinder httpx; do \
        command -v "$tool" >/dev/null 2>&1 && continue; \
        echo "Installing $tool from GitHub..."; \
        curl -sL "https://github.com/projectdiscovery/${tool}/releases/latest/download/${tool}_linux_${ARCH}.zip" \
            -o "/tmp/${tool}.zip" && \
        unzip -o "/tmp/${tool}.zip" -d /usr/local/bin && \
        rm -f "/tmp/${tool}.zip" || true; \
    done

# Python tools (confirmed on PyPI)
RUN pip3 install --break-system-packages \
    bloodhound \
    pwntools

# jwt_tool — from GitHub (not on PyPI)
RUN git clone --depth 1 https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool && \
    pip3 install --break-system-packages -r /opt/jwt_tool/requirements.txt && \
    chmod +x /opt/jwt_tool/jwt_tool.py && \
    ln -sf /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool

# trufflehog v3 — Go binary from GitHub
RUN ARCH=$(dpkg --print-architecture) && \
    curl -sL "https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_linux_${ARCH}.tar.gz" \
    | tar xz -C /usr/local/bin trufflehog || echo "trufflehog: install skipped"

# Wordlists
RUN mkdir -p /wordlists && \
    cp -r /usr/share/wordlists/seclists /wordlists/ 2>/dev/null || true && \
    cp /usr/share/wordlists/rockyou.txt.gz /wordlists/ 2>/dev/null || true && \
    gunzip /wordlists/rockyou.txt.gz 2>/dev/null || true

# Working dirs
RUN mkdir -p /output /scripts

WORKDIR /output
ENTRYPOINT ["/bin/bash", "-c"]
