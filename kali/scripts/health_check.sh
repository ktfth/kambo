#!/bin/bash
# Health check script for the Kali container
echo "=== Kambo Kali Container Health Check ==="
echo "Date: $(date -u)"
echo ""

echo "--- Tools Available ---"
for tool in nmap masscan ffuf nuclei sqlmap hydra crackmapexec subfinder amass whatweb wafw00f; do
    if command -v "$tool" &>/dev/null; then
        echo "[OK] $tool"
    else
        echo "[MISSING] $tool"
    fi
done

echo ""
echo "--- Network ---"
echo "Interfaces: $(ip -brief addr show 2>/dev/null | wc -l)"
echo "DNS: $(cat /etc/resolv.conf 2>/dev/null | grep nameserver | head -1)"

echo ""
echo "--- Wordlists ---"
echo "Path: /wordlists"
ls /wordlists/ 2>/dev/null | head -5 || echo "No wordlists found"

echo ""
echo "--- Disk ---"
df -h /output 2>/dev/null | tail -1

echo ""
echo "=== Health Check Complete ==="
