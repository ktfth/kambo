"""Container & Kubernetes security testing tools."""

from __future__ import annotations

from kambo.docker_runner import get_runner
from kambo.models import Phase
from kambo.scope import validate_scope


async def container_escape_detect(target: str) -> dict:
    """Detect container escape possibilities from within a container.

    Args:
        target: Target host/container identifier
    """
    validate_scope(target)
    runner = get_runner()

    checks = {
        "docker_socket": "ls -la /var/run/docker.sock 2>/dev/null && echo 'FOUND' || echo 'NOT_FOUND'",
        "privileged": "cat /proc/self/status | grep -i cap 2>/dev/null",
        "mounted_devices": "fdisk -l 2>/dev/null | head -20",
        "kubernetes_sa": "cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null | head -1 && echo 'FOUND' || echo 'NOT_FOUND'",
        "hostname_check": "hostname && cat /proc/1/cgroup 2>/dev/null | head -5",
    }

    results = {}
    for check_name, cmd in checks.items():
        result = await runner.run(cmd, f"container_escape_{check_name}", target, Phase.POST_EXPLOITATION, timeout=10)
        results[check_name] = {
            "output": result.raw_output.strip(),
            "exploitable": "FOUND" in result.raw_output or "docker.sock" in result.raw_output,
        }

    return {
        "target": target,
        "checks": results,
        "escape_possible": any(r.get("exploitable") for r in results.values()),
    }


async def container_image_scan(
    target: str,
    image: str,
) -> dict:
    """Scan container image for vulnerabilities with trivy.

    Args:
        target: Target context (for scope)
        image: Docker image to scan (e.g., nginx:latest)
    """
    validate_scope(target)
    runner = get_runner()

    cmd = f"trivy image --format json --severity HIGH,CRITICAL {image} 2>/dev/null"
    result = await runner.run(cmd, "container_image_scan", target, Phase.VULN_ANALYSIS, timeout=180)

    import json
    try:
        data = json.loads(result.raw_output)
        vulns = []
        for r in data.get("Results", []):
            for v in r.get("Vulnerabilities", []):
                vulns.append({
                    "id": v.get("VulnerabilityID", ""),
                    "severity": v.get("Severity", ""),
                    "package": v.get("PkgName", ""),
                    "installed": v.get("InstalledVersion", ""),
                    "fixed": v.get("FixedVersion", ""),
                    "title": v.get("Title", ""),
                })
        return {"image": image, "vulnerabilities": vulns, "total": len(vulns)}
    except json.JSONDecodeError:
        return {"image": image, "raw": result.raw_output[:5000]}


async def k8s_rbac_enum(
    target: str,
    token: str = "",
    api_server: str = "",
) -> dict:
    """Enumerate Kubernetes RBAC permissions.

    Args:
        target: K8s cluster identifier
        token: Service account token
        api_server: K8s API server URL
    """
    validate_scope(target)
    runner = get_runner()

    auth_header = f'-H "Authorization: Bearer {token}"' if token else ""
    server = api_server or f"https://{target}:6443"

    cmd = f'curl -sk {auth_header} {server}/api/v1/namespaces 2>/dev/null | jq ".items[].metadata.name" 2>/dev/null'
    result = await runner.run(cmd, "k8s_rbac_enum", target, Phase.POST_EXPLOITATION, timeout=30)

    # Check what we can do
    cmd2 = f'curl -sk {auth_header} {server}/apis/authorization.k8s.io/v1/selfsubjectaccessreviews -X POST -H "Content-Type: application/json" -d \'{{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{{"resourceAttributes":{{"verb":"create","resource":"pods"}}}}}}\' 2>/dev/null'
    result2 = await runner.run(cmd2, "k8s_rbac_check", target, Phase.POST_EXPLOITATION, timeout=15)

    return {
        "target": target,
        "namespaces": result.raw_output,
        "permissions_check": result2.raw_output[:2000],
    }
