"""Cloud Security testing tools — evidence-based validation."""

from __future__ import annotations

import json
import re

from kambo.docker_runner import get_runner
from kambo.metrics import get_metrics
from kambo.models import (
    Confidence,
    EvidenceChain,
    Phase,
    chain_rank,
    confidence_meets,
)
from kambo.scope import validate_scope
from kambo.validation import validate_ssrf


async def cloud_imds_test(
    target: str,
    parameter: str = "url",
    cloud_provider: str = "aws",
) -> dict:
    """Test SSRF to cloud metadata service (IMDS) with content validation.

    Validates response contains actual metadata, not just a 200 status.

    Args:
        target: URL with potential SSRF vulnerability
        parameter: Parameter to inject metadata URL into
        cloud_provider: aws, azure, gcp
    """
    validate_scope(target)
    runner = get_runner()
    metrics = get_metrics()

    metadata_urls = {
        "aws": [
            ("http://169.254.169.254/latest/meta-data/", "Instance metadata root"),
            ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "IAM credentials"),
            ("http://169.254.169.254/latest/user-data", "User data (may contain secrets)"),
        ],
        "azure": [
            ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Instance metadata"),
            ("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", "Managed identity token"),
        ],
        "gcp": [
            ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "Service account token"),
            ("http://metadata.google.internal/computeMetadata/v1/project/project-id", "Project ID"),
        ],
    }

    urls = metadata_urls.get(cloud_provider, metadata_urls["aws"])
    best_chain = EvidenceChain()
    results = []

    for meta_url, description in urls:
        url = target if target.startswith("http") else f"https://{target}"
        cmd = f'curl -s -D - "{url}?{parameter}={meta_url}" 2>/dev/null'
        result = await runner.run(cmd, "cloud_imds_test", target, Phase.VULN_ANALYSIS, timeout=15)

        status_match = re.search(r"HTTP/\d\.?\d?\s+(\d{3})", result.raw_output)
        status = status_match.group(1) if status_match else "000"

        chain = validate_ssrf(meta_url, status, result.raw_output)

        results.append({
            "metadata_url": meta_url,
            "description": description,
            "status": status,
            "confidence": chain.confidence.value,
            "evidence": chain.summary(),
            "response_preview": result.raw_output[:1000],
        })

        # Rank by effective confidence first (honors the I3 cap), then weight.
        if chain_rank(chain) > chain_rank(best_chain):
            best_chain = chain

    metrics.record_run("cloud_imds_test")
    if best_chain.total_weight > 0:
        metrics.record_finding("cloud_imds_test", best_chain.confidence, best_chain.total_weight)

    return {
        "target": target,
        "cloud_provider": cloud_provider,
        # IMDS SSRF is a blind class: without an OOB hit it stays TENTATIVE (I3).
        "vulnerable": confidence_meets(best_chain.confidence, Confidence.FIRM),
        "confidence": best_chain.confidence.value,
        "evidence": best_chain.summary(),
        "results": results,
    }


async def cloud_storage_enum(
    target: str,
    cloud_provider: str = "aws",
) -> dict:
    """Enumerate cloud storage with public access verification.

    Goes beyond status codes — actually checks if listing or downloading
    objects is possible.

    Args:
        target: Organization/domain name to derive bucket names
        cloud_provider: aws, azure, gcp
    """
    validate_scope(target)
    runner = get_runner()
    metrics = get_metrics()

    base = target.replace(".", "-").replace(" ", "-").lower()
    variations = [
        base, f"{base}-dev", f"{base}-staging", f"{base}-prod",
        f"{base}-backup", f"{base}-assets", f"{base}-uploads",
        f"{base}-data", f"{base}-public", f"{base}-private",
    ]

    chain = EvidenceChain()
    results = []

    if cloud_provider == "aws":
        for bucket in variations:
            # Check existence and access level
            cmd = f'curl -s -D - "https://{bucket}.s3.amazonaws.com" 2>/dev/null'
            result = await runner.run(cmd, "cloud_storage_enum", target, Phase.RECON, timeout=10)

            status_match = re.search(r"HTTP/\d\.?\d?\s+(\d{3})", result.raw_output)
            status = status_match.group(1) if status_match else "000"

            if status == "200":
                # 200 — check if it's a directory listing
                if "<ListBucketResult" in result.raw_output:
                    chain = chain.add(
                        signal=f"S3 bucket '{bucket}' is publicly listable",
                        source="s3_enum",
                        raw_data=result.raw_output[:500],
                        weight=1.5,
                    )
                    results.append({"bucket": bucket, "status": "200", "public": True, "listable": True})
                else:
                    chain = chain.add(
                        signal=f"S3 bucket '{bucket}' responds 200 but not listable",
                        source="s3_enum",
                        weight=0.3,
                    )
                    results.append({"bucket": bucket, "status": "200", "public": True, "listable": False})
            elif status == "403":
                # Exists but not public
                results.append({"bucket": bucket, "status": "403", "public": False, "listable": False})
            # 404 = doesn't exist, skip

    elif cloud_provider == "azure":
        for name in variations:
            cmd = f'curl -s -D - "https://{name}.blob.core.windows.net/?comp=list" 2>/dev/null'
            result = await runner.run(cmd, "cloud_storage_enum", target, Phase.RECON, timeout=10)

            status_match = re.search(r"HTTP/\d\.?\d?\s+(\d{3})", result.raw_output)
            status = status_match.group(1) if status_match else "000"

            if status == "200" and "<EnumerationResults" in result.raw_output:
                chain = chain.add(
                    signal=f"Azure container '{name}' is publicly listable",
                    source="azure_enum",
                    raw_data=result.raw_output[:500],
                    weight=1.5,
                )
                results.append({"container": name, "status": status, "public": True})
            elif status != "404":
                results.append({"container": name, "status": status, "public": False})

    elif cloud_provider == "gcp":
        for name in variations:
            cmd = f'curl -s -D - "https://storage.googleapis.com/{name}" 2>/dev/null'
            result = await runner.run(cmd, "cloud_storage_enum", target, Phase.RECON, timeout=10)

            status_match = re.search(r"HTTP/\d\.?\d?\s+(\d{3})", result.raw_output)
            status = status_match.group(1) if status_match else "000"

            if status == "200":
                chain = chain.add(
                    signal=f"GCS bucket '{name}' is publicly accessible",
                    source="gcs_enum",
                    raw_data=result.raw_output[:500],
                    weight=1.5,
                )
                results.append({"bucket": name, "status": status, "public": True})

    metrics.record_run("cloud_storage_enum")
    if chain.total_weight > 0:
        metrics.record_finding("cloud_storage_enum", chain.confidence, chain.total_weight)

    return {
        "target": target,
        "cloud_provider": cloud_provider,
        "vulnerable": chain.total_weight >= 1.0,
        "confidence": chain.confidence.value,
        "evidence": chain.summary(),
        "found": results,
        "total_checked": len(variations),
    }


async def cloud_secret_scan(
    target: str,
    repo_url: str = "",
) -> dict:
    """Scan for exposed secrets with severity weighting.

    Verified secrets get high weight; unverified get lower weight.
    Different secret types have different impact levels.

    Args:
        target: Target identifier (for scope)
        repo_url: Git repository URL to scan
    """
    validate_scope(target)
    runner = get_runner()
    metrics = get_metrics()

    if repo_url:
        cmd = f"trufflehog git {repo_url} --json 2>/dev/null | head -100"
    else:
        cmd = f"trufflehog filesystem /output --json 2>/dev/null | head -100"

    result = await runner.run(cmd, "cloud_secret_scan", target, Phase.VULN_ANALYSIS, timeout=120)

    chain = EvidenceChain()
    secrets = []

    # High-impact secret types
    critical_types = {"aws", "gcp", "azure", "private_key", "github", "slack", "stripe", "twilio"}
    medium_types = {"generic", "jwt", "password", "api_key"}

    for line in result.raw_output.splitlines():
        try:
            entry = json.loads(line)
            detector = entry.get("DetectorName", "unknown").lower()
            verified = entry.get("Verified", False)
            file_path = entry.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", "")

            secret_info = {
                "type": entry.get("DetectorName", "unknown"),
                "file": file_path,
                "verified": verified,
            }
            secrets.append(secret_info)

            if verified:
                weight = 2.0 if any(t in detector for t in critical_types) else 1.5
                chain = chain.add(
                    signal=f"VERIFIED secret ({entry.get('DetectorName', 'unknown')}) in {file_path}",
                    source="trufflehog",
                    raw_data=f"Detector: {detector}, Verified: True",
                    weight=weight,
                )
            else:
                weight = 0.5 if any(t in detector for t in critical_types) else 0.2
                chain = chain.add(
                    signal=f"Unverified secret ({entry.get('DetectorName', 'unknown')}) in {file_path}",
                    source="trufflehog",
                    weight=weight,
                )
        except (json.JSONDecodeError, KeyError):
            continue

    # Liveness gate (doctrine §3 / §5): a secret with no liveness check is capped
    # at TENTATIVE for valuation, no matter how many unverified hits piled up
    # weight. Only an actually-verified (live) secret lifts the cap.
    verified_count = sum(1 for s in secrets if s.get("verified"))
    if secrets and verified_count == 0:
        chain = chain.cap(
            Confidence.TENTATIVE,
            "Secret(s) found but none passed a liveness/verification check — "
            "a dead or placeholder secret has no value (§5)",
        )

    metrics.record_run("cloud_secret_scan")
    if chain.total_weight > 0:
        metrics.record_finding("cloud_secret_scan", chain.confidence, chain.total_weight)

    return {
        "target": target,
        # Verdict honors the ceiling — unverified-only secrets are not "vulnerable".
        "vulnerable": confidence_meets(chain.confidence, Confidence.FIRM),
        "confidence": chain.confidence.value,
        "evidence": chain.summary(),
        "secrets_found": len(secrets),
        "secrets": secrets,
        "verified_count": verified_count,
    }
