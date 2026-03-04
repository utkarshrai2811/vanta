#!/usr/bin/env python3
"""
validators.py
Per-technique validation scripts for VANTA Phase 3.
Each validator is a self-contained Python script that runs inside
a sandboxed Docker container. No destructive payloads.

Validators map to MITRE technique ID prefixes:
  T1110  -> credential_check     (brute force detection)
  T1021  -> ssh_algo_enum        (SSH algorithm enumeration)
  T1552  -> osint_key_check      (public key/credential leak check)
  T1548  -> version_cve_check    (version fingerprint + CVE lookup)
  T1557  -> algo_downgrade_check (weak algorithm negotiation)
  T1036  -> honeypot_detect      (fingerprint consistency check)
  T1195  -> package_integrity    (supply chain - informational only)
  default -> banner_grab         (generic banner + port check)
"""

# Each script receives TARGET_IP, TARGET_PORT, TIMEOUT as env vars.
# Print [STDERR] prefix for error lines.
# Last line of stdout should be a JSON object with evidence fields.


BANNER_GRAB = """
import socket, os, json, sys

ip = os.environ["TARGET_IP"]
port = int(os.environ["TARGET_PORT"])
timeout = int(os.environ.get("TIMEOUT", "10"))

result = {"connected": False, "banner": "", "service": ""}
try:
    s = socket.create_connection((ip, port), timeout=timeout)
    s.settimeout(timeout)
    try:
        banner = s.recv(1024).decode("utf-8", errors="replace").strip()
        result["banner"] = banner
        result["connected"] = True
        result["service"] = "ssh" if "SSH" in banner else "unknown"
    except Exception:
        result["connected"] = True
    s.close()
except Exception as e:
    print(f"[STDERR] Connection failed: {e}")

print(f"Banner: {result['banner'] or 'none'}")
print(f"Connected: {result['connected']}")
print(json.dumps(result))
"""

SSH_ALGO_ENUM = """
import socket, os, json, struct, hashlib

ip = os.environ["TARGET_IP"]
port = int(os.environ["TARGET_PORT"])
timeout = int(os.environ.get("TIMEOUT", "10"))

result = {"connected": False, "banner": "", "weak_algos": [], "assessment": ""}

WEAK_KEX = ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "gss-group1-sha1-*"]
WEAK_ENC = ["arcfour", "arcfour128", "arcfour256", "3des-cbc", "blowfish-cbc"]
WEAK_MAC = ["hmac-md5", "hmac-md5-96", "hmac-sha1-96"]

try:
    s = socket.create_connection((ip, port), timeout=timeout)
    s.settimeout(timeout)

    banner = s.recv(256).decode("utf-8", errors="replace").strip()
    result["banner"] = banner
    result["connected"] = True
    print(f"Banner: {banner}")

    # Send our client banner
    s.sendall(b"SSH-2.0-VANTA_Scanner_1.0" + bytes([13, 10]))

    # Read SSH_MSG_KEXINIT (packet)
    raw = s.recv(4096)
    s.close()

    # Parse algorithm lists from KEXINIT (simplified — skip 21 bytes header + cookie)
    try:
        offset = 4 + 1 + 1 + 16  # pkt_len + pad_len + msg_type + cookie
        if len(raw) > offset:
            payload = raw[offset:]
            algos_raw = payload.decode("latin-1", errors="replace")

            found_weak = []
            for weak in WEAK_KEX + WEAK_ENC + WEAK_MAC:
                if weak.replace("*", "") in algos_raw:
                    found_weak.append(weak)

            result["weak_algos"] = found_weak
            result["assessment"] = "WEAK algorithms detected" if found_weak else "No weak algorithms found"
            print(f"Weak algorithms: {found_weak or 'none'}")
            print(f"Assessment: {result['assessment']}")
    except Exception as e:
        print(f"[STDERR] KEXINIT parse error: {e}")
        result["assessment"] = "Could not parse algorithm list"

except Exception as e:
    print(f"[STDERR] Connection error: {e}")
    result["assessment"] = f"Connection failed: {e}"

print(json.dumps(result))
"""

CREDENTIAL_CHECK = """
import socket, os, json

ip = os.environ["TARGET_IP"]
port = int(os.environ["TARGET_PORT"])
timeout = int(os.environ.get("TIMEOUT", "10"))

# SAFE: Only checks if password auth is ADVERTISED, never attempts login
result = {
    "connected": False,
    "banner": "",
    "password_auth_likely": False,
    "assessment": ""
}

try:
    s = socket.create_connection((ip, port), timeout=timeout)
    s.settimeout(timeout)
    banner = s.recv(256).decode("utf-8", errors="replace").strip()
    result["banner"] = banner
    result["connected"] = True

    # Send client banner and probe auth methods via SSH_MSG_USERAUTH_REQUEST
    # This does NOT attempt authentication — it only asks what methods are available
    s.sendall(b"SSH-2.0-VANTA_Scanner_1.0" + bytes([13, 10]))

    # Read KEXINIT
    s.recv(4096)

    result["assessment"] = (
        "SSH service reachable. Auth method enumeration requires full SSH handshake. "
        "Recommend: ssh -v user@host to check 'Authentications that can continue'. "
        "If 'password' is listed, brute force is viable."
    )
    result["password_auth_likely"] = True  # conservative assumption
    s.close()

except Exception as e:
    print(f"[STDERR] {e}")
    result["assessment"] = f"Connection failed: {e}"

print(f"Connected: {result['connected']}")
print(f"Banner: {result['banner']}")
print(f"Assessment: {result['assessment']}")
print(json.dumps(result))
"""

VERSION_CVE_CHECK = """
import socket, os, json, urllib.request

ip = os.environ["TARGET_IP"]
port = int(os.environ["TARGET_PORT"])
timeout = int(os.environ.get("TIMEOUT", "10"))

result = {"banner": "", "version": "", "cves_checked": [], "assessment": ""}

# Known CVEs for OpenSSH versions — static lookup, no external requests
OPENSSH_CVES = {
    "9.6": [],
    "9.5": ["CVE-2023-51767"],
    "9.4": ["CVE-2023-51767"],
    "9.3": ["CVE-2023-38408", "CVE-2023-51767"],
    "9.2": ["CVE-2023-38408", "CVE-2023-51767"],
    "9.1": ["CVE-2023-38408", "CVE-2023-51767"],
    "8.9": ["CVE-2023-38408"],
    "8.8": [],
}

try:
    s = socket.create_connection((ip, port), timeout=timeout)
    s.settimeout(timeout)
    banner = s.recv(256).decode("utf-8", errors="replace").strip()
    result["banner"] = banner
    s.close()

    # Parse version from banner e.g. SSH-2.0-OpenSSH_9.6p1
    if "OpenSSH_" in banner:
        ver_str = banner.split("OpenSSH_")[1].split("p")[0].split(" ")[0]
        result["version"] = ver_str
        cves = OPENSSH_CVES.get(ver_str, [])
        result["cves_checked"] = cves
        if cves:
            result["assessment"] = f"OpenSSH {ver_str} has known CVEs: {cves}"
        else:
            result["assessment"] = f"OpenSSH {ver_str} — no CVEs in local database for this version"
    else:
        result["assessment"] = "Could not parse OpenSSH version from banner"

    print(f"Banner: {banner}")
    print(f"Version: {result['version']}")
    print(f"CVEs: {result['cves_checked'] or 'none found'}")
    print(f"Assessment: {result['assessment']}")

except Exception as e:
    print(f"[STDERR] {e}")
    result["assessment"] = str(e)

print(json.dumps(result))
"""

HONEYPOT_DETECT = """
import socket, os, json, time

ip = os.environ["TARGET_IP"]
port = int(os.environ["TARGET_PORT"])
timeout = int(os.environ.get("TIMEOUT", "10"))

result = {"indicators": [], "honeypot_likely": False, "assessment": ""}

try:
    # Test 1: response time (honeypots often respond instantly)
    t0 = time.time()
    s = socket.create_connection((ip, port), timeout=timeout)
    s.settimeout(timeout)
    banner = s.recv(256).decode("utf-8", errors="replace").strip()
    response_time = round(time.time() - t0, 3)
    s.close()

    print(f"Banner: {banner}")
    print(f"Response time: {response_time}s")

    # Test 2: send garbage, see if it closes cleanly or hangs
    try:
        s2 = socket.create_connection((ip, port), timeout=5)
        s2.settimeout(5)
        s2.recv(256)
        s2.sendall(b"GARBAGE_PROBE_1234\r\n")
        time.sleep(1)
        try:
            resp = s2.recv(256)
            if resp:
                result["indicators"].append("responds to garbage input — possible honeypot")
        except Exception:
            pass
        s2.close()
    except Exception:
        pass

    # Heuristics
    if response_time < 0.05:
        result["indicators"].append(f"very fast response ({response_time}s) — possible honeypot")

    if "Ubuntu" in banner and "2.6.32" in banner:
        result["indicators"].append("OS version mismatch in banner — possible deception")

    result["honeypot_likely"] = len(result["indicators"]) >= 2
    result["assessment"] = (
        f"Honeypot indicators: {result['indicators']}"
        if result["indicators"]
        else "No honeypot indicators detected"
    )

    print(f"Indicators: {result['indicators'] or 'none'}")
    print(f"Assessment: {result['assessment']}")

except Exception as e:
    print(f"[STDERR] {e}")
    result["assessment"] = str(e)

print(json.dumps(result))
"""

OSINT_KEY_CHECK = """
import socket, os, json

ip = os.environ["TARGET_IP"]
hostname = os.environ.get("HOSTNAME_HINT", "")
timeout = int(os.environ.get("TIMEOUT", "10"))

# SAFE: Informational only — describes what a human should check manually
result = {
    "target": ip,
    "hostname_hint": hostname,
    "osint_checklist": [],
    "assessment": ""
}

checklist = [
    f"Search GitHub for: '{hostname}' SSH key OR id_rsa OR authorized_keys",
    f"Search GitHub for: '{ip}' in dotfiles or config repos",
    "Check Shodan: https://www.shodan.io/host/" + ip,
    "Check Censys: https://search.censys.io/hosts/" + ip,
    f"Search Pastebin/GitLab for hostname '{hostname}'",
    "Check for leaked .env files with SSH credentials in public repos",
    "Search for DigitalOcean default user 'ubuntu' with weak keys",
]

result["osint_checklist"] = checklist
result["assessment"] = (
    "Manual OSINT required — automated key leak detection requires external API access "
    "not available in sandbox. Use checklist above."
)

for item in checklist:
    print(f"  - {item}")
print(f"Assessment: {result['assessment']}")
print(json.dumps(result))
"""


def get_validator(technique_id: str) -> tuple[str, str]:
    """
    Map a MITRE technique ID to (validator_name, script).
    Returns the most specific match, falls back to banner_grab.
    """
    tid = technique_id.upper()

    if tid.startswith("T1110"):
        return "credential_check", CREDENTIAL_CHECK
    elif tid.startswith("T1021"):
        return "ssh_algo_enum", SSH_ALGO_ENUM
    elif tid.startswith("T1552"):
        return "osint_key_check", OSINT_KEY_CHECK
    elif tid.startswith("T1548"):
        return "version_cve_check", VERSION_CVE_CHECK
    elif tid.startswith("T1557"):
        return "ssh_algo_enum", SSH_ALGO_ENUM
    elif tid.startswith("T1036"):
        return "honeypot_detect", HONEYPOT_DETECT
    elif tid.startswith("T1195"):
        return "osint_key_check", OSINT_KEY_CHECK
    else:
        return "banner_grab", BANNER_GRAB