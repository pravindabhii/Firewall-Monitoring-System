
import subprocess
import ctypes
import ipaddress


# ==========================================
# CHECK ADMINISTRATOR
# ==========================================

def is_admin():
    """Check whether Python is running as Administrator."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


# ==========================================
# VALIDATE IP ADDRESS
# ==========================================

def validate_ip(ip):
    """Validate and normalize IPv4 or IPv6."""
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except (ValueError, AttributeError):
        return None


# ==========================================
# FIREWALL RULE NAME
# ==========================================

def get_rule_name(ip):
    safe_ip = ip.replace(":", "-").replace(".", "-")
    return f"PRAVIN-FW-BLOCK-{safe_ip}"


# ==========================================
# BLOCK IP
# ==========================================

def block_ip(ip):

    if not is_admin():
        return False, "Run VS Code as Administrator."

    ip = validate_ip(ip)

    if not ip:
        return False, "Invalid IP address."

    rule_name = get_rule_name(ip)

    command = (
        f"if (Get-NetFirewallRule -PolicyStore PersistentStore "
        f"-DisplayName '{rule_name}' -ErrorAction SilentlyContinue) "
        f"{{ Write-Output 'RULE_EXISTS' }} "
        f"else {{ "
        f"New-NetFirewallRule "
        f"-PolicyStore PersistentStore "
        f"-DisplayName '{rule_name}' "
        f"-Direction Inbound "
        f"-RemoteAddress '{ip}' "
        f"-Action Block "
        f"-Profile Any "
        f"-Enabled True | Out-Null; "
        f"Write-Output 'BLOCKED' }}"
    )

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True,
            text=True,
            timeout=15
        )

        if result.returncode != 0:
            return False, result.stderr.strip() or "Firewall operation failed."

        output = result.stdout.strip()

        if "RULE_EXISTS" in output:
            return True, f"{ip} is already blocked."

        if "BLOCKED" in output:
            return True, f"{ip} blocked successfully."

        return False, output or "Could not verify firewall rule."

    except Exception as error:
        return False, str(error)


# ==========================================
# UNBLOCK IP
# ==========================================

def unblock_ip(ip):

    if not is_admin():
        return False, "Run VS Code as Administrator."

    ip = validate_ip(ip)

    if not ip:
        return False, "Invalid IP address."

    rule_name = get_rule_name(ip)

    command = (
        f"$rule = Get-NetFirewallRule "
        f"-PolicyStore PersistentStore "
        f"-DisplayName '{rule_name}' "
        f"-ErrorAction SilentlyContinue; "
        f"if ($rule) {{ "
        f"$rule | Remove-NetFirewallRule; "
        f"Write-Output 'UNBLOCKED' "
        f"}} else {{ Write-Output 'NOT_FOUND' }}"
    )

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True,
            text=True,
            timeout=15
        )

        if result.returncode != 0:
            return False, result.stderr.strip() or "Unblock operation failed."

        output = result.stdout.strip()

        if "UNBLOCKED" in output:
            return True, f"{ip} unblocked successfully."

        if "NOT_FOUND" in output:
            return False, f"No PRAVIN block rule found for {ip}."

        return False, output or "Could not verify firewall rule."

    except Exception as error:
        return False, str(error)


# ==========================================
# GET BLOCKED IP LIST
# ==========================================

def get_blocked_ips():

    if not is_admin():
        return []

    command = (
        "$rules = Get-NetFirewallRule "
        "-PolicyStore PersistentStore "
        "| Where-Object {$_.DisplayName -like 'PRAVIN-FW-BLOCK-*'}; "
        "foreach ($rule in $rules) { "
        "Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule "
        "| Select-Object -ExpandProperty RemoteAddress "
        "}"
    )

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True,
            text=True,
            timeout=15
        )

        if result.returncode != 0:
            return []

        blocked_ips = []

        for line in result.stdout.splitlines():
            ip = line.strip()

            if ip and ip not in blocked_ips:
                blocked_ips.append(ip)

        return blocked_ips

    except Exception:
        return []
