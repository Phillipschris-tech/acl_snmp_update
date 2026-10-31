"""
ACL and SNMP Host Update Script

Connects to a list of Cisco IOS switches via SSH (Netmiko), rebuilds a
standard management ACL, and updates SNMP trap host entries. Results are
logged per-device to success/failure CSVs.

Device list, ACL entries, and SNMP hosts are NOT hardcoded here — see
devices.example.csv and the ACL_ENTRIES / SNMP_HOSTS placeholders below.
Copy devices.example.csv to devices.csv (gitignored) before running.

ACL rebuild sequencing:
  This rebuilds the ACL in place (delete, then recreate under the same
  number) as consecutive lines in a single send_config_set call. That
  leaves a brief window — roughly one SSH round-trip — where the ACL
  doesn't exist, during which anything referencing it (e.g. "access-class
  N in" on the vty lines) has nothing to filter against.

  This is an accepted tradeoff, not an oversight: SSH access to these
  devices is already gated by TACACS+ authentication and a jump host, so
  the ACL is a secondary control, not the only one. A zero-window staging
  approach (build under a temp ACL number, re-point references, delete the
  old ACL, rebuild under the real number, re-point back) was evaluated and
  rejected — it closes a sub-second gap already covered by TACACS+/jump
  host, at the cost of more re-point steps and more ways to misconfigure
  3,500+ production devices. If this script is reused somewhere WITHOUT an
  equivalent secondary control in front of SSH access, redo this tradeoff.
"""

from netmiko import ConnectHandler
from netmiko.exceptions import NetMikoTimeoutException, NetMikoAuthenticationException, SSHException
import csv
import getpass
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DEVICES_FILE = BASE_DIR / "devices.csv"
success_file = str(BASE_DIR / "success.csv")
failure_file = str(BASE_DIR / "failures.csv")

print("Writing success to:", success_file)
print("Writing failures to:", failure_file)

# ---------------------------
# Logging Setup
# ---------------------------
# Netmiko/Paramiko debug log is OFF by default. It logs raw channel writes,
# which can include the enable secret. Only turn on for troubleshooting,
# and delete the file when you're done.
DEBUG_NETMIKO = False
if DEBUG_NETMIKO:
    logging.basicConfig(filename='netmiko_debug.log', level=logging.DEBUG)

# Application log: INFO level, rotated (keeps last 3 files, ~1MB each)
app_logger = logging.getLogger("acl_update")
app_logger.setLevel(logging.INFO)
handler = RotatingFileHandler("run.log", maxBytes=1_000_000, backupCount=3)
formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
handler.setFormatter(formatter)
app_logger.addHandler(handler)

# ---------------------------
# Credentials
# ---------------------------
username = input("Enter your SSH username: ")
password = getpass.getpass("Enter your SSH password: ")
secret = getpass.getpass("Enter enable password (press Enter if none): ") or None

# ---------------------------
# Load hosts from CSV (header = host)
# ---------------------------
hosts = []
with open(DEVICES_FILE, newline='') as f:
    reader = csv.DictReader(f)
    if not reader.fieldnames or "host" not in reader.fieldnames:
        raise SystemExit("CSV must have a header named 'host'. First row should be: host")
    for row in reader:
        host = (row.get("host") or "").strip()
        if host:
            hosts.append(host)

if not hosts:
    raise SystemExit(f"No hosts found in {DEVICES_FILE.name}. Ensure at least one host under header 'host'.")

app_logger.info(f"Loaded {len(hosts)} hosts: {hosts}")

# ---------------------------
# ACL / SNMP settings (placeholders — edit for your environment)
# ---------------------------
ACL_NUMBER = 10

ACL_ENTRIES = [
    "permit 192.0.2.0 0.0.0.255",   # example: jump host subnet
    "permit 198.51.100.10",          # example: monitoring server
    "deny any log",
]

SNMP_HOST_REMOVALS = [
    "203.0.113.5",     # example: decommissioned monitoring host
]
SNMP_HOST_ADDS = [
    ("198.51.100.10", "EXAMPLE-RO", "2c"),   # (address, community, version)
]

# ---------------------------
# Config commands (NO 'conf t'/'end'/'wr' here — send_config_set handles that)
# ---------------------------
config_commands = []

# ACL rebuild — see module docstring for why this window is an accepted
# tradeoff in this environment (TACACS+ + jump host as the primary control).
config_commands.append(f"no ip access-list standard {ACL_NUMBER}")
config_commands.append(f"ip access-list standard {ACL_NUMBER}")
config_commands.extend(f" {entry}" for entry in ACL_ENTRIES)
config_commands.append("exit")

# SNMP host updates.
for addr in SNMP_HOST_REMOVALS:
    config_commands.append(f"no snmp-server host {addr}")
for addr, community, version in SNMP_HOST_ADDS:
    config_commands.append(f"snmp-server host {addr} version {version} {community}")

# Optional verification commands after config
verify_commands = [
    f"show ip access-lists {ACL_NUMBER}",
    "show run | include access-class",
    "show run | include snmp-server host",
]

# ---------------------------
# Result files
# ---------------------------
# Initialize CSV headers (create or overwrite each run)
with open(success_file, "w", newline="") as sf:
    writer = csv.writer(sf)
    writer.writerow(["timestamp", "host", "status", "details"])

with open(failure_file, "w", newline="") as ff:
    writer = csv.writer(ff)
    writer.writerow(["timestamp", "host", "error_type", "error_message"])

# ---------------------------
# Processing
# ---------------------------
fail_count = 0
success_count = 0
start_time = datetime.now()

for host in hosts:
    print(f"\n=== Connecting to {host} ===")
    app_logger.info(f"Connecting to {host}")

    device = {
        "device_type": "cisco_ios",
        "host": host,
        "username": username,
        "password": password,
        "allow_agent": False,
        "look_for_keys": False,
        "banner_timeout": 60,
        "auth_timeout": 30,
        "timeout": 30,
        "secret": secret or "",
    }

    try:
        conn = ConnectHandler(**device)

        # Enter enable mode if provided
        if secret:
            conn.enable()

        # Apply configuration
        app_logger.info(f"Applying configuration to {host}")
        cfg_out = conn.send_config_set(config_commands)
        app_logger.info(f"Config applied to {host}")
        print(cfg_out)

        # Fail loudly if IOS rejected any line instead of logging it as success.
        if any(marker in cfg_out for marker in ("% Invalid", "% Incomplete", "% Ambiguous", "% Error")):
            raise RuntimeError(f"IOS rejected part of the config on {host}:\n{cfg_out}")

        # Save configuration
        try:
            conn.save_config()
            app_logger.info(f"Configuration saved on {host}")
        except Exception as save_e:
            app_logger.warning(f"save_config not supported or failed on {host}: {save_e}")

        # Verification
        verify_output = []
        for cmd in verify_commands:
            out = conn.send_command(cmd, expect_string=r"#|>")
            verify_output.append(out)
            app_logger.info(f"[{host}] VERIFY '{cmd}': {out.strip()}")

        conn.disconnect()
        print(f"Completed on {host}")
        app_logger.info(f"Completed on {host}")

        with open(success_file, "a", newline="") as sf:
            writer = csv.writer(sf)
            writer.writerow([datetime.now().isoformat(timespec="seconds"), host, "success", "config+save+verify"])

        success_count += 1

    except NetMikoAuthenticationException as ae:
        print(f"Auth failed on {host}: {ae}")
        app_logger.error(f"Auth failed on {host}: {ae}")
        with open(failure_file, "a", newline="") as ff:
            writer = csv.writer(ff)
            writer.writerow([datetime.now().isoformat(timespec="seconds"), host, "Authentication", str(ae)])
        fail_count += 1

    except NetMikoTimeoutException as te:
        print(f"Timeout to {host}: {te}")
        app_logger.error(f"Timeout to {host}: {te}")
        with open(failure_file, "a", newline="") as ff:
            writer = csv.writer(ff)
            writer.writerow([datetime.now().isoformat(timespec="seconds"), host, "Timeout", str(te)])
        fail_count += 1

    except Exception as e:
        print(f"General SSH/Paramiko error on {host}: {e}")
        app_logger.exception(f"General SSH/Paramiko error on {host}: {e}")
        with open(failure_file, "a", newline="") as ff:
            writer = csv.writer(ff)
            writer.writerow([datetime.now().isoformat(timespec="seconds"), host, "GeneralError", str(e)])
        fail_count += 1

# ---------------------------
# Summary
# ---------------------------
duration = (datetime.now() - start_time).total_seconds()
summary = f"Run summary: success={success_count}, failed={fail_count}, total={len(hosts)}, duration={duration:.1f}s"
print("\n" + summary)
app_logger.info(summary)
print(f"Details: success -> {success_file}, failures -> {failure_file}, app log -> run.log")