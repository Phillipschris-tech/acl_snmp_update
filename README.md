# cisco-acl-snmp-update

A Python/Netmiko script that pushes a standard management ACL and SNMP trap-host changes to a list of Cisco IOS switches over SSH, then verifies and logs the result per device.

The code is short. Most of the work went into the operational security decisions around it, which are documented below.

> Tested in a lab environment. Not validated against every IOS/IOS-XE release. Read the Known limitations section before pointing it at anything you care about.

## What it does

For each host in `devices.csv`, the script:

1. Connects over SSH (Netmiko, `cisco_ios`) and enters enable mode if a secret is provided.
2. Deletes and rebuilds standard ACL `ACL_NUMBER` from `ACL_ENTRIES`.
3. Removes the SNMP hosts in `SNMP_HOST_REMOVALS` and adds the ones in `SNMP_HOST_ADDS`.
4. Checks the device output for IOS rejection markers (`% Invalid`, `% Incomplete`, `% Ambiguous`, `% Error`). If any line was rejected, it marks the device as failed and **does not save the config**.
5. Saves the config, runs verification `show` commands, and logs the output.
6. Writes one row per device to `success.csv` or `failures.csv`, then prints a run summary.

## Security design decisions

**No secrets in code or arguments.** The username, password, and enable secret are prompted with `getpass` at runtime. Nothing is hardcoded, read from environment variables, or passed on the command line, where it would end up in shell history.

**Debug logging is off by default.** Netmiko/Paramiko debug logging records raw channel writes, which can include the enable secret. It is gated behind `DEBUG_NETMIKO = False`. If you turn it on to troubleshoot, delete `netmiko_debug.log` when you are done.

**Fail loudly, not silently.** IOS often accepts a config session even when individual lines were rejected. Without the rejection check, a device with a broken ACL would be logged as a success. Here, a rejected line raises an error, skips the save, and gets logged as a failure.

**Inventory and site data stay out of the repo.** Real hostnames, ACL entries, and SNMP hosts are never committed. The repo ships `devices.example.csv` and uses RFC 5737 documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) as placeholders. `devices.csv` and all output files are gitignored.

**An explicitly accepted risk: the ACL rebuild window.** The ACL is rebuilt in place (`no ip access-list standard N`, then recreated) in a single config session. For roughly one SSH round-trip, the ACL does not exist, so anything referencing it (for example `access-class N in` on the vty lines) is not filtered.

This is an accepted tradeoff, not an oversight. It is acceptable only when SSH access is already gated by a primary control, such as centralized AAA and a restricted management path, so this ACL is a secondary control. A zero-window staging approach was evaluated and rejected:

1. Build the ACL under a temporary number.
2. Re-point references to the temporary ACL.
3. Delete the old ACL.
4. Rebuild it under the real number.
5. Re-point references back.

That approach closes a sub-second gap at the cost of more steps and more ways to misconfigure a large fleet. **If you run this script without an equivalent primary control in front of SSH, redo this tradeoff.**

## Requirements

- Python 3.9+
- `netmiko` (see `requirements.txt`)
- SSH reachability to the target devices and an account with privilege to change config

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Setup

1. Copy the example inventory and add your devices. The first row must be the header `host`.

   ```bash
   cp devices.example.csv devices.csv
   ```

2. Edit the placeholders near the top of `acl_snmp_update.py`:

   | Setting | Purpose |
   |---|---|
   | `ACL_NUMBER` | Standard ACL number to rebuild |
   | `ACL_ENTRIES` | ACL lines, in order |
   | `SNMP_HOST_REMOVALS` | SNMP trap hosts to remove |
   | `SNMP_HOST_ADDS` | `(address, community, version)` tuples to add |

3. Test against **one** lab device before running against a list.

## Usage

```bash
python3 acl_snmp_update.py
```

You will be prompted for the SSH username, password, and enable secret. Press Enter at the enable prompt if there is none.

## Output

| File | Contents |
|---|---|
| `success.csv` | timestamp, host, status, details |
| `failures.csv` | timestamp, host, error type, error message |
| `run.log` | Application log, rotated at ~1 MB, 3 backups kept |

`success.csv` and `failures.csv` are overwritten on each run.

**Treat the output files as sensitive.** Two things end up in them:

- Verification output (`show run | include snmp-server host`) is written to `run.log`.
- On a rejected config, the full device output goes to `run.log` and `failures.csv`.

With SNMPv2c, both can contain **community strings in plaintext**, so keep these files out of version control and off shared drives.

## Known limitations

- **No rollback.** If a line is rejected partway through, the earlier lines (including the `no ip access-list` delete) have already been applied to the running config. The script does not save in that case, so a reload restores the startup config. Until then, the device may have a partial or empty ACL on its vty lines. Check any device that shows up in `failures.csv` with a rejection error immediately.
- **Sequential.** Devices are processed one at a time, so large inventories take a while.
- **No dry-run mode.** The script changes devices as soon as you run it.
- **Verification is logged, not asserted.** `show` output is recorded but not compared against the intended config.
- **SNMPv2c.** The example uses v2c community strings, which travel in plaintext. Prefer SNMPv3 (authPriv) where your platform supports it.
- **One credential set** is used for every device.

## Roadmap

- Validate each line as it is sent (`send_config_set(..., error_pattern=...)`) and roll back on rejection.
- Dry-run mode that prints the commands per device without connecting.
- Assert verification output against the intended ACL and SNMP state.
- Concurrency with a configurable worker limit.
- SNMPv3 support.

## License

MIT. See `LICENSE`.
