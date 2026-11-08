"""What runs on each host, and the scripts that control it."""

import json
import math
import re
import shlex

# Read-only: lists containers, running services and Proxmox guests. Sections are marked `##name`.
SCAN_SCRIPT = """\
echo '##docker'
if command -v docker >/dev/null 2>&1; then docker ps -a --format '{"Names":{{json .Names}},"State":{{json .State}},"Status":{{json .Status}},"Image":{{json .Image}},"Ports":{{json .Ports}},"ComposeDir":{{json (.Label "com.docker.compose.project.working_dir")}},"ComposeService":{{json (.Label "com.docker.compose.service")}}}' 2>/dev/null || echo '##warning docker_unreadable'; fi
echo '##systemd'; systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null
echo '##qm'; command -v qm >/dev/null 2>&1 && qm list 2>/dev/null
echo '##pct'; command -v pct >/dev/null 2>&1 && pct list 2>/dev/null
echo '##facts'
echo "cores=$(nproc 2>/dev/null)"
awk '{print "load1=" $1}' /proc/loadavg 2>/dev/null
awk '{printf "uptime_s=%d\\n", $1}' /proc/uptime 2>/dev/null
awk '/^MemTotal:/{t=$2} /^MemAvailable:/{a=$2} END{if (t) printf "mem_total_gb=%.1f\\nmem_used_gb=%.1f\\n", t/1048576, (t-a)/1048576}' /proc/meminfo 2>/dev/null
df -Pk / 2>/dev/null | awk 'NR==2{sub("%", "", $5); printf "disk_total_gb=%.1f\\ndisk_used_gb=%.1f\\ndisk_pct=%s\\n", $2/1048576, $3/1048576, $5}'
(. /etc/os-release 2>/dev/null && echo "os=$PRETTY_NAME")
true
"""

# ponytail: name list of OS plumbing to hide; anything else running shows up as a service.
OS_UNITS = re.compile(
    r"^(systemd-|getty@|serial-getty@|user@|dbus|cron|polkit|ssh|containerd|docker|qemu-guest-agent|"
    r"unattended-upgrades|rsyslog|irqbalance|multipathd|networkd-dispatcher|snapd|udisks2|ModemManager|"
    r"accounts-daemon|chrony|atd|lvm2|rpc-statd|rpcbind|smartd|smartmontools|ksmtuned|pve|qmeventd|"
    r"rrdcached|corosync|lxc|lxcfs|postfix|zfs|watchdog-mux|spiceproxy|proxmox|iscsid|open-iscsi|"
    r"blk-availability|cloud-|fwupd|thermald|wpa_supplicant|NetworkManager|avahi|cups)"
)


MAX_SERVICES, MAX_TEXT = 2000, 512  # per machine; anything past this is dropped and flagged
FACT_KEYS = {"cores", "load1", "uptime_s", "mem_total_gb", "mem_used_gb", "disk_total_gb", "disk_used_gb", "disk_pct", "os"}
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]+")


def _one_line(value, limit=MAX_TEXT):
    """Machine-supplied text as one printable line: it can't start a line of its own in an alert, and a
    `MEDIA:` tag in it is no longer one (Hermes would attach the file it names to the delivered alert)."""
    return re.sub("(?i)media:", "MEDIA :", CONTROL_RE.sub(" ", str(value or ""))).strip()[:limit]


def parse_scan(output):
    """Scan output → {"services": [{kind, name, state, detail, ...}], "facts": {cores, load1, ...}, "warnings": [...]}.
    Bounded and one-line per field, whatever the machine sends."""
    found, facts, warnings, section = [], {}, [], None

    def keep(record):
        if len(found) < MAX_SERVICES and all(len(str(v or "")) <= MAX_TEXT for v in record.values()):
            found.append({k: _one_line(v) for k, v in record.items()})
        elif "too_much_output" not in warnings:
            warnings.append("too_much_output")

    for line in output.splitlines():
        if line.startswith("##warning "):
            code = line[len("##warning "):].strip()
            if code in WARNINGS and code not in warnings:
                warnings.append(code)
            continue
        if line.startswith("##"):
            section = line[2:].strip()
            continue
        parts = line.split()
        if not parts:
            continue
        if section == "facts" and "=" in line:
            key, value = line.split("=", 1)
            if key in FACT_KEYS:
                facts[key] = _one_line(value) if key == "os" else _number(value)
        elif section == "docker":
            try:
                c = json.loads(line)
            except (ValueError, RecursionError):
                continue
            if isinstance(c, dict):
                keep({"kind": "docker", "name": c.get("Names"), "state": c.get("State"), "detail": c.get("Status"),
                      "image": c.get("Image"), "ports": c.get("Ports"),
                      "compose_dir": c.get("ComposeDir"), "compose_service": c.get("ComposeService")})
        elif section == "systemd" and parts[0].endswith(".service") and not OS_UNITS.match(parts[0]):
            keep({"kind": "systemd", "name": parts[0][:-len(".service")], "state": parts[3] if len(parts) > 3 else "",
                  "detail": " ".join(parts[4:])})
        elif section in ("qm", "pct") and parts[0].isdigit() and len(parts) >= 3:
            vm = section == "qm"  # qm: VMID NAME STATUS ...; pct: VMID STATUS [LOCK] NAME
            keep({"kind": "vm" if vm else "ct", "name": parts[1] if vm else parts[-1], "id": parts[0],
                  "state": parts[2] if vm else parts[1], "detail": "Proxmox " + ("VM" if vm else "container")})
    facts = {k: v for k, v in facts.items() if v not in (None, "")}
    if "cores" not in facts and "no_usage" not in warnings:
        warnings.append("no_usage")
    return {"services": found, "facts": facts, "warnings": warnings}


WARNINGS = {
    "docker_unreadable": ("containers hidden: this user can't read Docker", "Add the user to the docker group."),
    "no_usage": ("no usage numbers on this system", "Usage needs Linux /proc; services still show."),
    "too_much_output": ("some services hidden: this machine reported more than hostbook keeps",
                        "Check what runs there; hostbook keeps 2000 services per machine."),
}

# (pattern in ssh's output, code, message, fix). First match wins; formatted with target/address/port.
ERRORS = [
    (r"Permission denied \(publickey|Permission denied, please try again|Too many authentication failures",
     "key_refused", "key refused", "Copy your key with `ssh-copy-id {target}`, or set this machine's key file."),
    (r"Connection refused", "port_closed", "SSH isn't answering on port {port}",
     "Start the SSH server there, or set the right port."),
    (r"REMOTE HOST IDENTIFICATION HAS CHANGED|Host key verification failed", "host_key",
     "this machine's identity changed",
     "If you rebuilt it, run `ssh-keygen -R {address}`. If not, don't connect until you know why."),
    (r"Could not resolve hostname|Name or service not known|nodename nor servname", "dns", "name not found",
     "Use its IP address instead."),
    (r"timed out|No route to host|Network is unreachable|Host is down", "unreachable", "not reachable",
     "Check it's on and on the same network as Hermes."),
]


def classify(text, spec):
    """ssh/scan failure output → {code, message, fix} a person can act on."""
    fields = {"address": spec.get("address", ""), "port": spec.get("port", 22),
              "target": (spec["user"] + "@" if spec.get("user") else "") + spec.get("address", "")}
    for pattern, code, message, fix in ERRORS:
        if re.search(pattern, text or "", re.I):
            return {"code": code, "message": message.format(**fields), "fix": fix.format(**fields)}
    last = [ln for ln in (text or "").strip().splitlines() if ln.strip()][-1:] or ["no output"]
    return {"code": "scan_failed", "message": "scan failed: " + _one_line(last[0], 160),
            "fix": "Run `hermes hostbook scan` to see the full output."}


def _number(value):
    try:
        number = float(value)
    except ValueError:
        return None
    return number if math.isfinite(number) else None  # nan and inf would break the page's JSON


def diff(host, before, after, disk_alert=90):
    """What changed between two scans of one host, as alert lines. Only transitions, never steady state."""
    if after.get("error"):
        return [] if before.get("error") else [f"{host}: {after['error']}. {after.get('fix', '')}".strip()]
    lines = []
    if before.get("error"):
        lines.append(f"{host}: reachable again")
    was = {(s["kind"], s["name"]): s["state"] for s in before.get("services", [])}
    now = {(s["kind"], s["name"]): s["state"] for s in after.get("services", [])}
    for key, state in sorted(was.items()):
        label = f"{key[1]} ({KINDS.get(key[0], key[0])})"
        if state == "running" and key not in now:
            lines.append(f"{host}: {label} is gone")
        elif state == "running" and now[key] != "running":
            lines.append(f"{host}: {label} is {now[key]}")
        elif state != "running" and now.get(key) == "running":
            lines.append(f"{host}: {label} is running again")
    old, new = before.get("facts", {}).get("disk_pct"), after.get("facts", {}).get("disk_pct")
    if new is not None and (old or 0) < disk_alert <= new:
        lines.append(f"{host}: disk at {new:.0f}%")
    elif old is not None and new is not None and old >= disk_alert > new:
        lines.append(f"{host}: disk back to {new:.0f}%")
    return lines


KINDS = {"docker": "container", "systemd": "service", "vm": "VM", "ct": "LXC"}

# Read-only "more info" for one service. @@NAME@@ is replaced with the quoted name or guest id.
DETAILS = {
    "docker": """\
docker inspect -f 'image={{.Config.Image}}
started={{.State.StartedAt}}
health={{if .State.Health}}{{.State.Health.Status}}{{end}}
restarts={{.RestartCount}}
ports={{range $p, $b := .NetworkSettings.Ports}}{{$p}}{{if $b}}->{{(index $b 0).HostPort}}{{end}} {{end}}
mounts={{range .Mounts}}{{.Destination}} {{end}}' @@NAME@@
docker stats --no-stream --format 'cpu={{.CPUPerc}}
memory={{.MemUsage}}
network={{.NetIO}}
disk io={{.BlockIO}}' @@NAME@@
echo '##logs'
docker logs --tail 15 @@NAME@@ 2>&1
""",
    "systemd": """\
systemctl show @@NAME@@.service -p Description -p ActiveState -p SubState -p ActiveEnterTimestamp -p MainPID -p MemoryCurrent -p NRestarts -p FragmentPath
echo '##logs'
journalctl -u @@NAME@@.service -n 15 --no-pager 2>&1
""",
    "vm": "qm config @@NAME@@\n",
    "ct": "pct config @@NAME@@\n",
}
HIDDEN_FIELDS = {"digest", "vmgenid", "meta", "smbios1", "cipassword", "sshkeys"}  # Proxmox noise and secrets
SYSTEMD_LABELS = {"Description": "description", "ActiveState": "state", "SubState": "sub-state",
                  "ActiveEnterTimestamp": "since", "MainPID": "pid", "MemoryCurrent": "memory",
                  "NRestarts": "restarts", "FragmentPath": "unit file"}


# Read-only: addresses of running Proxmox guests (VMs through the QEMU guest agent, LXCs through lxc-info).
DISCOVER_SCRIPT = """\
command -v qm >/dev/null 2>&1 && for id in $(qm list 2>/dev/null | awk 'NR>1 && $3=="running" {print $1}'); do echo "##vm $id"; qm guest cmd "$id" network-get-interfaces 2>/dev/null; done
command -v pct >/dev/null 2>&1 && for id in $(pct list 2>/dev/null | awk 'NR>1 && $2=="running" {print $1}'); do echo "##ct $id"; lxc-info -n "$id" -iH 2>/dev/null; done
true
"""
SKIP_IFACES = re.compile(r"^(lo|docker|br-|veth|virbr|tailscale|wg|zt|cni|flannel)")


def parse_discovery(output):
    """Discovery output → {(kind, id): [IPv4 addresses on real interfaces]}."""
    found, key, chunk = {}, None, []

    def flush():
        if not key:
            return
        text, ips = "\n".join(chunk), []
        if key[0] == "vm":
            try:
                for iface in json.loads(text or "[]"):
                    if not SKIP_IFACES.match(iface.get("name", "")):
                        ips += [a.get("ip-address") for a in iface.get("ip-addresses", []) if a.get("ip-address-type") == "ipv4"]
            except (ValueError, TypeError, AttributeError, RecursionError):
                pass
        else:
            ips = [ln.strip() for ln in chunk]
        found[key] = [ip for ip in ips if isinstance(ip, str) and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip, re.A)
                      and not ip.startswith(("127.", "169.254."))]

    for line in output.splitlines():
        if m := re.match(r"^##(vm|ct) (\d+)$", line.strip()):
            flush()
            key, chunk = (m.group(1), m.group(2)), []
        else:
            chunk.append(line)
    flush()
    return found


def detail_script(svc):
    target = svc["id"] if svc["kind"] in ("vm", "ct") else svc["name"]
    return DETAILS[svc["kind"]].replace("@@NAME@@", shlex.quote(str(target)))


def parse_details(output):
    """Details output → {"fields": [[label, value]], "logs": [lines]}."""
    fields, logs, in_logs = [], [], False
    for line in output.splitlines():
        if line.strip() == "##logs":
            in_logs = True
        elif in_logs:
            logs.append(line)
        elif m := re.match(r"^([\w .-]+?)(=|: )(.*)$", line):
            label, value = SYSTEMD_LABELS.get(m.group(1), m.group(1)), m.group(3).strip()
            if label in HIDDEN_FIELDS:
                continue
            if label == "memory" and value.isdigit():
                value = f"{int(value) / 1048576:.0f} MB"
            if value and value != "[not set]":
                fields.append([label, value])
    return {"fields": fields, "logs": logs[-15:]}
ACTIONS = ("status", "logs", "restart", "start", "stop", "update")
READ_ACTIONS = ("status", "logs")


def action_script(svc, action, user="root"):
    """Script for one action on one service, or None when the action doesn't apply."""
    kind, q = svc["kind"], shlex.quote(svc["name"])
    if kind == "docker":
        if action == "update":
            if not svc.get("compose_dir"):
                return None
            s = shlex.quote(svc.get("compose_service") or svc["name"])
            return f"cd {shlex.quote(svc['compose_dir'])} && docker compose pull {s} && docker compose up -d {s}"
        return {"status": f"docker inspect -f '{{{{.State.Status}}}} since {{{{.State.StartedAt}}}}' {q}",
                "logs": f"docker logs --tail 100 {q} 2>&1",
                "restart": f"docker restart {q}", "start": f"docker start {q}", "stop": f"docker stop {q}"}.get(action)
    if kind == "systemd":
        sudo = "" if user == "root" else "sudo -n "
        return {"status": f"systemctl status --no-pager -n 0 {q}.service",
                "logs": f"journalctl -u {q}.service -n 100 --no-pager",
                "restart": f"{sudo}systemctl restart {q}.service", "start": f"{sudo}systemctl start {q}.service",
                "stop": f"{sudo}systemctl stop {q}.service"}.get(action)
    tool, vmid = ("qm" if kind == "vm" else "pct"), shlex.quote(svc["id"])
    return {"status": f"{tool} status {vmid}", "restart": f"{tool} reboot {vmid}",
            "start": f"{tool} start {vmid}", "stop": f"{tool} shutdown {vmid}"}.get(action)


def find(catalog, ref):
    """`host/name` or a name unique across hosts → (host, service), else (None, matches)."""
    host, _, name = ref.rpartition("/")
    matches = [(h, s) for h, entry in catalog.items() for s in entry.get("services", [])
               if s["name"] == name and (not host or h == host)]
    return matches[0] if len(matches) == 1 else (None, [f"{h}/{s['name']}" for h, s in matches])
