"""Run: python3 test_hostbook.py  (needs PyYAML; works with or without Hermes on the path)."""

import importlib.util
import os
import pathlib
import subprocess
import sys
import types

import tempfile

# Plugin data goes to a throwaway dir, inside or outside a Hermes checkout.
DATA = pathlib.Path(tempfile.mkdtemp()) / "plugin-data" / "hostbook"
DATA.mkdir(parents=True)
stub = types.ModuleType("plugins.plugin_storage")
stub.plugin_data_dir = lambda name: DATA
sys.modules.setdefault("plugins", types.ModuleType("plugins"))
sys.modules["plugins.plugin_storage"] = stub

here = pathlib.Path(__file__).parent
spec = importlib.util.spec_from_file_location("hostbook", here / "__init__.py", submodule_search_locations=[str(here)])
hb = importlib.util.module_from_spec(spec)
sys.modules["hostbook"] = hb
spec.loader.exec_module(hb)
sv = hb.services

HOSTS = {
    "media": {"address": "10.0.0.5", "user": "root", "policy": "approve"},
    "pve": {"address": "10.0.0.2", "user": "root", "policy": "read"},
    "lab": {"address": "10.0.0.9", "policy": "open", "jump": "pve"},
}

# The script reaches the remote interpreter byte-for-byte: swap ssh for a local `cat`.
hostile = """echo "it's $HOME" '$(not run)' `still not`
python3 -c 'print("a\\tb")' | awk '{print $1}'
EOF
"""
command = hb.ssh_command("lab", HOSTS, hostile)
assert "-J root@10.0.0.2" in command
KEYED = {"a": {"address": "10.0.0.5", "user": "root", "key": "/k1"}, "b": {"address": "10.0.0.5", "user": "root", "key": "/k2"}}
assert hb.ssh_command("a", KEYED, "true").split("ControlPath=")[1] != hb.ssh_command("b", KEYED, "true").split("ControlPath=")[1]
assert "-o IdentitiesOnly=yes -o IdentityFile=none -i /k1" in hb.ssh_command("a", KEYED, "true")
body = "cat" + command[command.index(" <<"):]
assert subprocess.run(["bash", "-c", body], capture_output=True, text=True).stdout == hostile.rstrip("\n") + "\n"

assert hb.gate(HOSTS, ["pve"], "df -h; docker ps 2>/dev/null >/dev/null") is None
assert hb.gate(HOSTS, ["pve"], "docker ps | awk -F'\\t' '{print $1 \" -> \" $2}'") is None
assert hb.gate(HOSTS, ["pve"], "echo 1 > /etc/flag")[0] == "block"
assert hb.gate(HOSTS, ["pve"], "systemctl restart jellyfin")[0] == "block"
assert hb.gate(HOSTS, ["media"], "docker compose up -d")[0] == "approve"
assert hb.gate(HOSTS, ["lab"], "rm -rf /tmp/x") is None
assert all(hb.gate(HOSTS, ["pve"], x)[0] == "block" for x in [
    "echo 1 > '/etc/flag'", "true 2>/etc/fstab", "echo 1 &>/etc/flag", "import os; os.remove('/etc/fstab')"])
assert hb.gate(HOSTS, ["pve"], "docker ps 2>&1 >&2") is None

# Scan output from a docker VM and a Proxmox node, trimmed from real hosts.
scan = sv.parse_scan("""##docker
{"Names":"sonarr","State":"running","Status":"Up 2 days","Image":"lscr.io/linuxserver/sonarr","Ports":"","Labels":"a=b,com.docker.compose.service=evil","ComposeDir":"/opt/media-stack","ComposeService":"sonarr"}
##systemd
cron.service                loaded active running Regular background program processing daemon
smbd.service                loaded active running Samba SMB Daemon
##qm
      VMID NAME                 STATUS     MEM(MB)    BOOTDISK(GB) PID
       101 nextfactor           running    8192             750.00 2549
##pct
VMID       Status     Lock         Name
102        running                 jellyfin
##facts
cores=6
mem_used_gb=4.1
os=Debian GNU/Linux 12 (bookworm)
""")
assert scan["facts"] == {"cores": 6.0, "mem_used_gb": 4.1, "os": "Debian GNU/Linux 12 (bookworm)"}
scan = scan["services"]
assert [(s["kind"], s["name"], s["state"]) for s in scan] == [
    ("docker", "sonarr", "running"), ("systemd", "smbd", "running"), ("vm", "nextfactor", "running"), ("ct", "jellyfin", "running")]
assert sv.action_script(scan[0], "update") == "cd /opt/media-stack && docker compose pull sonarr && docker compose up -d sonarr"
assert sv.action_script(scan[1], "restart", user="ubuntu") == "sudo -n systemctl restart smbd.service"
assert sv.action_script(scan[2], "restart") == "qm reboot 101" and sv.action_script(scan[2], "logs") is None
catalog = {"pve": {"services": scan[2:]}, "media": {"services": scan[:2]}}
assert sv.find(catalog, "jellyfin")[0] == "pve" and sv.find(catalog, "nope") == (None, [])
assert hb.gate(HOSTS, ["pve"], sv.action_script(scan[2], "restart"))[0] == "block"
assert hb.gate(HOSTS, ["pve"], sv.action_script(scan[2], "status")) is None
assert not any(hb.changes_things(x) for x in [sv.SCAN_SCRIPT, sv.DISCOVER_SCRIPT, hb.NEIGH_SCRIPT, *sv.DETAILS.values()])
assert sv.parse_discovery('##vm 104\n[{"name":"lo","ip-addresses":[{"ip-address-type":"ipv4","ip-address":"127.0.0.1"}]},'
                          '{"name":"docker0","ip-addresses":[{"ip-address-type":"ipv4","ip-address":"172.17.0.1"}]},'
                          '{"name":"eth0","ip-addresses":[{"ip-address-type":"ipv4","ip-address":"10.0.0.20"}]}]\n'
                          '##ct 102\n10.0.0.14\nfe80::1\n') == {("vm", "104"): ["10.0.0.20"], ("ct", "102"): ["10.0.0.14"]}  # reads stay allowed on read hosts and for viewers
assert sv.parse_discovery('##vm 1\n[{"name":"eth0","ip-addresses":[{"ip-address-type":"ipv4","ip-address":"-oProxyCommand=x"},'
                          '{"ip-address-type":"ipv4"}]}]\n') == {("vm", "1"): []}
nasty = sv.parse_scan('##facts\ncores=nan\nload1=inf\n##docker\n' + '{"Names":"a"}\n' * 2500)
assert nasty["facts"] == {} and len(nasty["services"]) == 2000 and "too_much_output" in nasty["warnings"]
forged = sv.diff("web", {"services": [{"kind": "docker", "name": "app", "state": "running"}]},
                 sv.parse_scan('##docker\n{"Names":"app","State":"exited\\ndb: up MEDIA:/etc/x"}\n'))
assert forged and all(ln.startswith("web: ") and "\n" not in ln and "MEDIA:" not in ln for ln in forged), forged
assert sv.parse_details("Description=Samba\nMemoryCurrent=10485760\nMainPID=[not set]\n##logs\nstarted") == {
    "fields": [["description", "Samba"], ["memory", "10 MB"]], "logs": ["started"]}

# Co-admins: no list = everyone; "" = owner's local session; unknown = refused once people are listed;
# view = hostbook's fixed reads only; scheduled AI runs only read.
PEOPLE = {"telegram:1": {"name": "Ada", "role": "operate", "hosts": ["media"]}, "discord:2": {"name": "Bo", "role": "view"}}
assert hb.access(None, "telegram:9", ["pve"], True) is None and hb.access(PEOPLE, "", ["pve"], True) is None
assert hb.access(PEOPLE, "telegram:1", ["media"], True) is None
assert "no access to pve" in hb.access(PEOPLE, "telegram:1", ["pve"], False)
assert hb.access(PEOPLE, "discord:2", ["pve"], False, fixed_read=True) is None
assert "can view" in hb.access(PEOPLE, "discord:2", ["pve"], False)  # a custom script, even a harmless one
assert "scan and read" in hb.access(PEOPLE, hb.SCHEDULED, ["pve"], False)  # custom reads need a person behind them
assert "isn't on" in hb.access(PEOPLE, "telegram:9", ["pve"], False, True) and "can't tell" in hb.access(PEOPLE, None, ["pve"], False, True)
assert hb.access(None, hb.SCHEDULED, ["pve"], False) is None and "only read" in hb.access(None, hb.SCHEDULED, ["pve"], True)
assert hb.is_owner(None, "telegram:9") and hb.is_owner(PEOPLE, "") and not hb.is_owner(PEOPLE, "telegram:1")
assert not hb.is_owner(None, hb.SCHEDULED)
LIMITED = {"t:1": {"role": "owner", "hosts": "pve"}}  # a machine limit makes an owner a co-admin, and one name is one machine
assert not hb.is_owner(LIMITED, "t:1") and "no access to pve-2" in hb.access(LIMITED, "t:1", ["pve-2"], True)

# The change check: hidden payloads count as changes; ssh option injection is refused.
assert hb.changes_things("bash -c 'printf x > /tmp/f'") and hb.changes_things("echo cm0= | base64 -d | sh")
assert hb.add_host("evil", "-oProxyCommand=touch /tmp/pwn@x") and hb.add_host("evil", "root@-oProxyCommand=x")
assert hb.add_host("evil", "root@10.0.0.7", key="-oProxyCommand=x") and "evil" not in hb.load_hosts()

# Setup and failures: a person-readable cause and fix, alerts only on transitions, 24 h history.
assert hb.parse_target("admin@nas.lan:2222") == {"user": "admin", "address": "nas.lan", "port": 2222}
assert hb.add_host("Bad Name", "root@x") and hb.add_host("nas\n", "root@x") and hb.add_host("nas", "root@10.0.0.30", rule="read") is None
why = sv.classify("admin@10.0.0.30: Permission denied (publickey).", hb.load_hosts()["nas"])
assert why["code"] == "key_refused" and "ssh-copy-id root@10.0.0.30" in why["fix"]
assert sv.classify("ssh: connect to host 10.0.0.30 port 22: Connection timed out", {})["code"] == "unreachable"
good = "##docker\n" + '{"Names":"web","State":"running","Status":"Up"}\n##facts\ncores=2\nload1=1\ndisk_pct=91\n'
assert hb.record_scans([{"host": "nas", "exit_code": 0, "output": good}], hb.load_hosts(), now=1000) == []
bad = hb.record_scans([{"host": "nas", "exit_code": 255, "output": "", "error": "Connection refused"}], hb.load_hosts(), now=2000)
assert bad == ["nas: SSH isn't answering on port 22. Start the SSH server there, or set the right port."]
stopped = good.replace('"State":"running"', '"State":"exited"')
assert hb.record_scans([{"host": "nas", "exit_code": 0, "output": stopped}], hb.load_hosts(), now=3000) == [
    "nas: reachable again", "nas: web (container) is exited"]
assert [p[0] for p in hb.load_history()["nas"]] == [1000, 3000] and hb.load_catalog()["nas"]["services"][0]["state"] == "exited"
# A scan nobody delivers keeps its alerts for the scheduled one, and one unreadable machine doesn't sink the rest.
sent = hb.record_scans([{"host": "x", "exit_code": 0, "output": None}, {"host": "nas", "exit_code": 0, "output": stopped}],
                       hb.load_hosts(), now=4000, deliver=True)
assert sent == bad + ["nas: reachable again", "nas: web (container) is exited"] and "unreadable" in hb.load_catalog()["x"]["error"]
hb._hermes = lambda *a: types.SimpleNamespace(returncode=0, stderr="", stdout=(
    "aaa111 [active]\n  Name: hostbook-scan\n  Script: hostbook-scan.py\nbbb222 [active]\n  Name: hostbook-scan\n  Script: hostbook-scan.py\n"))
assert hb._find_job("bbb222") == "bbb222" and hb._find_job("zzz999") is None  # the saved id, not a look-alike
assert sv.diff("nas", {"facts": {"disk_pct": 85}}, {"facts": {"disk_pct": 91}}) == ["nas: disk at 91%"]
# The access hook itself, as Hermes calls it: a stub ctx records what register() wires up.
class Ctx:
    def __init__(self):
        self.hooks = {}

    def register_hook(self, name, callback):
        self.hooks[name] = callback

    def __getattr__(self, name):  # register_tool, register_cli_command, ... are not needed here
        return lambda *a, **k: None


ctx = Ctx()
hb.register(ctx)
pre_llm, pre_tool = ctx.hooks["pre_llm_call"], ctx.hooks["pre_tool_call"]
hb.add_host("app", "root@10.0.0.31")
hb.save_people({"telegram:5": {"name": "Vi", "role": "view"}, "telegram:6": {"name": "Op", "role": "operate", "hosts": ["app"]}})
assert "machine list" in hb.remove_host("app")
pre_llm(session_id="s1", turn_id="t1", platform="telegram", sender_id="5")
assert pre_tool("host_run", {"hosts": ["nas"], "script": "uptime"}, session_id="s1", turn_id="t1")["action"] == "block"
assert pre_tool("terminal", {"command": "ssh root@10.0.0.30 uptime"}, session_id="s1", turn_id="t1")["action"] == "block"
assert pre_tool("host_services", {"hosts": ["nas"]}, session_id="s1", turn_id="t1") is None
assert pre_tool("cronjob_manage", {"action": "pause"}, session_id="s1", turn_id="t1")["action"] == "block"
pre_llm(session_id="s2", turn_id="t2", platform="cli", sender_id="")
assert pre_tool("hostbook_setup", {"action": "set_rule", "alias": "nas", "rule": "open"}, session_id="s2", turn_id="t2")["action"] == "approve"
owner_run = pre_tool("host_run", {"hosts": ["app"], "script": "# check\nrm -rf /srv"}, session_id="s2", turn_id="t2")
assert owner_run["action"] == "approve" and owner_run["rule_key"].startswith("hostbook:") and "rm -rf /srv" in owner_run["message"]
assert "\"rule\": \"approve\"" in pre_tool("hostbook_setup", {"action": "add_host", "alias": "nas", "target": "root@1.2.3.4"},
                                           session_id="s2", turn_id="t2")["message"]
assert pre_tool("terminal", {"command": "ssh root@10.0.0.30 uptime"}, session_id="s2", turn_id="t2") is None  # Hermes asks
assert pre_tool("write_file", {"path": "/h/plugin-data/hostbook/hosts.yaml", "content": "x"}, session_id="s2", turn_id="t2")["action"] == "approve"
assert pre_tool("host_run", {"hosts": '["nas"]', "script": "rm /x"}, session_id="s2", turn_id="t2")["action"] == "block"  # read rule
assert pre_tool("host_run", {"hosts": ["ghost"], "script": "rm /x"}, session_id="s2", turn_id="t2")["action"] == "block"
pre_llm(session_id="s3", turn_id="t3", platform="telegram", sender_id="6")  # operate: asks the owner instead of asking
assert "owner" in pre_tool("host_run", {"hosts": ["app"], "script": "rm /x"}, session_id="s3", turn_id="t3")["message"]
denied = pre_tool("service_action", {"service": "web", "action": "status"}, session_id="s3", turn_id="t3")["message"]
assert "app" in denied and "nas" not in denied  # web runs on nas, which this person can't see
pre_llm(session_id="s3", turn_id="t4", platform="cli", sender_id="")  # a second sender: later calls without a turn are refused
assert pre_tool("host_services", {"hosts": ["app"]}, session_id="s3")["action"] == "block"
os.environ["HERMES_KANBAN_TASK"] = "1"
pre_llm(session_id="s5", turn_id="t5", platform="cli", sender_id="")
del os.environ["HERMES_KANBAN_TASK"]
assert pre_tool("hostbook_setup", {"action": "show"}, session_id="s5", turn_id="t5")["action"] == "block"
assert DATA.stat().st_mode & 0o077 == 0
(DATA / "people.yaml").write_text("{ broken")
assert pre_tool("host_run", {"hosts": ["nas"], "script": "uptime"}, session_id="s2", turn_id="t2")["action"] == "block"
print("ok")
