# Security and privacy

What hostbook connects to, what it runs, what it stores, and when it calls a model. This is also the disclosure the Hermes plugin catalog asks for.

## Connections

- hostbook connects over SSH only to machines you add, as the user you give.
- It uses your existing keys, `ssh-agent` or SSH config. It stores a key's **path** if you give one, never the key itself.
- New host keys are accepted on first contact (`StrictHostKeyChecking=accept-new`). A changed host key is refused and reported, never accepted.
- Connection settings are checked so that a user, address or key can never be read as an `ssh` option.
- Connections are shared for 10 minutes to keep repeated calls fast (`ControlMaster`), with sockets in hostbook's data folder. Sharing is off on Windows and when the socket path would be too long.

## What runs on your machines

| When | What | Path |
|---|---|---|
| You or a co-admin ask in chat | Your script, or a service action | Through Hermes's terminal tool, after hostbook's checks and with Hermes's approvals |
| A scheduled scan, a *Check*, *Details*, *Find on Proxmox*, or the evidence for *Get AI help* | A fixed, read-only script | Directly over SSH, outside a chat turn |

The read-only scripts list containers, running services, Proxmox guests and usage (`docker ps`, `systemctl list-units`, `qm list`, `pct list`, `nproc`, `/proc/meminfo`, `df`, `/proc/uptime`, `/etc/os-release`), show one service's details (`docker inspect`, `docker stats`, `docker logs`, `systemctl show`, `journalctl`, `qm config`, `pct config`), find guest addresses (`qm guest cmd … network-get-interfaces`, `lxc-info`), or read the neighbour table (`ip -4 neigh`). Setup shows the scan under *What a scan runs on each machine*.

On machines where you connect as a non-root user, systemd start, stop and restart use `sudo -n`, which never prompts and fails if passwordless sudo isn't set up.

## What hostbook writes outside its data folder

- `scripts/hostbook-scan.py` in your Hermes home, when you turn on scheduled scans. It loads hostbook and runs the read-only scan.
- One Hermes cron job named `hostbook-scan`, in no-agent mode, visible and pausable on Hermes's Cron page.

## What it stores

In `plugin-data/hostbook/` in your Hermes home: your machines, people and settings, the last scan, 24 hours of usage history, connection-sharing sockets, and the last 20 chat accounts that messaged Hermes (platform, ID and time), which Setup offers when you add people. Nothing is sent anywhere.

## Model calls

hostbook calls a model only when you click **Get AI help** in Setup. That one call goes through Hermes's own model routing on a task hostbook registers, `hostbook_discovery`, which uses your current model unless you pick another for it in Hermes's model settings. It sends:

- the machines already added: names, addresses, users, operating systems, and up to 12 service names each;
- Proxmox guests not added yet: names and addresses;
- other addresses from network neighbour tables, with their MAC addresses and which machine saw them.

It never sends keys, passwords, tokens or file contents. The model's answer is checked against the evidence, and nothing is added until you click.

## The dashboard

The Hosts tab's routes sit behind the Hermes dashboard's login. They read hostbook's data, change it when you use Setup, and run the read-only scripts above. They never run a custom script.

## Telemetry

None.

## Reporting a problem

Open an issue at https://github.com/Timidan/hostbook/issues. For anything sensitive, say so in a short issue without details and ask for a private contact.
