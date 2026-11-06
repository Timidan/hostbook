# hostbook guide

This guide walks through setting hostbook up, using it from chat and the dashboard, scheduled scans, finding machines, and fixing connection problems. For who may do what, see [access control](access-control.md). For what hostbook runs and stores, see [security](security.md).

## Before you start

- Hermes Agent 0.22.0 or newer.
- The machine Hermes runs on needs SSH key access to every machine you add. If you can run `ssh user@machine` there without typing a password, hostbook can connect too. To set it up:

  ```bash
  ssh-copy-id user@machine
  ```

  An `ssh-agent` or a Host entry in your SSH config works as well. hostbook passes only the key's path to `ssh`; it never reads or stores the key.
- Targets are Linux machines reachable over SSH. Usage numbers need Linux `/proc`. Docker, systemd and Proxmox information shows up when those are present.

## Install

```bash
hermes plugins install hostbook        # from the Hermes plugin catalog, once listed
# or: hermes plugins install https://github.com/Timidan/hostbook
hermes plugins enable hostbook
```

Restart the Hermes dashboard afterwards so the **Hosts** tab appears. New chat sessions pick up hostbook's tools automatically.

## Add machines

Every way of adding a machine connects to it straight away with a read-only scan and tells you the result: either what runs there, or what went wrong and how to fix it.

### From the dashboard

Hosts → Setup → **Add a machine**:

| Field | Example | |
|---|---|---|
| Name | `nas` | Short, lowercase. This is how you and Hermes refer to the machine. |
| User and address | `root@192.168.1.20` or `admin@nas.lan:2222` | A Host from your SSH config works too. |
| Key file | `/home/you/.ssh/id_ed25519` | Optional. Leave empty to use your default keys or ssh-agent. |
| Connect through | `pve` | Optional jump host, picked from machines already added. |
| Rule | Asks before changes | See [machine rules](#machine-rules). |

### From chat

Tell Hermes, for example: "add my server root@192.168.1.20 as nas, read only". Hermes uses the `hostbook_setup` tool, asks for your approval, then reports the connection check. Only the owner can change setup from chat.

### From the command line

```bash
hermes hostbook add nas root@192.168.1.20 --rule read
hermes hostbook add web ubuntu@10.0.0.5 --key ~/.ssh/web_key --jump nas
hermes hostbook list
```

## Find machines

Setup → **Find machines** has two helpers. Both are read-only, and nothing is added until you click *Add and check*.

- **Find on Proxmox** asks every Proxmox node already in the hostbook for its running VMs and containers and their addresses (VMs through the QEMU guest agent, containers through `lxc-info`). Guests already added are left out.
- **Get AI help** also reads the network neighbour tables of Hermes's host and of your machines, then asks your current model which addresses are worth adding, what each one probably is, and which SSH user to try. Routers, phones and unidentified devices are listed separately. Addresses the model invents are dropped. This costs one model call per click; see [security](security.md#model-calls).

Check the suggested SSH user before adding: Home Assistant OS uses `hassio`, Ubuntu cloud images use `ubuntu`, Proxmox containers usually use `root`.

## Machine rules

| Rule | What Hermes may do |
|---|---|
| Read only | Look, never change. Scripts that change things are blocked. |
| Asks before changes | Changes wait for your OK in chat. Reads run freely. |
| Open | Changes run without asking. Hermes's own safety checks still apply. |

hostbook decides whether a script changes something from what it contains. Scripts it can't read through (nested shells, `eval`, decoded payloads, inline interpreters) count as changes. This is a guardrail against mistakes, not a sandbox; see [access control](access-control.md#limits).

Change a rule in Setup, from chat ("set nas to read only"), or by adding the machine again with `--rule`.

## Use it

In chat, ask in your own words. Hermes picks the tool:

- "How full are the disks on all my servers?" runs one `host_run` across every machine and answers with one table.
- "What's running on nas?" uses `host_services`.
- "Restart sonarr" uses `service_action`; on a machine set to *asks before changes*, Hermes asks you first.
- "Show me the last logs for jellyfin" uses `service_action` with `logs`.

In the dashboard, **Machines** shows every machine's CPU, memory and disk, what isn't running, and a 24-hour CPU line once scans have history. **View all services** opens every service on a machine, and **Details** fetches live, read-only information for one of them: image, ports, health, restarts, mounts, CPU and memory, and the latest log lines for containers; state, memory and recent journal lines for systemd services; configuration for Proxmox guests.

Machines with something wrong (a stopped service, a full disk, a failed scan) sort to the top.

## Scheduled scans

Setup → **Scheduled scans**, or:

```bash
hermes hostbook schedule 30m --deliver telegram
hermes hostbook schedule off
```

| Setting | |
|---|---|
| Frequency | Off, 15 min, 30 min, hourly, 6 hours or daily. |
| Send alerts to | Nowhere (the page only), or a Hermes delivery target such as your Telegram home chat. |
| Disk alert | Alert when a disk passes this percentage (default 90). |
| Per machine | Untick *Included* in the machines table to leave a machine out. |

Scans run as one Hermes cron job named `hostbook-scan` in no-agent mode: a script runs on schedule and the AI is never called, so scans cost no tokens. The job appears on Hermes's Cron page, where you can pause or remove it.

Alerts are sent only when something changes: a service stops or comes back, a disk crosses the threshold, a machine stops answering or answers again. A quiet run sends nothing.

## Troubleshooting

hostbook names the cause of a failed connection and the fix, in Setup, on the machine's card, and in chat.

| Message | Cause | Fix |
|---|---|---|
| Key refused | The machine doesn't accept the key for that user. | `ssh-copy-id user@address` from Hermes's machine, or set the right key file or user. |
| SSH isn't answering on port 22 | No SSH server, or a different port. | Start `sshd`, or add the machine again as `user@address:port`. |
| Not reachable | Off, asleep, or on another network. | Check it's on and reachable from Hermes's machine. |
| Name not found | The name doesn't resolve from Hermes's machine. | Use the IP address. |
| This machine's identity changed | Its SSH host key is different from last time. | If you rebuilt it, `ssh-keygen -R <address>`. If you didn't, find out why before connecting. hostbook never accepts a changed key. |
| Containers hidden | The SSH user can't read Docker. | Add the user to the `docker` group, or connect as a user who can. |
| No usage numbers | The machine has no Linux `/proc` (macOS, BSD). | Nothing to fix; services still show. |
| No Hosts tab | The dashboard loaded its plugin list before hostbook was enabled. | Restart the Hermes dashboard. |
| "can view, which covers scans, status and logs" | A co-admin with view access asked for a script or a change. | Give them *can operate*, or do it yourself. |

To see a scan's full output, run `hermes hostbook scan` on Hermes's machine.
