# hostbook

**Run scripts on your named machines in one call, with no quoting, under per-machine rules, and see your whole homelab in the Hermes dashboard.**

Hermes already reaches your servers through `ssh` in its terminal. In practice that breaks: in one homelab's 6.5 months of Hermes history, 188 commands failed on shell quoting alone, and the same machine was reached as two or three different users. hostbook gives Hermes a host list and a `host_run` tool that sends a whole script to one or more machines with no escaping, under rules you set per machine.

## What you get

- **`host_run`** – run a bash, sh or Python script on one or more machines by name. The script is passed as typed; no quoting.
- **Per-machine rules** – `read` (Hermes can look, never change), `approve` (changes wait for your OK in chat), `open`. Enforced before every call, on top of Hermes's own approval checks.
- **`host_services` and `service_action`** – what runs where (Docker, systemd, Proxmox VMs and LXCs) with usage, and status / logs / restart / start / stop / update for any of it, under the same rules.
- **Co-admins** – list people by their chat account (Telegram, Discord, Slack and the other Hermes platforms) as *can view*, *can operate* or *owner*, optionally limited to some machines.
- **Scheduled scans without the AI** – a Hermes no-agent cron job scans every machine on a schedule you pick, costs no tokens, and only messages you when something changes.
- **Hosts tab in the Hermes dashboard** – every machine with cpu, memory and disk, what's not running, live details per service, and a setup page.
- **Finding machines** – add one Proxmox node and hostbook offers its VMs and containers with their addresses; or ask your model to read the network neighbour tables and suggest what's worth adding.

## Requirements

- Hermes Agent 0.22.0 or newer.
- The machine Hermes runs on can SSH into your machines with a key (`ssh-copy-id user@machine`). Linux or macOS for Hermes's host; Windows works without connection sharing.
- Targets: any Linux machine over SSH. Usage numbers need Linux `/proc`; Docker, systemd and Proxmox data appear when present.

## Install

```bash
hermes plugins install hostbook
hermes plugins enable hostbook
```

## Set up

Pick whichever surface you use:

- **Dashboard:** Hosts → setup → name, `user@address`, rule → *Add and check*.
- **Chat:** "add my server root@192.168.1.20 as nas" (owner only).
- **Command line:** `hermes hostbook add nas root@192.168.1.20 --rule read`, then `hermes hostbook schedule 30m`.

Every add checks the connection right away and says what to fix if it fails (key refused, port closed, unreachable, name not found, changed host identity).

## What hostbook does on your machines and your Hermes (disclosure)

- **SSH:** connects only to machines you add, as the user you give, with your existing keys or ssh-agent. It stores key *paths*, never keys. New host keys are accepted on first contact (`StrictHostKeyChecking=accept-new`); a changed key is refused and reported.
- **Commands it runs without a chat turn:** scheduled scans, the setup page's *check*, *details*, *find on Proxmox* and the evidence for *AI help* run read-only scripts over SSH directly. The exact scan is shown in setup under "what a scan runs". Anything that changes a machine only runs from a chat tool call, under the machine's rule and Hermes's approval prompt.
- **sudo:** on machines where you connect as a non-root user, systemd start/stop/restart use `sudo -n` (never prompts; fails if passwordless sudo isn't set up).
- **Files outside its data folder:** writes `scripts/hostbook-scan.py` in your Hermes home when you turn on scheduled scans, and creates a Hermes cron job named `hostbook-scan` (visible and pausable on Hermes's Cron page).
- **Data it keeps** (in `plugin-data/hostbook/`): your machine list, people, settings, the last scan, 24 hours of usage history, SSH connection-sharing sockets, and the last 20 chat accounts that messaged Hermes (platform, id, time; used to pick co-admins).
- **Model calls:** only when you click *get AI help finding machines*. It sends your current model the addresses, MAC addresses, machine names, OS names and service names it gathered, never keys or passwords. One call per click, on hostbook's own model task (`hostbook_discovery`), which you can point at another model in Hermes's model settings.
- **No telemetry.**

## How the rules are enforced, and their limits

- Every hostbook tool call is checked before it runs: who asked (their chat account, or you at your own terminal or dashboard), then the machine's rule. If hostbook can't read its own settings, it blocks instead of letting calls through.
- People with *can view* get hostbook's fixed reads only: scans, status and logs. No custom scripts.
- Changing hostbook's setup from chat (adding or removing machines, changing a rule, the schedule) always asks for your approval, so a model can't loosen the rules on its own.
- Scheduled AI runs (Hermes cron jobs that use the AI) can only read through hostbook. The no-AI scheduled scan is read-only by design.
- Connection settings are checked, so a user, address or key can never be read as an `ssh` option.
- The "changes something" check is a guardrail, not a sandbox: it catches common writes and treats scripts it can't read (nested shells, `eval`, decoded payloads, inline interpreters) as changes, but a determined script can still hide a write. Hermes's own approval checks still apply to every command.
- Co-admins are blocked from running `ssh`, `scp`, `rsync` and similar through Hermes's terminal and code tools, and from editing hostbook's files. That too is a guardrail: Hermes's machine holds your SSH keys, so for people you don't fully trust, also limit which Hermes tools they can use.
- Until you list anyone under *people*, everyone Hermes already lets in (its chat allow-lists, webhooks, API clients) has full hostbook access, the same as you.
- Runs started on Hermes's own machine without a person present, such as `hermes chat -q` and Kanban workers, count as you, the owner. hostbook can't tell them apart from your own terminal.

## People and their access

Setup → *people*: pick someone who recently messaged Hermes, or enter their chat platform and user id, then choose *can view*, *can operate* or *owner* and, optionally, which machines. To change someone later, pick a different access level on their row or edit their machines; it saves straight away. *Remove* asks once more before it takes effect. The list lives in `plugin-data/hostbook/people.yaml` if you prefer editing it by hand.

## Credits

- Interface icons: [Phosphor Icons](https://phosphoricons.com) (MIT).
- Service logos: [Simple Icons](https://simpleicons.org) (CC0). Logos and trademarks belong to their owners and are shown only to identify the software running on your machines; see the Simple Icons [disclaimer](https://github.com/simple-icons/simple-icons/blob/develop/DISCLAIMER.md).
- Glyphs for services without a public logo (Bazarr, Prowlarr, Seerr, Gluetun, FlareSolverr, Homepage, Samba, NFS, fail2ban, mail, Windows) are original to hostbook.

## License

MIT
