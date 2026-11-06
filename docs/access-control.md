# Access control

hostbook decides two things before any of its tools touch a machine: **who asked**, and **what that machine's rule allows**. This page explains both, how to set them up, and where their limits are.

## Who asked

Hermes tells plugins which chat account sent each message. hostbook records it per turn and checks it on every tool call in that turn.

| Who | Counts as |
|---|---|
| You at Hermes's own terminal, TUI or dashboard | Owner |
| A chat account on the people list | Their access level |
| A chat account not on the list, once the list has anyone | Refused |
| A subagent | Whoever started its parent conversation |
| A Hermes cron job that uses the AI | Read only |
| A run hostbook can't attribute, once the list has anyone | Refused |

Until you add anyone to the people list, everyone Hermes already lets in has full hostbook access, the same as you. That suits a single-person setup. Add people as soon as anyone else can talk to your Hermes.

## People and access levels

| Access | Scans, status and logs | Custom scripts and changes | Setup |
|---|---|---|---|
| Can view | Yes | No | No |
| Can operate | Yes | Yes, within each machine's rule | No |
| Owner | Yes | Yes, within each machine's rule | Yes, with approval |

People are identified by **chat platform and user ID**, so a Telegram account and a Discord account with the same number are different people. Each person can be limited to some machines.

### Add someone

Setup → **People** → *Add a person*. The easiest way to get the right ID: have them message your Hermes once, then pick them from *Recently messaged Hermes*.

Add your own chat account first, as **owner**. Once the list has anyone on it, accounts not on it are refused, including yours.

### Change someone's access

On their row, pick a different access level; it saves straight away. Edit *Machines* (comma-separated, empty means all) and press Enter. *Remove* asks once more before acting.

You can also edit `plugin-data/hostbook/people.yaml` by hand:

```yaml
telegram:123456789: {name: You, role: owner}
discord:234567890123456789: {name: Ada, role: operate, hosts: [nas, media]}
```

If the file can't be read, hostbook blocks its tools instead of letting calls through, and says so.

## Machine rules

| Rule | Reads | Changes |
|---|---|---|
| Read only | Allowed | Blocked |
| Asks before changes | Allowed | Wait for your approval in chat |
| Open | Allowed | Run, under Hermes's own safety checks |

Service actions are judged by the action: *status* and *logs* read, the rest change. For `host_run`, hostbook reads the script. Common writes (`rm`, `mv`, `systemctl restart`, `docker compose up`, package installs, redirects into files, Python writes) count as changes. So do scripts it can't read through: nested shells (`bash -c`), `eval`, decoded payloads (`base64 -d`), inline interpreters (`python -c`), and Python that spawns processes.

## Setup changes from chat

Adding or removing machines, changing a rule or the schedule from chat always asks for the owner's approval, even when the owner asked. That stops a model, steered by text it read somewhere, from loosening the rules on its own. Changes made on the dashboard or the command line apply directly, because you are making them yourself.

## Limits

- **The change check is a guardrail, not a sandbox.** It catches common writes and treats unreadable scripts as changes, but a determined script can still hide a write. Every command still passes through Hermes's own approval checks.
- **Co-admins and the terminal.** Hermes's machine holds your SSH keys. hostbook blocks co-admins from running `ssh`, `scp`, `rsync` and similar through Hermes's terminal and code tools, and from editing hostbook's files, but that is a keyword guardrail too. For people you don't fully trust, also limit which Hermes tools they can use.
- **Runs without a person present.** `hermes chat -q` runs and Kanban workers report themselves as local, so hostbook counts them as you. It can't tell them apart from your own terminal.
- **No people list means no co-admin checks.** Everyone Hermes admits, including webhooks and API clients, has full hostbook access until the list has anyone on it.
