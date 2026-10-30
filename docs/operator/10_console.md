# The console

**Audience:** whoever sets up a deployment for the people who answer for it.
**Design:** [ADR 0039](../adr/0039-the-console-a-persons-hands-verified-on-their-computer.md).

`vgconsole` is the application a person opens instead of a terminal. It runs on
their computer and checks everything itself, so it needs only a route to one port
of the authority's host.

## Turn it on

A new deployment:

```bash
acpctl provision ... --console-listen 0.0.0.0:9443
```

An existing one, in `sagvd.json`, then restart `sagvd`:

```json
"console": {"listen_address": "0.0.0.0:9443", "dir": "/etc/vaultgenome/console"},
"operator_stop": {"kid": "console-operator-stop",
                  "public_key_path": "/etc/vaultgenome/console/operator_stop.pem",
                  "list_path": "/etc/vaultgenome/console/stop_list.json"}
```

Let the firewall admit that port from the people's network only. The listener
admits only keys on its list, and it is one more door.

## Give the first person a pass

On the authority's host, after `sagvd` has started once:

```bash
acpctl console invite --sagvd-config /etc/vaultgenome/sagvd.json --worker-config /etc/vaultgenome/acp-compute.json \
  --address 203.0.113.10:9443 --label "Production, Ohio" --name "Anna Kovalenko" --role owner --out anna.vgpass
```

Send `anna.vgpass` to that person. It works once, for three days unless `--valid`
says otherwise. Whoever opens it first is the one the server admits, so if Anna
finds it used, tell her to say so at once. The first `owner` holds the emergency
stop: the key is made on her computer and is never on the server. After that she
invites people herself, from the console.

## What the person does

They open `vgconsole` (`vgconsole-darwin-arm64`, `vgconsole-windows-amd64.exe`, …
from the release, checked against the signed list), and choose the pass. The page
says in one line whether all is well and what was checked. The buttons:

| Button | Who | What happens |
| - | - | - |
| Check now | everyone | A random question to the chip; the answer is verified on their computer. Also every minute while the page is open. |
| Check the model comes back | `operator`, `owner` | A gate job on the newest sealed genome, under their name. The bank's running model is not touched. |
| Emergency stop / Lift the stop | the holder | A stop list signed on their computer. Every gate job and key release is refused until it is lifted; the bank's running model is not switched off. |
| Invite a person / Close access | `owner` | A pass as a file; a person off the list at once. |

Everything but the look is on the audit chain, under the person's name, before it
takes effect. `acpctl audit verify` and the independent auditor read those records
as any other.

## When something is wrong

| The page says | What it means | What to do |
| - | - | - |
| The server did not prove itself | The chip's answer failed on their computer: another firmware than the pass pins, or not that chip. | Treat the host as untrusted. If the firmware was updated on purpose, a new pass carries the new pin. |
| No connection to the server | The port is not reachable, or `sagvd` is down. | The firewall; `systemctl status sagvd`. |
| The journal is damaged | A record failed its signature or its link. | `acpctl audit verify` on the stopped daemon's file, and the incident process. |
| The emergency stop cannot be read | The list or its key is unreadable; nothing is released while this lasts (ADR 0010). | Restore the file from the record; only the holder can sign a new one. |
