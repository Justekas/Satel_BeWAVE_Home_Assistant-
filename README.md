# BE WAVE (Satel) — Home Assistant integration

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://github.com/hacs/integration)

Local control of a **Satel BE WAVE** Smart HUB alarm from Home Assistant — **no hardware
bridge, no cloud account**. It speaks the HUB's own (reverse-engineered) protocol over the
local network and authenticates with your **local username + password**.

Works with **any** BE WAVE Smart HUB / Smart HUB Plus — nothing is hard-coded to a specific
unit. You enter your own credentials; the serial is auto-discovered and a per-install device
identity is generated automatically.

## Features
- 🔌 Local connection (UDP discovery + TCP) — `local_push`
- 🔐 Sign-in with your local username + password (AES-256-GCM, fully on-device)
- 🛡️ `alarm_control_panel` entity: **Arm away / Disarm**
- ⚙️ Configurable protection-mode key (supports custom modes)

> **Status: v0.1.** Sign-in + arm/disarm + all crypto are verified against a real unit.
> Live **state read-back** (armed/alarm reflected back into HA) is best-effort in v0.1; the
> panel currently reflects the last command optimistically. See *Roadmap*.

## Install via HACS (custom repository)
1. HACS → **⋮** → **Custom repositories**.
2. Add `https://github.com/slaveitgr/Satel_BeWAVE_Home_Assistant-` as category **Integration**.
3. Install **BE WAVE (Satel)**, then **restart Home Assistant**.
4. Settings → Devices & Services → **Add Integration** → **BE WAVE**.
5. Enter the HUB IP, your **local username** and **password** (HA must be on the same LAN).

### Manual install
Copy `custom_components/bewave/` into your HA `config/custom_components/` and restart.

## Test the protocol directly (optional)
The protocol core is runnable standalone (`pip install cryptography`):
```bash
python3 custom_components/bewave/bewave_client.py discover
python3 custom_components/bewave/bewave_client.py arm    --host 192.168.10.129 --login USER --password 'PASS'
python3 custom_components/bewave/bewave_client.py disarm --host 192.168.10.129 --login USER --password 'PASS'
```

## How it works (protocol)
| stage | key | aad |
|-------|-----|-----|
| sign-in app→hub | MD5(password)·2 | login |
| sign-in hub→app | deviceUuid (ASCII 32B) | MD5(login padded to 64) |
| ongoing app→hub (commands) | deviceUuid (ASCII 32B) | MD5(sessionId) |
| ongoing hub→app (status) | sessionSecret `f4` (from response) | MD5(sessionId) |

IV = `randomNumber‖timestamp‖counter` (BE32). Cipher = AES-256-GCM, 12-byte IV, 16-byte tag.
ARM/DISARM payload = protobuf `f94{f1{f1{f1=mode, f2=1|0}}}`.

## Roadmap
- Map the protection-mode **status field** for accurate state read-back.
- Multiple protection modes → `arm_home` / `arm_night` / custom.
- **Cloud (remote)** transport: MQTT 5.0 over TLS to `*.satel.cloud:8854` (no cert pinning;
  the broker JWT is returned in the sign-in response). Mapped, not yet wired in.
- Zones / sensors as `binary_sensor`s.

## Disclaimer
This is an **unofficial** community integration, not affiliated with SATEL. It controls
**your own** alarm using **your** credentials. A network/software integration should not be
your sole line of defence on a security system. Use responsibly and at your own risk.

## License
MIT — see [LICENSE](LICENSE).
