# BE WAVE (Satel) — Home Assistant integration

Local control of a Satel **BE WAVE** Smart HUB alarm from Home Assistant, with no
hardware bridge and no cloud account — by speaking the HUB's own protocol
(reverse-engineered: AES-256-GCM over TCP/4200, sign-in with your local user/password).

> Status: **v0.1**. The crypto/sign-in/arm/disarm are verified against a real demo unit.
> Live panel **state read-back** (armed/alarm) is best-effort and may need one tuning pass
> on your unit — arm/disarm control works regardless.

## What works (verified)
- Local discovery (UDP/4111) and connect (TCP/4200)
- Sign-in with local username + password
- **Arm / Disarm** the default protection mode
- Decrypting all HUB traffic (status, events, device list)

## Install
1. Copy the `bewave/` folder into `config/custom_components/` of your Home Assistant.
   (Final path: `config/custom_components/bewave/`.)
2. Restart Home Assistant.
3. Settings → Devices & Services → **Add Integration** → search **BE WAVE**.
4. Enter the HUB IP (e.g. `192.168.10.129`), your local **username** and **password**.
   Home Assistant must be on the **same LAN** as the HUB.
5. An `alarm_control_panel.bewave_*` entity appears with Arm away / Disarm.

## Test the protocol directly (before/without HA)
The core client is runnable on its own (needs `pip install cryptography`):
```bash
python3 bewave_client.py discover
python3 bewave_client.py status  --host 192.168.10.129 --login mslave --password 'YOURPASS'
python3 bewave_client.py arm     --host 192.168.10.129 --login mslave --password 'YOURPASS'
python3 bewave_client.py disarm  --host 192.168.10.129 --login mslave --password 'YOURPASS'
```

## Protocol summary
| stage | key | aad |
|-------|-----|-----|
| sign-in app→hub | MD5(password)·2 | login |
| sign-in hub→app | deviceUuid (ASCII 32B) | MD5(login padded 64) |
| ongoing app→hub (commands) | deviceUuid (ASCII 32B) | MD5(sessionId) |
| ongoing hub→app (status) | sessionSecret f4 (from response) | MD5(sessionId) |

IV = `randomNumber‖timestamp‖counter` (BE32). Cipher = AES-256-GCM.
ARM/DISARM payload = `f94{f1{f1{f1=mode, f2=1|0}}}`.
`deviceUuid` is generated once at config time and reused (the HUB keys responses to it).

## Notes / roadmap
- **Cloud (remote) support** is mapped (MQTT 5.0 over TLS to `*.satel.cloud:8854`, no cert
  pinning; the broker JWT comes back in the sign-in response field `f6`) but not wired into
  this v0.1 — local first. It can be added on top of the same `BeWaveClient`.
- **State read-back**: the per-device telemetry decrypts fine; the exact field that reflects
  the *protection-mode armed/alarm* status still needs a labelled capture to map 1:1. Until
  then the panel reports state optimistically from the last command.
- This integration talks to **your own** alarm with **your** credentials. Use responsibly.
