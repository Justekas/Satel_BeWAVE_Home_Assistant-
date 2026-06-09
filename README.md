# BE WAVE (Satel) — Home Assistant integration

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://github.com/hacs/integration)

## Ελληνικά

Custom integration για το **Home Assistant** που επιτρέπει τοπικό έλεγχο ενός συναγερμού **Satel BE WAVE Smart HUB** από το Home Assistant, χωρίς hardware bridge και χωρίς cloud λογαριασμό.

Η σύνδεση γίνεται απευθείας στο τοπικό δίκτυο, χρησιμοποιώντας το local protocol του HUB, με authentication μέσω του **τοπικού username και password** του χρήστη.

Λειτουργεί με **BE WAVE Smart HUB** και **BE WAVE Smart HUB Plus**. Δεν είναι δεμένο σε συγκεκριμένη συσκευή. Ο χρήστης βάζει τα δικά του στοιχεία σύνδεσης, το serial γίνεται auto-discovery όπου είναι δυνατόν και δημιουργείται αυτόματα μοναδικό device identity ανά εγκατάσταση.

### Δυνατότητες

- 🔌 Τοπική σύνδεση στο LAN, χωρίς cloud
- 🔐 Login με local username + password
- 🛡️ `alarm_control_panel` entity στο Home Assistant
- ✅ Arm away / Disarm
- ⚙️ Ρυθμιζόμενο protection-mode key για custom modes
- 🔒 AES-256-GCM crypto, fully local/on-device

> **Κατάσταση: v0.1.** Το sign-in, το arm/disarm και το crypto έχουν δοκιμαστεί σε πραγματική μονάδα.
> Το live **state read-back** προς το Home Assistant είναι best-effort σε αυτή την έκδοση.
> Προς το παρόν το panel ενημερώνεται αισιόδοξα από την τελευταία εντολή. Δες το Roadmap.

### Εγκατάσταση μέσω HACS custom repository

1. Άνοιξε το **HACS**.
2. Πήγαινε **⋮ → Custom repositories**.
3. Πρόσθεσε το παρακάτω repository ως category **Integration**:

```text
https://github.com/slaveitgr/Satel_BeWAVE_Home_Assistant-
```

4. Εγκατέστησε το **BE WAVE (Satel)**.
5. Κάνε **restart** το Home Assistant.
6. Πήγαινε **Settings → Devices & Services → Add Integration**.
7. Αναζήτησε **BE WAVE**.
8. Βάλε την IP του HUB, το τοπικό username και το password.

Το Home Assistant πρέπει να βρίσκεται στο ίδιο LAN με το BE WAVE Smart HUB.

### Χειροκίνητη εγκατάσταση

Αν δεν χρησιμοποιείς HACS, αντέγραψε τον φάκελο:

```text
custom_components/bewave/
```

στο Home Assistant path:

```text
config/custom_components/bewave/
```

και κάνε restart το Home Assistant.

### Άμεση δοκιμή του protocol

Το protocol core μπορεί να τρέξει και standalone, χωρίς Home Assistant.

Πρώτα εγκατέστησε το dependency:

```bash
pip install cryptography
```

Μετά μπορείς να δοκιμάσεις:

```bash
python3 custom_components/bewave/bewave_client.py discover
python3 custom_components/bewave/bewave_client.py arm    --host 192.168.10.129 --login USER --password 'PASS'
python3 custom_components/bewave/bewave_client.py disarm --host 192.168.10.129 --login USER --password 'PASS'
```

### Πώς δουλεύει το protocol

| Stage | Key | AAD |
|------|-----|-----|
| sign-in app → hub | MD5(password)·2 | login |
| sign-in hub → app | deviceUuid ASCII 32B | MD5(login padded to 64) |
| ongoing app → hub commands | deviceUuid ASCII 32B | MD5(sessionId) |
| ongoing hub → app status | sessionSecret `f4` from response | MD5(sessionId) |

Το IV είναι:

```text
randomNumber ‖ timestamp ‖ counter
```

σε BE32 μορφή.

Cipher:

```text
AES-256-GCM, 12-byte IV, 16-byte tag
```

ARM/DISARM payload:

```text
protobuf f94{f1{f1{f1=mode, f2=1|0}}}
```

### Roadmap

- Ακριβές mapping του protection-mode status field για σωστό state read-back
- Υποστήριξη πολλαπλών protection modes
- `arm_home`, `arm_night` και custom modes
- Cloud/remote transport μέσω MQTT 5.0 over TLS προς `*.satel.cloud:8854`
- Zones και sensors ως `binary_sensor` entities

### Σημαντική σημείωση

Αυτό είναι unofficial community integration και δεν έχει σχέση με τη SATEL.
Χρησιμοποιεί τα δικά σου credentials για να ελέγξει τον δικό σου συναγερμό.
Μην βασίζεις την ασφάλεια ενός χώρου αποκλειστικά σε software integration ή automation.
Η χρήση γίνεται με δική σου ευθύνη.

---

## English

Custom **Home Assistant** integration for local control of a **Satel BE WAVE Smart HUB** alarm system, without a hardware bridge and without a cloud account.

The integration connects directly over the local network and speaks the HUB's own local protocol, using the user's **local username and password** for authentication.

It works with **BE WAVE Smart HUB** and **BE WAVE Smart HUB Plus**. It is not hard-coded to a specific unit. The user enters their own credentials, the serial is auto-discovered where possible, and a unique device identity is generated automatically per installation.

### Features

- 🔌 Local LAN connection, no cloud required
- 🔐 Sign-in with local username + password
- 🛡️ `alarm_control_panel` entity in Home Assistant
- ✅ Arm away / Disarm
- ⚙️ Configurable protection-mode key for custom modes
- 🔒 AES-256-GCM crypto, fully local/on-device

> **Status: v0.1.** Sign-in, arm/disarm and all crypto have been verified against a real unit.
> Live **state read-back** into Home Assistant is best-effort in this version.
> The panel currently reflects the last command optimistically. See Roadmap.

### Install via HACS custom repository

1. Open **HACS**.
2. Go to **⋮ → Custom repositories**.
3. Add the following repository as category **Integration**:

```text
https://github.com/slaveitgr/Satel_BeWAVE_Home_Assistant-
```

4. Install **BE WAVE (Satel)**.
5. **Restart** Home Assistant.
6. Go to **Settings → Devices & Services → Add Integration**.
7. Search for **BE WAVE**.
8. Enter the HUB IP, local username and password.

Home Assistant must be on the same LAN as the BE WAVE Smart HUB.

### Manual install

Copy the folder:

```text
custom_components/bewave/
```

to your Home Assistant path:

```text
config/custom_components/bewave/
```

then restart Home Assistant.

### Test the protocol directly

The protocol core can run standalone, without Home Assistant.

First install the dependency:

```bash
pip install cryptography
```

Then test:

```bash
python3 custom_components/bewave/bewave_client.py discover
python3 custom_components/bewave/bewave_client.py arm    --host 192.168.10.129 --login USER --password 'PASS'
python3 custom_components/bewave/bewave_client.py disarm --host 192.168.10.129 --login USER --password 'PASS'
```

### How the protocol works

| Stage | Key | AAD |
|------|-----|-----|
| sign-in app → hub | MD5(password)·2 | login |
| sign-in hub → app | deviceUuid ASCII 32B | MD5(login padded to 64) |
| ongoing app → hub commands | deviceUuid ASCII 32B | MD5(sessionId) |
| ongoing hub → app status | sessionSecret `f4` from response | MD5(sessionId) |

IV:

```text
randomNumber ‖ timestamp ‖ counter
```

in BE32 format.

Cipher:

```text
AES-256-GCM, 12-byte IV, 16-byte tag
```

ARM/DISARM payload:

```text
protobuf f94{f1{f1{f1=mode, f2=1|0}}}
```

### Roadmap

- Accurate mapping of the protection-mode status field for correct state read-back
- Support for multiple protection modes
- `arm_home`, `arm_night` and custom modes
- Cloud/remote transport via MQTT 5.0 over TLS to `*.satel.cloud:8854`
- Zones and sensors as `binary_sensor` entities

### Disclaimer

This is an unofficial community integration and is not affiliated with SATEL.
It uses your own credentials to control your own alarm system.
Do not rely on a software integration or automation as the only security layer for a property.
Use responsibly and at your own risk.

## License

MIT — see [LICENSE](LICENSE).
