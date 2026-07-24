# BE WAVE (Satel) — Home Assistant integration

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://github.com/hacs/integration)

## Ελληνικά

Custom integration για το **Home Assistant** που επιτρέπει τοπικό έλεγχο ενός συναγερμού **Satel BE WAVE** από το Home Assistant, χωρίς hardware bridge και χωρίς cloud λογαριασμό.

Η σύνδεση γίνεται απευθείας στο τοπικό δίκτυο, χρησιμοποιώντας το local protocol του HUB, με authentication μέσω του **τοπικού username και password** του χρήστη.

Έχει επαληθευτεί με **BE WAVE Smart HUB** και **BE WAVE Smart HUB Plus**. Η integration πλέον δεν είναι δεμένη σε ονομασία συγκεκριμένου HUB και αντιμετωπίζει τη μονάδα ως γενικό **BE WAVE controller / control panel**, ώστε να μπορεί να συνδεθεί και με νεότερα μοντέλα που μιλάνε το ίδιο local protocol μέσω της εφαρμογής **BE WAVE**, όπως το **HYBRID 128 Plus**. Για τέτοια μοντέλα η συμβατότητα είναι **expected but not yet field-verified**.

### Δυνατότητες

- 🔌 Τοπική σύνδεση στο LAN, χωρίς cloud
- 🔐 Login με local username + password
- 🛡️ `alarm_control_panel` entity στο Home Assistant
- ✅ Arm away / Disarm
- 🔴 **Live state read-back** — το panel δείχνει την πραγματική κατάσταση **ακόμα κι όταν αλλάζει από το κινητό**, τοπικά
- 🚪 **Sensors**: ανιχνευτές πόρτας/παραθύρου (opening) & κίνησης (motion) ως `binary_sensor`
- 🌡️ **Θερμοκρασία & μπαταρία** ανά συσκευή ως `sensor` (+ τάση, σήμα, system number ως attributes)
- 🎛️ **Hub setting switches**: LED indicator, GRADE 2, SATEL server connection
- 🔑 **Αυτο-εγγραφή** (firmware 1.04+): δημιουργεί δικό του device id και εγγράφεται μόνο του — δεν χρειάζεται «add device» χειροκίνητα
- ⚙️ Configurable protection-mode key
- 🔒 AES-256-GCM crypto, fully local/on-device

> **Κατάσταση: v0.4.** Sign-in, arm/disarm, live state, switches, **sensors (πόρτα/κίνηση/θερμοκρασία/μπαταρία) και αυτο-εγγραφή** δοκιμασμένα σε πραγματική μονάδα (fw 1.04).
> Το read-back είναι 100% τοπικό (δουλεύει ακόμα και χωρίς internet): μετά το sign-in ο HUB
> κάνει push την κατάσταση των συσκευών και σε κάθε αλλαγή.

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

Μετά μπορείς να δοκιμάσεις (βάλε τα δικά σου στοιχεία στη θέση των `USER` / `PASS`):

```bash
python3 custom_components/bewave/bewave_client.py discover
python3 custom_components/bewave/bewave_client.py status --host 192.168.1.50 --login USER --password 'PASS'
python3 custom_components/bewave/bewave_client.py arm    --host 192.168.1.50 --login USER --password 'PASS'
python3 custom_components/bewave/bewave_client.py disarm --host 192.168.1.50 --login USER --password 'PASS'
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

**State read-back (τοπικά):** μετά το sign-in, ο client κάνει subscribe στα κανάλια συσκευών.
Ο HUB τότε στέλνει ένα μήνυμα `f89` (device state) μία φορά αμέσως και ξανά σε κάθε αλλαγή
— ακόμα κι όταν οπλίζεις/αφοπλίζεις από το κινητό. Η κατάσταση οπλισμού βρίσκεται στο
**protobuf πεδίο 20** (`1`=οπλισμένος, `2`=μερικός, `0`=αφοπλισμένος).

### Roadmap

- Υποστήριξη πολλαπλών protection modes (`arm_home`, `arm_night`, custom)
- Relays / outputs ως `switch` entities (όταν υπάρχουν ρυθμισμένα)
- Time / timezone και network (LAN) ρυθμίσεις ως υπηρεσίες (commands `f92` / `f28` αποκωδικοποιημένα)
- Keyfob button events (απαιτεί Event Log)

### Σημαντική σημείωση

Αυτό είναι unofficial community integration και δεν έχει σχέση με τη SATEL.
Χρησιμοποιεί τα δικά σου credentials για να ελέγξει τον δικό σου συναγερμό.
Μην βασίζεις την ασφάλεια ενός χώρου αποκλειστικά σε software integration ή automation.
Η χρήση γίνεται με δική σου ευθύνη.

---

## English

Custom **Home Assistant** integration for local control of a **Satel BE WAVE** alarm system, without a hardware bridge and without a cloud account.

The integration connects directly over the local network and speaks the HUB's own local protocol, using the user's **local username and password** for authentication.

It has been verified with **BE WAVE Smart HUB** and **BE WAVE Smart HUB Plus**. The integration is no longer tied to a Smart HUB-specific product label and now treats the target as a generic **BE WAVE controller / control panel**, which makes it suitable for newer BE WAVE units that expose the same local protocol through the **BE WAVE** app, such as **HYBRID 128 Plus**. Those additional models are **expected to work, but not yet field-verified**.

### Features

- 🔌 Local LAN connection, no cloud required
- 🔐 Sign-in with local username + password
- 🛡️ `alarm_control_panel` entity in Home Assistant
- ✅ Arm away / Disarm
- 🔴 **Live state read-back** — the panel shows the real armed/disarmed state, **even when changed from the phone**, fully locally
- 🚪 **Sensors**: door/window (opening) & motion detectors as `binary_sensor`
- 🌡️ **Temperature & battery** per device as `sensor` (+ voltage, signal, system number as attributes)
- 🎛️ **Hub setting switches**: LED indicator, GRADE 2, SATEL server connection
- 🔑 **Auto-registration** (firmware 1.04+): generates its own device id and registers itself — no manual "add device" needed
- ⚙️ Configurable protection-mode key
- 🔒 AES-256-GCM crypto, fully local/on-device

> **Status: v0.4.** Sign-in, arm/disarm, live state, switches, **sensors (door/motion/temperature/battery) and auto-registration** verified against a real unit (fw 1.04).
> Read-back is 100% local (works even with internet off): after sign-in the HUB pushes
> device state immediately and on every change.

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

Then test (replace `USER` / `PASS` with your own credentials):

```bash
python3 custom_components/bewave/bewave_client.py discover
python3 custom_components/bewave/bewave_client.py status --host 192.168.1.50 --login USER --password 'PASS'
python3 custom_components/bewave/bewave_client.py arm    --host 192.168.1.50 --login USER --password 'PASS'
python3 custom_components/bewave/bewave_client.py disarm --host 192.168.1.50 --login USER --password 'PASS'
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

**State read-back (local):** after sign-in the client subscribes to the device channels.
The HUB then pushes an `f89` device-state message once immediately and again on every
change — including arming/disarming from the phone. The arming state is carried in
**protobuf field 20** (`1`=armed, `2`=partial, `0`=disarmed).

### Roadmap

- Multiple protection modes (`arm_home`, `arm_night`, custom)
- Relays / outputs as `switch` entities (when configured)
- Time / timezone and network (LAN) settings as services (commands `f92` / `f28` decoded)
- Keyfob button events (requires Event Log)

### Disclaimer

This is an unofficial community integration and is not affiliated with SATEL.
It uses your own credentials to control your own alarm system.
Do not rely on a software integration or automation as the only security layer for a property.
Use responsibly and at your own risk.

## License

MIT — see [LICENSE](LICENSE).
