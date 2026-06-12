"""
BE WAVE (Satel) protocol client — local TCP/4200.
Reverse-engineered from pl.satel.bewave. Crypto verified on a demo unit (fw 1.04).

Self-contained & runnable standalone for testing:
    python3 bewave_client.py status --host 192.168.1.50 --login USER --password 'PASS'
    python3 bewave_client.py arm    --host 192.168.1.50 --login USER --password 'PASS'
    python3 bewave_client.py disarm --host 192.168.1.50 --login USER --password 'PASS'

Key chain (AES-256-GCM, IV = randomNumber||timestamp||counter, each BE32):
  sign-in  app->hub : key MD5(pw)*2            aad login
  sign-in  hub->app : key deviceUuid(ASCII)    aad MD5(login padded 64)
  ongoing  app->hub : key deviceUuid(ASCII)    aad MD5(sessionId)
  ongoing  hub->app : key sessionSecret(f4)    aad MD5(sessionId)

Authorisation (firmware 1.04+): any self-chosen device receives live state after
it registers (f8 push-token message) and then reconnects. See LocalConnection.

State / data sources:
  f89  device telemetry  -> armed state (field 20), per-device open/motion (f9),
                            battery % (f4) / voltage (f110), signal (f3), temp.
  f27  hub status        -> LED/GRADE2/SATEL toggles, power, storage, firmware.
  f45  config            -> device names, rooms, model, system number.
  f31  connection methods-> active network (LAN/SIM).
"""
import socket, struct, hashlib, time, secrets, sys

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    raise SystemExit("pip install cryptography")

DATA_PORT = 4200
# Subscribe after sign-in so the hub starts sending state/config.
STATE_SUBS = [88, 44, 26, 52, 46, 56, 58, 90, 24, 30]
# Light re-subscribe used every poll to refresh device + settings (small + reliable).
REFRESH_SUBS = [88, 26]
ALARM_ARMED_FIELD = 20
# Site-setting toggles. Command is a FLIP: f34{f1{f1=id, f2{f3:{}}}}.
SETTING_IDS = {"led": 5, "grade2": 12, "satel": 11}
# device category by telemetry field f10
DEV_TYPES = {0x10002: "keyfob", 0x10003: "motion", 0x10007: "contact"}
# device model by config field f2 (verified from the app)
DEV_MODELS = {11: "APD-200", 26: "APT-210", 42: "AXD-200 Lite"}

# ---------- helpers ----------
def md5(x): return hashlib.md5(x.encode() if isinstance(x, str) else x).digest()
def pad(b, n):
    b = b.encode() if isinstance(b, str) else b
    return b + bytes(n - len(b))
def _wv(n):
    out = bytearray()
    while True:
        b = n & 0x7f; n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n: break
    return bytes(out)
def _rv(b, i):
    s = r = 0
    while True:
        if i >= len(b): raise IndexError
        x = b[i]; i += 1; r |= (x & 0x7f) << s; s += 7
        if not x & 0x80: break
    return r, i
def pb_bytes(field, data): return _wv((field << 3) | 2) + _wv(len(data)) + data
def pb_varint(field, val): return _wv((field << 3) | 0) + _wv(val)
def pb_fixed32(field, val): return _wv((field << 3) | 5) + struct.pack('<I', val)
def pb_read(b):
    """shallow read -> {field:[values]}"""
    o = {}; i = 0
    while i < len(b):
        try:
            tag, i = _rv(b, i); fn, wt = tag >> 3, tag & 7
            if wt == 0: v, i = _rv(b, i)
            elif wt == 5:
                if i + 4 > len(b): break
                v = struct.unpack_from('<I', b, i)[0]; i += 4
            elif wt == 1:
                if i + 8 > len(b): break
                v = struct.unpack_from('<Q', b, i)[0]; i += 8
            elif wt == 2:
                ln, i = _rv(b, i)
                if i + ln > len(b): break
                v = b[i:i+ln]; i += ln
            else: break
        except Exception:
            break
        o.setdefault(fn, []).append(v)
    return o
def _looks_str(b):
    return isinstance(b, (bytes, bytearray)) and len(b) >= 2 and all(32 <= c < 127 for c in b)
def _f32(v):
    try: return round(struct.unpack('<f', struct.pack('<I', v))[0], 2)
    except Exception: return None
def _s(v):
    return v.decode('latin1') if isinstance(v, (bytes, bytearray)) else (v or "")
def find_varint(buf, target, depth=0):
    res = []; i = 0
    while i < len(buf):
        try:
            tag, i = _rv(buf, i); fn, wt = tag >> 3, tag & 7
            if wt == 0:
                v, i = _rv(buf, i)
                if fn == target: res.append(v)
            elif wt == 5: i += 4
            elif wt == 1: i += 8
            elif wt == 2:
                ln, i = _rv(buf, i); sub = buf[i:i+ln]; i += ln
                if depth < 12 and not _looks_str(sub):
                    res += find_varint(sub, target, depth + 1)
            else: break
        except Exception:
            break
    return res

# ---------- decoders ----------
def armed_state(plaintext):
    """True=armed, False=disarmed, None=not a device-state message (field 20)."""
    if 89 not in pb_read(plaintext):
        return None
    vals = find_varint(plaintext, ALARM_ARMED_FIELD)
    if not vals:
        return None
    return any(v in (1, 2) for v in vals)

def system_status(plaintext):
    """f27 -> {'led','grade2','satel'} or None.
    f27.f1.f6==1 LED on; f27.f1.f26==1 GRADE2 on; f27.f1.f22==1 SATEL OFF."""
    d = pb_read(plaintext)
    if 27 not in d: return None
    f1 = pb_read(d[27][0])
    if 1 not in f1: return None
    body = pb_read(f1[1][0])
    return {"led": bool(body.get(6) and body[6][0] == 1),
            "grade2": bool(body.get(26) and body[26][0] == 1),
            "satel": not (22 in body and body[22][0] == 1)}

def hub_info(plaintext):
    """f27 -> {'power','stor_free','stor_total','firmware'} or None."""
    d = pb_read(plaintext)
    if 27 not in d: return None
    f1 = pb_read(d[27][0])
    if 1 not in f1: return None
    body = pb_read(f1[1][0])
    pw = body.get(9, [None])[0]
    if isinstance(pw, int) and pw > 100: pw = None       # fw 1.04: -1 on mains
    fw = None
    if 40 in body:
        v = pb_read(body[40][0]).get(9, [b""])[0]
        if _looks_str(v): fw = v.decode("latin1")
    return {"power": pw, "stor_free": body.get(10, [None])[0],
            "stor_total": body.get(11, [None])[0], "firmware": fw}

def network_active(plaintext):
    """f31 -> active connection name (e.g. 'LAN') or None."""
    d = pb_read(plaintext)
    if 31 not in d: return None
    top = pb_read(d[31][0])
    if 1 not in top: return None
    f1 = pb_read(top[1][0])
    for e in f1.get(1, []):
        ed = pb_read(e)
        if ed.get(5):
            if pb_read(ed[5][0]).get(2, [0])[0] == 1:
                return _s(ed.get(2, [b''])[0])
    return None

def _telem_from_block(f3block, f2list):
    """extract telemetry from a device's f3 body + nested f2 (temp)."""
    f3 = pb_read(f3block) if f3block else {}
    temp = None
    for t in f2list:
        td = pb_read(t)
        if td.get(1, [None])[0] == 6 and 3 in td and isinstance(td[3][0], int):
            temp = _f32(td[3][0])
    return {"signal": f3.get(3, [None])[0], "battery": f3.get(4, [None])[0],
            "state": f3.get(9, [None])[0], "armed": f3.get(20, [None])[0],
            "type": f3.get(10, [None])[0], "temp": temp,
            "volt": _f32(f3[110][0]) if 110 in f3 else None}

def parse_telemetry(plaintext):
    """f89 -> {devid: telemetry}."""
    d = pb_read(plaintext)
    if 89 not in d: return {}
    top = pb_read(d[89][0])
    if 1 not in top: return {}
    f1 = pb_read(top[1][0]); out = {}
    for dev in f1.get(2, []):
        dd = pb_read(dev)
        if 1 not in dd: continue
        devid = pb_read(dd[1][0]).get(1, [None])[0]
        if devid is None: continue
        body = pb_read(dd[2][0]) if 2 in dd else {}
        out[devid] = _telem_from_block(body[3][0] if 3 in body else None, body.get(2, []))
    return out

def parse_config_devices(plaintext):
    """f45 -> {devid: {name, room, type, model, sysnum, bypass, + telemetry}}."""
    d = pb_read(plaintext)
    if 45 not in d: return {}
    top = pb_read(d[45][0])
    if 1 not in top: return {}
    body = pb_read(top[1][0]); out = {}
    for room in body.get(4, []):
        rd = pb_read(room); rname = _s(rd.get(2, [b''])[0])
        for dev in rd.get(5, []):
            dd = pb_read(dev)
            if 1 not in dd: continue
            devid = pb_read(dd[1][0]).get(1, [None])[0]
            if devid is None: continue
            tel = {"type": None}
            if 20 in dd:
                t = pb_read(dd[20][0])
                tel = _telem_from_block(t[3][0] if 3 in t else None, t.get(2, []))
            out[devid] = {"name": _s(dd.get(9, [b''])[0]), "room": rname,
                          "type": tel.get("type"),
                          "model": DEV_MODELS.get(dd.get(2, [None])[0]),
                          "sysnum": dd.get(21, [None])[0],
                          "bypass": bool(dd.get(22, [0])[0]),
                          "signal": tel.get("signal"), "battery": tel.get("battery"),
                          "state": tel.get("state"), "temp": tel.get("temp"),
                          "volt": tel.get("volt")}
    return out

# ---------- framing ----------
def build_message(counter, plaintext, key, aad, user_id=2, device_id=4, with_ids=True):
    ts = int(time.time()) & 0xffffffff; rnd = secrets.randbits(31)
    ids = (pb_varint(3, user_id) + pb_varint(4, device_id)) if with_ids else b''
    header = (pb_fixed32(2, len(plaintext)) + ids + pb_varint(5, counter)
              + pb_varint(6, ts) + pb_varint(7, rnd) + pb_bytes(8, b'\x01\x00'))
    iv = struct.pack('>III', rnd, ts, counter)
    ct = AESGCM(key).encrypt(iv, plaintext, aad)
    return b'\x0a' + _wv(len(header)) + header + ct

def parse_header(buf, i):
    if buf[i] != 0x0a: return None
    try: hlen, j = _rv(buf, i + 1)
    except IndexError: return None
    if j + hlen > len(buf): return None
    header = buf[j:j+hlen]; fd = {}; k = 0
    try:
        while k < len(header):
            tag, k = _rv(header, k); fn, wt = tag >> 3, tag & 7
            if wt == 5:
                if k + 4 > len(header): return None
                fd[fn] = struct.unpack_from('<I', header, k)[0]; k += 4
            elif wt == 0: fd[fn], k = _rv(header, k)
            elif wt == 1:
                if k + 8 > len(header): return None
                fd[fn] = struct.unpack_from('<Q', header, k)[0]; k += 8
            elif wt == 2:
                ln, k = _rv(header, k)
                if k + ln > len(header): return None
                fd[fn] = header[k:k+ln]; k += ln
            else: return None
    except Exception:
        return None
    return fd, hlen, j + hlen

# ============================================================
class BeWaveError(Exception): pass

class BeWaveClient:
    def __init__(self, login, password, device_uuid=None, device_token=None):
        self.login = login
        self.password = password
        self.uuid = (device_uuid or secrets.token_hex(16).upper())[:32]
        self.token = device_token or ("ha-bewave-" + self.uuid)
        self.serial = None
        self.session_id = None
        self.session_secret = None
        self._counter = 0
        self.K_signin = md5(password) * 2
        self.A_signin = login.encode()
        self.A_resp = md5(pad(login, 64))

    def next_counter(self):
        self._counter += 1
        return self._counter
    def signin_message(self):
        inner = pb_bytes(2, self.uuid.encode()) + pb_bytes(3, (self.serial or "").encode())
        return build_message(self.next_counter(), pb_bytes(6, pb_bytes(1, inner)),
                             self.K_signin, self.A_signin, with_ids=False)
    def command_message(self, plaintext):
        if not self.session_id:
            raise BeWaveError("not signed in")
        return build_message(self.next_counter(), plaintext, self.uuid.encode(),
                             md5(self.session_id))
    def subscribe_plaintext(self, field): return pb_bytes(field, pb_bytes(1, b""))
    def register_plaintext(self):
        return pb_bytes(8, pb_bytes(1, pb_bytes(1, self.token.encode()) + pb_varint(2, 1)))
    def arm_disarm_plaintext(self, arm, mode="defau"):
        inner = pb_bytes(1, mode.encode()) + pb_varint(2, 1 if arm else 0)
        return pb_bytes(94, pb_bytes(1, pb_bytes(1, inner)))
    def setting_toggle_plaintext(self, setting_id):
        return pb_bytes(34, pb_bytes(1, pb_varint(1, setting_id) + pb_bytes(2, pb_bytes(3, b""))))

    def decrypt(self, buf, i):
        parsed = parse_header(buf, i)
        if not parsed: return None
        fd, hlen, off = parsed
        clen = fd.get(2, 0); ct = buf[off:off+clen]; tag = buf[off+clen:off+clen+16]
        if len(tag) < 16: return None
        iv = struct.pack('>III', fd.get(7, 0) & 0xffffffff,
                         fd.get(6, 0) & 0xffffffff, fd.get(5, 0) & 0xffffffff)
        end = off + clen + 16
        for key, aad in self._decrypt_keys():
            try:
                return fd, AESGCM(key).decrypt(iv, ct + tag, aad), end
            except Exception:
                continue
        return fd, None, end
    def _decrypt_keys(self):
        ks = [(self.uuid.encode(), self.A_resp)]
        if self.session_secret and self.session_id:
            ks.append((self.session_secret, md5(self.session_id)))
            ks.append((self.uuid.encode(), md5(self.session_id)))
        ks.append((self.K_signin, self.A_signin))
        return ks
    def ingest_response(self, plaintext):
        try:
            l2 = pb_read(pb_read(pb_read(plaintext)[7][0])[1][0])
            self.serial = l2[2][0].decode('latin1')
            self.session_id = l2[3][0].decode('latin1')
            self.session_secret = l2[4][0]
            return True
        except Exception:
            return False


class LocalConnection:
    def __init__(self, host, client, port=DATA_PORT, timeout=8):
        self.host = host; self.port = port; self.client = client; self.timeout = timeout
        self.sock = None; self._buf = b''

    def connect_and_signin(self):
        self.sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock.settimeout(self.timeout)
        self.sock.sendall(self.client.signin_message())
        deadline = time.time() + self.timeout; signed = False
        while time.time() < deadline and not signed:
            self._pump()
            for _fd, pt in self._drain():
                if pt and len(pt) > 200 and self.client.ingest_response(pt):
                    signed = True; break
        if not signed:
            raise BeWaveError("sign-in response not received/decrypted")
        for f in STATE_SUBS:
            self.sock.sendall(self.client.command_message(self.client.subscribe_plaintext(f)))
            time.sleep(0.02)
        try:
            self.sock.sendall(self.client.command_message(self.client.register_plaintext()))
        except Exception:
            pass
        # capture the hub's initial config (f45) + per-device telemetry (f89) burst,
        # which is pushed once right after subscribing. The standalone app catches it
        # via its continuous reader; here we read a few seconds so the first poll parses it.
        t0 = time.time()
        while time.time() - t0 < 3.5:
            self._pump()
        return True

    def refresh(self):
        """Light re-subscribe (f88 device state, f26 settings) — call each poll."""
        for f in REFRESH_SUBS:
            try:
                self.sock.sendall(self.client.command_message(self.client.subscribe_plaintext(f)))
            except Exception:
                pass

    def _pump(self):
        try:
            data = self.sock.recv(8192)
            if data:
                self._buf += data
            else:
                # recv() returning b'' means the hub closed the socket (it allows
                # only a few concurrent sessions; opening the phone/web app evicts
                # this one). Surface it so the caller reconnects instead of looping.
                raise BeWaveError("connection closed by hub")
        except socket.timeout:
            pass
    def _drain(self):
        out = []; i = 0
        while i < len(self._buf):
            if self._buf[i] != 0x0a:
                i += 1; continue
            res = self.client.decrypt(self._buf, i)
            if not res: break
            fd, pt, end = res
            if end > len(self._buf): break
            out.append((fd, pt)); i = end
        self._buf = self._buf[i:]
        if len(self._buf) > 200000:    # desync safety
            self._buf = b""
        return out
    def send_command(self, plaintext):
        self.sock.sendall(self.client.command_message(plaintext))
    def arm(self, mode="defau"):  self.send_command(self.client.arm_disarm_plaintext(True, mode))
    def disarm(self, mode="defau"): self.send_command(self.client.arm_disarm_plaintext(False, mode))
    def toggle_setting(self, setting_id): self.send_command(self.client.setting_toggle_plaintext(setting_id))
    def read_messages(self, seconds=2):
        out = []; t0 = time.time()
        while time.time() - t0 < seconds:
            self._pump(); out += self._drain()
        return out
    def close(self):
        try: self.sock.close()
        except Exception: pass


def _cli():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["status", "arm", "disarm"])
    ap.add_argument("--host"); ap.add_argument("--login"); ap.add_argument("--password")
    ap.add_argument("--serial"); ap.add_argument("--uuid"); ap.add_argument("--mode", default="defau")
    a = ap.parse_args()
    c = BeWaveClient(a.login, a.password, a.uuid)
    if a.serial: c.serial = a.serial
    conn = LocalConnection(a.host, c)
    conn.connect_and_signin()
    conn.close(); time.sleep(1)         # register, then reconnect as a known device
    conn = LocalConnection(a.host, c); conn.connect_and_signin()
    print("signed in. serial=", c.serial)
    if a.action == "arm": conn.arm(a.mode); print("ARM sent")
    elif a.action == "disarm": conn.disarm(a.mode); print("DISARM sent")
    armed = None
    for _fd, pt in conn.read_messages(3):
        if pt is not None:
            st = armed_state(pt)
            if st is not None: armed = st
    print("state:", {True: "ARMED", False: "DISARMED"}.get(armed, "unknown"))
    conn.close()

if __name__ == "__main__":
    _cli()
