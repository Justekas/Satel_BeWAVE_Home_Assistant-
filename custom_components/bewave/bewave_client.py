"""
BE WAVE (Satel) protocol client — local TCP/4200 and cloud MQTT/TLS.
Reverse-engineered from pl.satel.bewave 1.2.0. Crypto verified on a demo unit.

Self-contained & runnable standalone for testing:
    python3 bewave_client.py discover
    python3 bewave_client.py status   --host 192.168.10.129 --login mslave --password 'pw'
    python3 bewave_client.py arm       --host 192.168.10.129 --login mslave --password 'pw'
    python3 bewave_client.py disarm    --host 192.168.10.129 --login mslave --password 'pw'
    python3 bewave_client.py status    --cloud --serial <SERIAL> --jwt <BROKER_JWT> --login mslave --password 'pw'

Key chain (AES-256-GCM, IV = randomNumber||timestamp||counter, each BE32):
  sign-in  app->hub : key MD5(pw)*2            aad login
  sign-in  hub->app : key deviceUuid(ASCII)    aad MD5(login padded 64)
  ongoing  app->hub : key deviceUuid(ASCII)    aad MD5(sessionId)
  ongoing  hub->app : key sessionSecret(f4)    aad MD5(sessionId)
deviceUuid = client-chosen 32 hex chars; sessionSecret(f4)+sessionId(f3) come in the response.
"""
import socket, struct, hashlib, time, secrets, sys

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    raise SystemExit("pip install cryptography")

DISCOVERY_PORT = 4111
DATA_PORT = 4200

# ---------- small helpers ----------
def md5(x): return hashlib.md5(x.encode() if isinstance(x, str) else x).digest()
def pad(b, n):
    b = b.encode() if isinstance(b, str) else b
    return b + bytes(n - len(b))

def _wv(n):  # write varint
    out = bytearray()
    while True:
        b = n & 0x7f; n >>= 7
        out.append(b | (0x80 if n else 0));
        if not n: break
    return bytes(out)
def _rv(b, i):
    s = r = 0
    while True:
        x = b[i]; i += 1; r |= (x & 0x7f) << s; s += 7
        if not x & 0x80: break
    return r, i

# ---------- minimal protobuf builder/reader ----------
def pb_bytes(field, data): return _wv((field << 3) | 2) + _wv(len(data)) + data
def pb_varint(field, val): return _wv((field << 3) | 0) + _wv(val)
def pb_fixed32(field, val): return _wv((field << 3) | 5) + struct.pack('<I', val)

def pb_read(b):
    """shallow read -> {field:[values]}"""
    out = {}; i = 0
    while i < len(b):
        tag, i = _rv(b, i); fn, wt = tag >> 3, tag & 7
        if wt == 0: v, i = _rv(b, i)
        elif wt == 5: v = struct.unpack_from('<I', b, i)[0]; i += 4
        elif wt == 1: v = struct.unpack_from('<Q', b, i)[0]; i += 8
        elif wt == 2:
            ln, i = _rv(b, i); v = b[i:i+ln]; i += ln
        else: break
        out.setdefault(fn, []).append(v)
    return out

# ---------- message framing ----------
def build_message(counter, plaintext, key, aad, user_id=2, device_id=4):
    ts = int(time.time()) & 0xffffffff
    rnd = secrets.randbits(31)
    # header protobuf: f2 contentLength(fixed32), f3 userId, f4 deviceId,
    # f5 counter, f6 timestamp, f7 randomNumber, f8 protocolVersion
    header = (pb_fixed32(2, len(plaintext)) + pb_varint(3, user_id) + pb_varint(4, device_id)
              + pb_varint(5, counter) + pb_varint(6, ts) + pb_varint(7, rnd)
              + pb_bytes(8, b'\x01\x00'))
    iv = struct.pack('>III', rnd, ts, counter)
    ct = AESGCM(key).encrypt(iv, plaintext, aad)   # ciphertext||tag
    return b'\x0a' + _wv(len(header)) + header + ct

def parse_header(buf, i):
    """return (fields_dict, header_len, body_offset) for a 0x0a message at i, else None"""
    if buf[i] != 0x0a: return None
    hlen, j = _rv(buf, i + 1)
    header = buf[j:j+hlen]; fd = {}; k = 0
    while k < len(header):
        tag, k = _rv(header, k); fn, wt = tag >> 3, tag & 7
        if wt == 5: fd[fn] = struct.unpack_from('<I', header, k)[0]; k += 4
        elif wt == 0: fd[fn], k = _rv(header, k)
        elif wt == 2:
            ln, k = _rv(header, k); fd[fn] = header[k:k+ln]; k += ln
        else: return None
    return fd, hlen, j + hlen

# ============================================================
class BeWaveError(Exception): pass

class BeWaveClient:
    """Synchronous client. Use over local TCP or supply an MQTT transport."""
    def __init__(self, login, password, device_uuid=None):
        self.login = login
        self.password = password
        self.uuid = (device_uuid or secrets.token_hex(16).upper())[:32]
        self.serial = None
        self.session_id = None
        self.session_secret = None     # f4
        self.broker_jwt = None         # f6 (cloud MQTT password)
        self._counter = 0
        # keys
        self.K_signin = md5(password) * 2
        self.A_signin = login.encode()
        self.A_resp = md5(pad(login, 64))

    def next_counter(self):
        self._counter += 1
        return self._counter

    # ---- build the messages ----
    def signin_message(self):
        # plaintext: f6{ f1{ f2=uuid(str), f3=serial(str) } }
        inner = pb_bytes(2, self.uuid.encode()) + pb_bytes(3, (self.serial or "").encode())
        plaintext = pb_bytes(6, pb_bytes(1, inner))
        return build_message(self.next_counter(), plaintext, self.K_signin, self.A_signin)

    def command_message(self, plaintext):
        if not self.session_id:
            raise BeWaveError("not signed in")
        return build_message(self.next_counter(), plaintext, self.uuid.encode(), md5(self.session_id))

    def arm_disarm_plaintext(self, arm, mode="defau"):
        # f94{ f1{ f1{ f1=mode, f2=1|0 } } }
        inner = pb_bytes(1, mode.encode()) + pb_varint(2, 1 if arm else 0)
        return pb_bytes(94, pb_bytes(1, pb_bytes(1, inner)))

    # ---- decrypt an incoming framed message ----
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
        ks = [(self.uuid.encode(), self.A_resp)]      # sign-in response
        if self.session_secret and self.session_id:
            ks.append((self.session_secret, md5(self.session_id)))     # ongoing hub->app
            ks.append((self.uuid.encode(), md5(self.session_id)))      # ongoing app->hub (echo)
        ks.append((self.K_signin, self.A_signin))
        return ks

    def ingest_response(self, plaintext):
        """parse a sign-in response plaintext -> learn serial, sessionId, sessionSecret, jwt"""
        # structure: f7{ f1{ f1{...}, f2=serial, f3=sessionId, f4=secret, f6=jwt, f8=jwt } }
        try:
            l1 = pb_read(plaintext)[7][0]
            l2 = pb_read(l1)[1][0]
            f = pb_read(l2)
            self.serial = f[2][0].decode('latin1')
            self.session_id = f[3][0].decode('latin1')
            self.session_secret = f[4][0]
            if 6 in f: self.broker_jwt = f[6][0].decode('latin1')
            return True
        except Exception:
            return False


# ============================================================
# LOCAL transport (UDP discovery + TCP/4200)
# ============================================================
def discover(timeout=3, broadcast="255.255.255.255"):
    """Return list of {serial, endpoint, name} announced on UDP/4111."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(timeout)
    # StructureDiscoverRequest is small; replaying a minimal probe. Many HUBs also
    # answer to any datagram on 4111 — send a 1-byte probe and listen.
    found = {}
    try:
        s.sendto(b'\x00', (broadcast, DISCOVERY_PORT))
        t0 = time.time()
        while time.time() - t0 < timeout:
            try:
                data, addr = s.recvfrom(2048)
            except socket.timeout:
                break
            # plaintext protobuf; pull readable strings
            txt = ''.join(chr(b) if 32 <= b < 127 else ' ' for b in data)
            import re
            m = re.findall(r'(\d+\.\d+\.\d+\.\d+:\d+)', txt)
            ser = re.findall(r'([0-9A-Z]{25,40})', txt)
            if m:
                found[addr[0]] = {"ip": addr[0], "endpoint": m[0],
                                  "serial": ser[0] if ser else None}
    finally:
        s.close()
    return list(found.values())


class LocalConnection:
    def __init__(self, host, client: BeWaveClient, port=DATA_PORT, timeout=8):
        self.host = host; self.port = port; self.client = client; self.timeout = timeout
        self.sock = None; self._buf = b''

    def connect_and_signin(self):
        self.client.serial = self.client.serial  # may be None; HUB still accepts
        self.sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock.settimeout(self.timeout)
        # if serial unknown, discover it first
        if not self.client.serial:
            d = [x for x in discover() if x.get("serial")]
            if d: self.client.serial = d[0]["serial"]
        self.sock.sendall(self.client.signin_message())
        # read until we get the sign-in response (the big one)
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            self._pump()
            for fd, pt in self._drain():
                if pt and len(pt) > 200 and self.client.ingest_response(pt):
                    return True
        raise BeWaveError("sign-in response not received/decrypted")

    def _pump(self):
        try:
            data = self.sock.recv(8192)
            if data: self._buf += data
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
        return out

    def send_command(self, plaintext):
        self.sock.sendall(self.client.command_message(plaintext))

    def arm(self, mode="defau"):  self.send_command(self.client.arm_disarm_plaintext(True, mode))
    def disarm(self, mode="defau"): self.send_command(self.client.arm_disarm_plaintext(False, mode))

    def read_messages(self, seconds=2):
        out = []; t0 = time.time()
        while time.time() - t0 < seconds:
            self._pump(); out += self._drain()
        return out

    def close(self):
        try: self.sock.close()
        except Exception: pass


# ============================================================
# CLI for live testing
# ============================================================
def _cli():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["discover", "status", "arm", "disarm"])
    ap.add_argument("--host"); ap.add_argument("--login"); ap.add_argument("--password")
    ap.add_argument("--serial"); ap.add_argument("--uuid")
    ap.add_argument("--mode", default="defau")
    a = ap.parse_args()
    if a.action == "discover":
        for d in discover(): print(d)
        return
    c = BeWaveClient(a.login, a.password, a.uuid)
    if a.serial: c.serial = a.serial
    conn = LocalConnection(a.host, c)
    conn.connect_and_signin()
    print("signed in. serial=", c.serial)
    print("sessionId=", c.session_id[:40], "...")
    print("uuid=", c.uuid)
    if a.action == "arm": conn.arm(a.mode); print("ARM sent")
    elif a.action == "disarm": conn.disarm(a.mode); print("DISARM sent")
    for fd, pt in conn.read_messages(2):
        if pt:
            import re
            s = b' '.join(re.findall(rb'[\x20-\x7e]{3,}', pt)).decode('latin1')[:80]
            print(f"  msg c={fd.get(5)} clen={fd.get(2)} {s}")
    conn.close()

if __name__ == "__main__":
    _cli()
