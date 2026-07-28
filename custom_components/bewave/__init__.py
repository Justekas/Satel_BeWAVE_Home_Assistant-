"""BE WAVE (Satel) integration for Home Assistant."""
from __future__ import annotations
import logging
import threading
import time
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import (DOMAIN, CONF_LOGIN, CONF_PASSWORD, CONF_HOST, CONF_SERIAL,
                    CONF_DEVICE_UUID, CONF_MODE, CONF_ARMING_MODES, DEFAULT_MODE, SCAN_INTERVAL_SECONDS)
from . import bewave_client as proto

_LOGGER = logging.getLogger(__name__)
PLATFORMS = ["alarm_control_panel", "switch", "binary_sensor", "sensor"]


def _is_default_partition(mode_key: str, pdata: dict, default_mode: str) -> bool:
    return (
        mode_key == default_mode
        or pdata.get("mode") == default_mode
        or pdata.get("name") == default_mode
        or pdata.get("name") == "default"
    )


class BeWaveHub:
    """Owns a persistent local connection; thread-safe for executor jobs."""

    def __init__(self, host, login, password, device_uuid, serial=None, mode="defau"):
        self.host = host
        self.mode = mode
        self._lock = threading.Lock()
        self.client = proto.BeWaveClient(login, password, device_uuid)
        if serial:
            self.client.serial = serial
        self.conn: proto.LocalConnection | None = None
        self._registered = False
        self._empty = 0                        # consecutive polls with no data
        self.state: str | None = None          # armed_away | disarmed | None
        self.flags = {"led": None, "grade2": None, "satel": None}
        self.info = {"power": None, "stor_free": None, "stor_total": None,
                     "network": None, "firmware": None}
        self.dev_names: dict[str, dict] = {}   # config: name/room/model/sysnum/bypass
        self.dev_state: dict[str, dict] = {}   # live telemetry
        self._id_map: dict[tuple, str] = {}    # (f1,f2) -> devkey, for telemetry lookup
        self.partitions: dict[str, dict] = {}  # partition config: {mode_key: {name,id}}
        self.partition_states: dict[str | int | None, bool] = {}  # {mode/id: is_armed}
        self.active_modes: set[str] | None = None  # None = no f45 yet; set = known modes

    def _sync_partition_state_keys(self):
        for mode_key, pdata in self.partitions.items():
            pid = pdata.get("id")
            if pid in self.partition_states:
                self.partition_states[mode_key] = self.partition_states[pid]

    def _ensure(self):
        # conn.sock being None means a previous connect_and_signin failed partway —
        # treat it the same as conn=None and reconnect.
        if self.conn is not None and self.conn.sock is not None:
            return
        self.conn = proto.LocalConnection(self.host, self.client)
        self.conn.connect_and_signin()         # subscribes + registers
        if not self._registered:
            # firmware 1.04+: a brand-new self-generated device id gets FULL access
            # (state + control) only AFTER it registers, the hub processes the
            # registration (and the user approves the "new device" on their phone if
            # prompted), and we then reconnect. The wait is essential — reconnecting
            # immediately leaves the device read-only (it can read state but the hub
            # ignores its arm/disarm commands). Proven with bewave_ownuuid.py.
            self._registered = True
            self.conn.close()
            self.conn = None
            time.sleep(8)
            self.conn = proto.LocalConnection(self.host, self.client)
            self.conn.connect_and_signin()
        _LOGGER.info("BE WAVE: signed in to %s (serial=%s)", self.host, self.client.serial)

    def _reconnect(self):
        """Drop a dead/stale session and sign in again (caller holds the lock)."""
        try:
            if self.conn:
                self.conn.close()
        except Exception:
            pass
        self.conn = None
        self._empty = 0
        self._ensure()

    def poll(self):
        with self._lock:
            try:
                self._ensure()
                self.conn.refresh()            # light re-subscribe (f88 + f26)
                msgs = self.conn.read_messages(1.5)
                if msgs:
                    self._empty = 0
                    self._update_from(msgs)
                    # HYBRID closes TCP after every burst. Proactively reconnect
                    # now so the buffer is pre-filled for the next poll instead of
                    # spending an entire poll interval on an empty reconnect cycle.
                    if self.conn._closed:
                        try:
                            self._reconnect()
                        except Exception:
                            # Failed proactive reconnect — clear conn so _ensure
                            # tries again next poll instead of using a sock=None conn.
                            self.conn = None
                else:
                    # A healthy session answers a refresh with telemetry; several
                    # silent polls in a row mean the hub dropped us -> reconnect.
                    self._empty += 1
                    if self._empty >= 3:
                        _LOGGER.info("BE WAVE: stale session, reconnecting")
                        self._reconnect()
                        # drain the fresh pipeline burst collected during reconnect
                        if self.conn and self.conn._buf:
                            fresh = self.conn._drain()
                            if fresh:
                                self._empty = 0
                                self._update_from(fresh)
                    elif self._empty == 1:
                        # could be HYBRID with hub-closed; try reconnect to get fresh state
                        _LOGGER.debug("BE WAVE: no data from hub, attempting reconnect")
                        self._reconnect()
                        if self.conn and self.conn._buf:
                            fresh = self.conn._drain()
                            if fresh:
                                self._empty = 0
                                self._update_from(fresh)
                return {"state": self.state}
            except Exception as err:
                try:
                    if self.conn: self.conn.close()
                finally:
                    self.conn = None
                self._empty = 0
                raise UpdateFailed(f"BE WAVE poll failed: {err}") from err

    def _update_from(self, msgs):
        for _fd, pt in msgs:
            if not pt:
                continue
            # Per-partition arm states (replaces simple global state)
            part_states = proto.parse_armed_states(pt)
            if part_states:
                self.partition_states.update(part_states)
                self._sync_partition_state_keys()
                # Global state: armed if any partition is armed
                all_armed = [v for v in part_states.values() if v is not None]
                if all_armed:
                    self.state = "armed_away" if any(all_armed) else "disarmed"
            else:
                # Fallback to old single-value armed_state
                st = proto.armed_state(pt)
                if st is not None:
                    self.state = "armed_away" if st else "disarmed"
            fl = proto.system_status(pt)
            if fl is not None:
                self.flags.update(fl)
            hi = proto.hub_info(pt)
            if hi is not None:
                self.info.update({"power": hi["power"], "stor_free": hi["stor_free"],
                                  "stor_total": hi["stor_total"]})
                if hi.get("firmware"):
                    self.info["firmware"] = hi["firmware"]
            net = proto.network_active(pt)
            if net is not None:
                self.info["network"] = net
            # Partition config
            parts = proto.parse_config_partitions(pt)
            if parts:
                self.partitions.update(parts)
                self._sync_partition_state_keys()
            # Active modes from f45 user data (which mode each user has selected)
            active = proto.parse_active_modes(pt)
            if active is not None:
                self.active_modes = active
                for mode_key in self.partitions:
                    self.partition_states[mode_key] = mode_key in self.active_modes
            cfg = proto.parse_config_devices(pt)
            for devkey, d in cfg.items():
                self.dev_names[devkey] = {k: d[k] for k in
                    ("name", "room", "type", "is_output", "model", "sysnum", "bypass")}
                # rebuild id_map so telemetry can resolve (f1,f2) -> devkey
                f1, f2 = d.get("_f1"), d.get("_f2")
                if f1 is not None or f2 is not None:
                    self._id_map[(f1, f2)] = devkey
                ds = self.dev_state.setdefault(devkey, {})
                for k in ("signal", "battery", "state", "temp", "type", "volt"):
                    if d.get(k) is not None:
                        ds[k] = d[k]
            for devkey, d in proto.parse_telemetry(pt, id_map=self._id_map).items():
                self.dev_state.setdefault(devkey, {}).update(
                    {k: v for k, v in d.items() if v is not None})
        # while armed, a currently-violated contact/motion zone means the alarm has
        # been tripped -> show the panel as "triggered" (sounding)
        if self.state == "armed_away":
            for _dkey, _st in self.dev_state.items():
                _typ = self.dev_names.get(_dkey, {}).get("type") or _st.get("type")
                if _st.get("state") == 1 and proto.DEV_TYPES.get(_typ) in ("contact", "motion"):
                    self.state = "triggered"
                    break

    def devices(self):
        out = []
        for did in set(self.dev_names) | set(self.dev_state):
            nm = self.dev_names.get(did, {}); st = self.dev_state.get(did, {})
            typ = nm.get("type") or st.get("type")
            # is_output flag set in parse_config_devices overrides DEV_TYPES lookup
            if nm.get("is_output"):
                cat = "output"
            else:
                cat = proto.DEV_TYPES.get(typ, "device")
            out.append({"id": did, "name": nm.get("name") or f"#{did}",
                        "room": nm.get("room"), "model": nm.get("model"),
                        "sysnum": nm.get("sysnum"), "bypass": nm.get("bypass"),
                        "cat": cat,
                        "state": st.get("state"), "temp": st.get("temp"),
                        "battery": st.get("battery"), "signal": st.get("signal"),
                        "volt": st.get("volt")})
        return out

    def _command(self, send, verify=None):
        """Run a command on a live session, verifying + retrying on a fresh
        connection if the socket was stale (commands are lost on a dead socket).
        Caller holds the lock."""
        last = None
        for attempt in (1, 2):
            try:
                self._ensure()
                send()
                # A live session answers with telemetry; no reply == dropped
                # socket (half-open), so require real data before trusting it.
                msgs = self.conn.read_messages(2)
                self._update_from(msgs)
                if msgs and (verify is None or verify()):
                    self._empty = 0
                    return True
            except Exception as err:
                last = err
            # stale, silent or unverified -> reconnect and try once more
            self._reconnect()
        if last:
            errno = getattr(last, "errno", None)
            if errno in (32, 104, 10054) or "connection closed by hub" in str(last):
                _LOGGER.debug("BE WAVE: command socket dropped (expected): %s", last)
            else:
                _LOGGER.warning("BE WAVE: command failed: %s", last)
        return False

    def arm(self, partition_mode: str | None = None):
        """Arm one partition (by mode/room name) or all partitions (mode=None)."""
        mode = partition_mode if partition_mode is not None else self.mode
        with self._lock:
            self._command(
                lambda: self.conn.send_command(
                    self.client.arm_disarm_plaintext(True, mode)),
                verify=lambda: self.state == "armed_away")

    def disarm(self, partition_mode: str | None = None):
        """Disarm one partition (by mode/room name) or all partitions (mode=None)."""
        mode = partition_mode if partition_mode is not None else self.mode
        with self._lock:
            self._command(
                lambda: self.conn.send_command(
                    self.client.arm_disarm_plaintext(False, mode)),
                verify=lambda: self.state == "disarmed")
    def set_toggle(self, name, desired):
        if name not in proto.SETTING_IDS:
            return
        with self._lock:
            def _send():
                cur = self.flags.get(name)
                if cur is None or cur != desired:
                    self.conn.toggle_setting(proto.SETTING_IDS[name])
                self.flags[name] = desired
            self._command(_send, verify=lambda: self.flags.get(name) == desired)

    def toggle_output(self, devid):
        """Toggle a wired PGM output on/off."""
        sysnum = self.dev_names.get(devid, {}).get("sysnum") or devid
        with self._lock:
            self._command(lambda: self.conn.toggle_output(sysnum))


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    hub = BeWaveHub(
        host=entry.data[CONF_HOST],
        login=entry.data[CONF_LOGIN],
        password=entry.data[CONF_PASSWORD],
        device_uuid=entry.data[CONF_DEVICE_UUID],
        serial=entry.data.get(CONF_SERIAL),
        mode=entry.options.get(CONF_MODE, entry.data.get(CONF_MODE, DEFAULT_MODE)),
    )
    # Load user-configured arming modes (e.g. "am1,am2") into hub.partitions so
    # alarm_control_panel can create per-mode panels immediately at setup.
    _modes_str = entry.options.get(CONF_ARMING_MODES, entry.data.get(CONF_ARMING_MODES, ""))
    for _m in (_x.strip() for _x in _modes_str.split(",") if _x.strip()):
        hub.partitions.setdefault(_m, {"mode": _m, "name": _m, "id": None})
    entry.async_on_unload(entry.add_update_listener(_async_reload))

    async def _update():
        return await hass.async_add_executor_job(hub.poll)

    coordinator = DataUpdateCoordinator(
        hass, _LOGGER, name=DOMAIN, update_method=_update,
        update_interval=timedelta(seconds=SCAN_INTERVAL_SECONDS),
    )
    await coordinator.async_config_entry_first_refresh()

    # Remove stale devices (old key scheme, removed hardware, user account ghosts)
    # Use FULL devkey (e.g. "z1", "o5") to avoid zone/output collisions.
    serial = entry.data.get(CONF_SERIAL) or entry.entry_id
    valid_ids: set = {(DOMAIN, serial)}
    for d in hub.devices():
        valid_ids.add((DOMAIN, f"{serial}_{d['id']}"))
    for part_key, pdata in hub.partitions.items():
        if not _is_default_partition(part_key, pdata, hub.mode):
            valid_ids.add((DOMAIN, f"{serial}_part_{part_key}"))
    dev_reg = dr.async_get(hass)
    for dev_entry in dr.async_entries_for_config_entry(dev_reg, entry.entry_id):
        if not dev_entry.identifiers.intersection(valid_ids):
            _LOGGER.debug("BE WAVE: removing stale device %s", dev_entry.identifiers)
            dev_reg.async_remove_device(dev_entry.id)

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {"hub": hub, "coordinator": coordinator}
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def _async_reload(hass: HomeAssistant, entry: ConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if ok:
        data = hass.data[DOMAIN].pop(entry.entry_id)
        hub: BeWaveHub = data["hub"]
        if hub.conn:
            await hass.async_add_executor_job(hub.conn.close)
    return ok
