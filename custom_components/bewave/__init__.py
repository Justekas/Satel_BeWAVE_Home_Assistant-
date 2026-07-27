"""BE WAVE (Satel) integration for Home Assistant."""
from __future__ import annotations
import logging
import threading
import time
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import (DOMAIN, CONF_LOGIN, CONF_PASSWORD, CONF_HOST, CONF_SERIAL,
                    CONF_DEVICE_UUID, CONF_MODE, DEFAULT_MODE, SCAN_INTERVAL_SECONDS)
from . import bewave_client as proto

_LOGGER = logging.getLogger(__name__)
PLATFORMS = ["alarm_control_panel", "switch", "binary_sensor", "sensor"]


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

    def _ensure(self):
        if self.conn is not None:
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
                            pass
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

    def arm(self):
        with self._lock:
            # do not claim "armed" until the hub confirms via read-back
            self._command(lambda: self.conn.arm(self.mode),
                          verify=lambda: self.state == "armed_away")
    def disarm(self):
        with self._lock:
            self._command(lambda: self.conn.disarm(self.mode),
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
    entry.async_on_unload(entry.add_update_listener(_async_reload))

    async def _update():
        return await hass.async_add_executor_job(hub.poll)

    coordinator = DataUpdateCoordinator(
        hass, _LOGGER, name=DOMAIN, update_method=_update,
        update_interval=timedelta(seconds=SCAN_INTERVAL_SECONDS),
    )
    await coordinator.async_config_entry_first_refresh()

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
