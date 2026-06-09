"""BE WAVE (Satel) integration for Home Assistant."""
from __future__ import annotations
import logging
import threading
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import (DOMAIN, CONF_LOGIN, CONF_PASSWORD, CONF_HOST, CONF_SERIAL,
                    CONF_DEVICE_UUID, CONF_MODE, DEFAULT_MODE, SCAN_INTERVAL_SECONDS)
from . import bewave_client as proto

_LOGGER = logging.getLogger(__name__)
PLATFORMS = ["alarm_control_panel"]


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
        # last known state for the panel: "armed_away" | "disarmed" | "triggered" | None
        self.state: str | None = None

    def _ensure(self):
        if self.conn is None:
            self.conn = proto.LocalConnection(self.host, self.client)
            self.conn.connect_and_signin()
            _LOGGER.info("BE WAVE: signed in to %s (serial=%s)", self.host, self.client.serial)

    def poll(self):
        with self._lock:
            try:
                self._ensure()
                msgs = self.conn.read_messages(1)
                self._update_state_from(msgs)
                return {"state": self.state, "serial": self.client.serial}
            except Exception as err:  # reconnect next time
                try:
                    if self.conn:
                        self.conn.close()
                finally:
                    self.conn = None
                raise UpdateFailed(f"BE WAVE poll failed: {err}") from err

    def _update_state_from(self, msgs):
        # Best-effort: status field mapping for armed/alarm is not fully decoded yet,
        # so panel state is driven optimistically by commands (see arm/disarm).
        # Hook left here to refine once the protection-mode status field is mapped.
        return

    def arm(self):
        with self._lock:
            self._ensure()
            self.conn.arm(self.mode)
            self.state = "armed_away"

    def disarm(self):
        with self._lock:
            self._ensure()
            self.conn.disarm(self.mode)
            self.state = "disarmed"


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
        hass, _LOGGER, name=DOMAIN,
        update_method=_update,
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
