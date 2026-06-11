"""BE WAVE binary sensors: opening (door/window) and motion detectors."""
from __future__ import annotations

from homeassistant.components.binary_sensor import (
    BinarySensorEntity, BinarySensorDeviceClass)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN

_CLASS = {"contact": BinarySensorDeviceClass.OPENING,
          "motion": BinarySensorDeviceClass.MOTION}


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities):
    data = hass.data[DOMAIN][entry.entry_id]
    hub, coordinator = data["hub"], data["coordinator"]
    known: set[int] = set()

    @callback
    def _sync():
        new = []
        for d in hub.devices():
            if d["cat"] in _CLASS and d["id"] not in known:
                known.add(d["id"])
                new.append(BeWaveBinary(coordinator, hub, entry, d["id"], _CLASS[d["cat"]]))
        if new:
            async_add_entities(new)

    _sync()
    entry.async_on_unload(coordinator.async_add_listener(_sync))


class BeWaveBinary(CoordinatorEntity, BinarySensorEntity):
    _attr_has_entity_name = True
    _attr_name = None

    def __init__(self, coordinator, hub, entry: ConfigEntry, devid, devclass):
        super().__init__(coordinator)
        self._hub = hub
        self._devid = devid
        self._attr_device_class = devclass
        serial = entry.data.get("serial") or entry.entry_id
        self._attr_unique_id = f"bewave_{serial}_{devid}_state"
        d = self._dev()
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, f"{serial}_{devid}")},
            manufacturer="Satel", model=d.get("model"),
            name=d.get("name") or f"BE WAVE {devid}",
            via_device=(DOMAIN, serial),
        )

    def _dev(self):
        for d in self._hub.devices():
            if d["id"] == self._devid:
                return d
        return {}

    @property
    def is_on(self):
        s = self._dev().get("state")
        return None if s is None else (s == 1)

    @property
    def extra_state_attributes(self):
        d = self._dev()
        return {"room": d.get("room"), "system_number": d.get("sysnum"),
                "serial": d.get("id"), "signal_pct": d.get("signal"),
                "battery_pct": d.get("battery"), "battery_voltage": d.get("volt"),
                "bypassed": d.get("bypass")}
