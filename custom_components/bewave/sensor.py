"""BE WAVE sensors: temperature and battery level per device."""
from __future__ import annotations

from homeassistant.components.sensor import (
    SensorEntity, SensorDeviceClass, SensorStateClass)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfTemperature, PERCENTAGE
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN

# kind -> (field, name, device_class, unit)
_KINDS = {
    "temp": ("temp", "Temperature", SensorDeviceClass.TEMPERATURE, UnitOfTemperature.CELSIUS),
    "battery": ("battery", "Battery", SensorDeviceClass.BATTERY, PERCENTAGE),
}


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities):
    data = hass.data[DOMAIN][entry.entry_id]
    hub, coordinator = data["hub"], data["coordinator"]
    known: set[tuple[int, str]] = set()

    @callback
    def _sync():
        new = []
        for d in hub.devices():
            for kind in ("temp", "battery"):
                if d.get(kind) is not None and (d["id"], kind) not in known:
                    known.add((d["id"], kind))
                    new.append(BeWaveSensor(coordinator, hub, entry, d["id"], kind))
        if new:
            async_add_entities(new)

    _sync()
    entry.async_on_unload(coordinator.async_add_listener(_sync))


class BeWaveSensor(CoordinatorEntity, SensorEntity):
    _attr_has_entity_name = True
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, coordinator, hub, entry: ConfigEntry, devid, kind):
        super().__init__(coordinator)
        self._hub = hub
        self._devid = devid
        self._field, name, dclass, unit = _KINDS[kind]
        self._attr_name = name
        self._attr_device_class = dclass
        self._attr_native_unit_of_measurement = unit
        serial = entry.data.get("serial") or entry.entry_id
        self._attr_unique_id = f"bewave_{serial}_{devid}_{kind}"
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
    def native_value(self):
        return self._dev().get(self._field)
