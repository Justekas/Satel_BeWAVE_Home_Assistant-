"""BE WAVE site-setting switches (LED indicator, GRADE 2, SATEL server)."""
from __future__ import annotations

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo, EntityCategory
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DEFAULT_CONTROLLER_MODEL, DOMAIN

# key -> (display name, reliability note)
SWITCHES = [
    ("led", "LED indicator"),
    ("grade2", "Grade 2"),
    ("satel", "SATEL server connection"),
]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities):
    data = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(
        BeWaveSettingSwitch(data["coordinator"], data["hub"], entry, key, name)
        for key, name in SWITCHES
    )


class BeWaveSettingSwitch(CoordinatorEntity, SwitchEntity):
    _attr_has_entity_name = True
    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, coordinator, hub, entry: ConfigEntry, key: str, name: str):
        super().__init__(coordinator)
        self._hub = hub
        self._key = key
        self._attr_name = name
        serial = entry.data.get("serial") or entry.entry_id
        self._attr_unique_id = f"bewave_{serial}_{key}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, serial)},
            manufacturer="Satel",
            model=DEFAULT_CONTROLLER_MODEL,
            name=entry.title or f"BE WAVE {serial}",
        )

    @property
    def is_on(self) -> bool | None:
        # None -> Home Assistant shows the entity as unknown until first read
        return self._hub.flags.get(self._key)

    async def async_turn_on(self, **kwargs):
        await self.hass.async_add_executor_job(self._hub.set_toggle, self._key, True)
        await self.coordinator.async_request_refresh()
        self.async_write_ha_state()

    async def async_turn_off(self, **kwargs):
        await self.hass.async_add_executor_job(self._hub.set_toggle, self._key, False)
        await self.coordinator.async_request_refresh()
        self.async_write_ha_state()
