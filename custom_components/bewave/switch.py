"""BE WAVE switches: site-setting toggles and wired PGM output relays."""
from __future__ import annotations

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo, EntityCategory
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DEFAULT_CONTROLLER_MODEL, DOMAIN

# key -> display name  (site-level setting toggles)
SWITCHES = [
    ("led", "LED indicator"),
    ("grade2", "Grade 2"),
    ("satel", "SATEL server connection"),
]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities):
    data = hass.data[DOMAIN][entry.entry_id]
    hub, coordinator = data["hub"], data["coordinator"]

    # site-setting switches (LED, Grade 2, SATEL server)
    async_add_entities(
        BeWaveSettingSwitch(coordinator, hub, entry, key, name)
        for key, name in SWITCHES
    )

    # wired output (PGM/relay) switches — discovered dynamically
    known_outputs: set[int] = set()

    @callback
    def _sync_outputs():
        new = []
        for d in hub.devices():
            if d["cat"] == "output" and d["id"] not in known_outputs:
                known_outputs.add(d["id"])
                new.append(BeWaveOutputSwitch(coordinator, hub, entry, d["id"]))
        if new:
            async_add_entities(new)

    _sync_outputs()
    entry.async_on_unload(coordinator.async_add_listener(_sync_outputs))


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
        return self._hub.flags.get(self._key)

    async def async_turn_on(self, **kwargs):
        await self.hass.async_add_executor_job(self._hub.set_toggle, self._key, True)
        await self.coordinator.async_request_refresh()
        self.async_write_ha_state()

    async def async_turn_off(self, **kwargs):
        await self.hass.async_add_executor_job(self._hub.set_toggle, self._key, False)
        await self.coordinator.async_request_refresh()
        self.async_write_ha_state()


class BeWaveOutputSwitch(CoordinatorEntity, SwitchEntity):
    """Wired PGM/relay output on the BE WAVE controller."""
    _attr_has_entity_name = True

    def __init__(self, coordinator, hub, entry: ConfigEntry, devid):
        super().__init__(coordinator)
        self._hub = hub
        self._devid = devid
        serial = entry.data.get("serial") or entry.entry_id
        d = self._dev()
        self._attr_name = d.get("name") or f"Output {devid}"
        # Use full devkey (e.g. "o5") — keeps zones and outputs collision-free
        self._attr_unique_id = f"bewave_{serial}_{devid}_output"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, f"{serial}_{devid}")},
            manufacturer="Satel",
            name=d.get("name") or f"BE WAVE Output {devid}",
            via_device=(DOMAIN, serial),
        )

    def _dev(self):
        for d in self._hub.devices():
            if d["id"] == self._devid:
                return d
        return {}

    @property
    def is_on(self) -> bool | None:
        s = self._dev().get("state")
        return None if s is None else (s == 1)

    @property
    def extra_state_attributes(self):
        d = self._dev()
        return {"room": d.get("room"), "system_number": d.get("sysnum")}

    async def async_turn_on(self, **kwargs):
        await self.hass.async_add_executor_job(self._hub.toggle_output, self._devid)
        await self.coordinator.async_request_refresh()
        self.async_write_ha_state()

    async def async_turn_off(self, **kwargs):
        await self.hass.async_add_executor_job(self._hub.toggle_output, self._devid)
        await self.coordinator.async_request_refresh()
        self.async_write_ha_state()
