"""BE WAVE alarm_control_panel entity."""
from __future__ import annotations

from homeassistant.components.alarm_control_panel import (
    AlarmControlPanelEntity, AlarmControlPanelEntityFeature, AlarmControlPanelState,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DEFAULT_CONTROLLER_MODEL, DOMAIN

_STATE_MAP = {
    "armed_away": AlarmControlPanelState.ARMED_AWAY,
    "disarmed": AlarmControlPanelState.DISARMED,
    "triggered": AlarmControlPanelState.TRIGGERED,
}


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities):
    data = hass.data[DOMAIN][entry.entry_id]
    hub, coordinator = data["hub"], data["coordinator"]

    # Global panel (whole system arm/disarm — always present)
    async_add_entities([BeWaveAlarmPanel(coordinator, hub, entry)])

    # Per-partition panels — discovered dynamically from hub config
    known_parts: set = set()

    @callback
    def _sync_partitions():
        new = []
        for pid, pdata in hub.partitions.items():
            if pid not in known_parts:
                known_parts.add(pid)
                new.append(BeWavePartitionPanel(coordinator, hub, entry, pid, pdata.get("name")))
        if new:
            async_add_entities(new)

    _sync_partitions()
    entry.async_on_unload(coordinator.async_add_listener(_sync_partitions))


class BeWaveAlarmPanel(CoordinatorEntity, AlarmControlPanelEntity):
    _attr_has_entity_name = True
    _attr_name = None
    _attr_code_arm_required = False
    _attr_supported_features = (
        AlarmControlPanelEntityFeature.ARM_AWAY
    )

    def __init__(self, coordinator, hub, entry: ConfigEntry):
        super().__init__(coordinator)
        self._hub = hub
        self._serial = entry.data.get("serial") or entry.entry_id
        self._attr_unique_id = f"bewave_{self._serial}_panel"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, self._serial)},
            manufacturer="Satel",
            model=DEFAULT_CONTROLLER_MODEL,
            name=entry.title or f"BE WAVE {self._serial}",
        )

    @property
    def alarm_state(self) -> AlarmControlPanelState | None:
        st = self._hub.state or (self.coordinator.data or {}).get("state")
        return _STATE_MAP.get(st)

    @property
    def extra_state_attributes(self) -> dict[str, str | int | None]:
        return {
            "serial": self._serial,
            "host": self._hub.host,
            "firmware": self._hub.info.get("firmware"),
            "network": self._hub.info.get("network"),
            "power_pct": self._hub.info.get("power"),
            "storage_free": self._hub.info.get("stor_free"),
            "storage_total": self._hub.info.get("stor_total"),
            "protection_mode": self._hub.mode,
        }

    async def async_alarm_arm_away(self, code=None):
        await self.hass.async_add_executor_job(self._hub.arm)
        await self.coordinator.async_request_refresh()
        self.async_write_ha_state()

    async def async_alarm_disarm(self, code=None):
        await self.hass.async_add_executor_job(self._hub.disarm)
        await self.coordinator.async_request_refresh()
        self.async_write_ha_state()


class BeWavePartitionPanel(CoordinatorEntity, AlarmControlPanelEntity):
    """Per-partition alarm panel (one per area/partition defined in the hub)."""
    _attr_has_entity_name = True
    _attr_code_arm_required = False
    _attr_supported_features = AlarmControlPanelEntityFeature.ARM_AWAY

    def __init__(self, coordinator, hub, entry: ConfigEntry, part_id: int, name: str | None):
        super().__init__(coordinator)
        self._hub = hub
        self._part_id = part_id
        serial = entry.data.get("serial") or entry.entry_id
        self._attr_name = name or f"Partition {part_id}"
        self._attr_unique_id = f"bewave_{serial}_part{part_id}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, f"{serial}_part{part_id}")},
            manufacturer="Satel",
            name=name or f"BE WAVE Partition {part_id}",
            via_device=(DOMAIN, serial),
        )

    @property
    def alarm_state(self) -> AlarmControlPanelState | None:
        # Try per-partition state first, fall back to global
        armed = self._hub.partition_states.get(self._part_id)
        if armed is None:
            armed = self._hub.partition_states.get(None)
        if armed is None:
            return None
        # Check if any zone in this partition is triggered
        if armed and self._hub.state == "triggered":
            return AlarmControlPanelState.TRIGGERED
        return AlarmControlPanelState.ARMED_AWAY if armed else AlarmControlPanelState.DISARMED

    async def async_alarm_arm_away(self, code=None):
        await self.hass.async_add_executor_job(self._hub.arm, self._part_id)
        await self.coordinator.async_request_refresh()
        self.async_write_ha_state()

    async def async_alarm_disarm(self, code=None):
        await self.hass.async_add_executor_job(self._hub.disarm, self._part_id)
        await self.coordinator.async_request_refresh()
        self.async_write_ha_state()
