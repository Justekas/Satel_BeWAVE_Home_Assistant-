"""Config + options flow for BE WAVE (with DHCP auto-discovery)."""
from __future__ import annotations
import logging
import secrets
import voluptuous as vol

_LOGGER = logging.getLogger(__name__)

from homeassistant import config_entries
from homeassistant.core import HomeAssistant, callback

try:  # HA 2024.x location
    from homeassistant.helpers.service_info.dhcp import DhcpServiceInfo
except ImportError:  # older fallback
    from homeassistant.components.dhcp import DhcpServiceInfo  # type: ignore

from .const import (DOMAIN, CONF_LOGIN, CONF_PASSWORD, CONF_HOST, CONF_SERIAL,
                    CONF_DEVICE_UUID, CONF_MODE, DEFAULT_MODE)
from . import bewave_client as proto


async def _validate(hass: HomeAssistant, data: dict) -> str:
    """Connect + sign in. Returns the controller serial. Raises on failure."""
    def _do():
        client = proto.BeWaveClient(data[CONF_LOGIN], data[CONF_PASSWORD],
                                    data[CONF_DEVICE_UUID])
        if data.get(CONF_SERIAL):
            client.serial = data[CONF_SERIAL]
        conn = proto.LocalConnection(data[CONF_HOST], client)
        try:
            conn.connect_and_signin()
            return client.serial
        finally:
            conn.close()
    return await hass.async_add_executor_job(_do)


class BeWaveConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    def __init__(self):
        self._host: str | None = None

    async def async_step_dhcp(self, discovery_info: DhcpServiceInfo):
        """Triggered when a Satel (00:1B:9C) device appears on the network."""
        self._host = discovery_info.ip
        mac = discovery_info.macaddress.replace(":", "").upper()
        await self.async_set_unique_id(f"bewave_mac_{mac}")
        self._abort_if_unique_id_configured(updates={CONF_HOST: self._host})
        self.context["title_placeholders"] = {"name": f"BE WAVE controller ({self._host})"}
        return await self.async_step_user()

    async def async_step_user(self, user_input=None):
        errors = {}
        if user_input is not None:
            user_input[CONF_DEVICE_UUID] = (
                (user_input.get(CONF_DEVICE_UUID) or secrets.token_hex(16))
                .strip()
                .upper()[:32]
            )
            try:
                serial = await _validate(self.hass, user_input)
            except proto.BeWaveError as err:
                _LOGGER.error("BE WAVE sign-in failed for %s: %s",
                              user_input.get(CONF_HOST), err)
                if "code 31" in str(err):
                    errors["base"] = "invalid_auth"
                else:
                    errors["base"] = "cannot_connect"
            except Exception as err:  # noqa: BLE001
                _LOGGER.error("BE WAVE sign-in failed for %s: %s",
                              user_input.get(CONF_HOST), err)
                errors["base"] = "cannot_connect"
            else:
                user_input[CONF_SERIAL] = serial or user_input.get(CONF_SERIAL)
                # prefer the real serial as unique id when known
                await self.async_set_unique_id(f"bewave_{serial}", raise_on_progress=False)
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=f"BE WAVE {serial or ''}".strip(), data=user_input)

        schema = vol.Schema({
            vol.Required(CONF_HOST, default=self._host or vol.UNDEFINED): str,
            vol.Required(CONF_LOGIN): str,
            vol.Required(CONF_PASSWORD): str,
            vol.Optional(CONF_MODE, default=DEFAULT_MODE): str,
            vol.Optional(CONF_SERIAL): str,
            vol.Optional(CONF_DEVICE_UUID): str,
        })
        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        return BeWaveOptionsFlow(config_entry)


class BeWaveOptionsFlow(config_entries.OptionsFlow):
    def __init__(self, entry):
        self.entry = entry

    async def async_step_init(self, user_input=None):
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)
        current = self.entry.options.get(
            CONF_MODE, self.entry.data.get(CONF_MODE, DEFAULT_MODE))
        schema = vol.Schema({vol.Optional(CONF_MODE, default=current): str})
        return self.async_show_form(step_id="init", data_schema=schema)
