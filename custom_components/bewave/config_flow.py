"""Config + options flow for BE WAVE."""
from __future__ import annotations
import secrets
import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import HomeAssistant, callback

from .const import (DOMAIN, CONF_LOGIN, CONF_PASSWORD, CONF_HOST, CONF_SERIAL,
                    CONF_DEVICE_UUID, CONF_MODE, DEFAULT_MODE)
from . import bewave_client as proto


async def _validate(hass: HomeAssistant, data: dict) -> str:
    """Connect + sign in. Returns the HUB serial. Raises on failure."""
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

    async def async_step_user(self, user_input=None):
        errors = {}
        if user_input is not None:
            user_input[CONF_DEVICE_UUID] = secrets.token_hex(16).upper()
            try:
                serial = await _validate(self.hass, user_input)
            except Exception:  # noqa: BLE001
                errors["base"] = "cannot_connect"
            else:
                user_input[CONF_SERIAL] = serial or user_input.get(CONF_SERIAL)
                await self.async_set_unique_id(f"bewave_{serial}")
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=f"BE WAVE {serial or ''}".strip(), data=user_input)

        schema = vol.Schema({
            vol.Required(CONF_HOST): str,
            vol.Required(CONF_LOGIN): str,
            vol.Required(CONF_PASSWORD): str,
            vol.Optional(CONF_MODE, default=DEFAULT_MODE): str,
            vol.Optional(CONF_SERIAL): str,
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
