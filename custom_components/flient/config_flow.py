"""Config flow for Flient Smart Lock."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import FlientApi, FlientApiError, FlientAuthError, FlientOtpRequired
from .const import (
    CONF_ACCESS_TOKEN,
    CONF_REFRESH_TOKEN,
    CONF_USER_ID,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_EMAIL): str,
        vol.Required(CONF_PASSWORD): str,
    }
)

STEP_OTP_DATA_SCHEMA = vol.Schema({vol.Required("otp"): str})


class FlientConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Flient."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize the flow."""
        self._email: str | None = None
        self._password: str | None = None

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial (email/password) step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            self._email = user_input[CONF_EMAIL]
            self._password = user_input[CONF_PASSWORD]
            return await self._attempt_login(errors)

        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors
        )

    async def async_step_otp(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the OTP (2FA) step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            return await self._attempt_login(errors, otp=user_input["otp"])

        return self.async_show_form(
            step_id="otp", data_schema=STEP_OTP_DATA_SCHEMA, errors=errors
        )

    async def _attempt_login(
        self, errors: dict[str, str], otp: str | None = None
    ) -> ConfigFlowResult:
        """Try to log in, routing to the OTP step if 2FA is required."""
        assert self._email is not None and self._password is not None
        session = async_get_clientsession(self.hass)
        api = FlientApi(session, self._email, self._password)

        try:
            await api.async_login(otp=otp)
        except FlientOtpRequired:
            return self.async_show_form(
                step_id="otp", data_schema=STEP_OTP_DATA_SCHEMA, errors=errors
            )
        except FlientAuthError:
            errors["base"] = "invalid_auth"
        except FlientApiError:
            errors["base"] = "cannot_connect"
        except Exception:  # noqa: BLE001
            _LOGGER.exception("Unexpected exception during Flient login")
            errors["base"] = "unknown"
        else:
            tokens = api.tokens
            user_id = tokens.get(CONF_USER_ID) or self._email
            await self.async_set_unique_id(str(user_id))
            self._abort_if_unique_id_configured()
            return self.async_create_entry(
                title="Flient Smart Lock",
                data={
                    CONF_EMAIL: self._email,
                    CONF_PASSWORD: self._password,
                    CONF_USER_ID: user_id,
                    CONF_ACCESS_TOKEN: tokens.get(CONF_ACCESS_TOKEN),
                    CONF_REFRESH_TOKEN: tokens.get(CONF_REFRESH_TOKEN),
                },
            )

        # On error, re-show the step we came from.
        if otp is not None:
            return self.async_show_form(
                step_id="otp", data_schema=STEP_OTP_DATA_SCHEMA, errors=errors
            )
        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors
        )
