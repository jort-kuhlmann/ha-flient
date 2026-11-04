"""Data coordinator for Flient Smart Lock."""
from __future__ import annotations

from datetime import timedelta
import logging
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import FlientApi, FlientApiError, FlientAuthError
from .const import DOMAIN, SCAN_INTERVAL_SECONDS

_LOGGER = logging.getLogger(__name__)


class FlientCoordinator(DataUpdateCoordinator[dict[int, dict[str, Any]]]):
    """Coordinator to manage fetching Flient lock data."""

    def __init__(self, hass: HomeAssistant, api: FlientApi) -> None:
        """Initialize the coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=SCAN_INTERVAL_SECONDS),
        )
        self.api = api
        self._locks_loaded = False

    async def _async_update_data(self) -> dict[int, dict[str, Any]]:
        """Refresh all locks each cycle (state + battery come from getLockList)."""
        try:
            # getLockList returns lock_state and battery_percentage for every
            # lock in one call, so refresh the whole set each cycle.
            data: dict[int, dict[str, Any]] = {}
            for lock in await self.api.get_locks():
                lock_id = lock.get("lock_id")
                if lock_id is None:
                    continue
                data[lock_id] = lock
            self._locks_loaded = True
            return data

        except FlientAuthError as err:
            # Token unrecoverable (e.g. 2FA re-login needed): trigger HA reauth.
            raise ConfigEntryAuthFailed(str(err)) from err
        except FlientApiError as err:
            raise UpdateFailed(f"Error communicating with Flient API: {err}") from err

    async def async_refresh_lock_state(self, lock_id: int) -> dict[str, Any]:
        """Fetch state for a single lock on demand."""
        try:
            state = await self.api.get_lock_state(lock_id)
            if self.data and lock_id in self.data:
                self.data[lock_id].update(state)
            return state
        except FlientApiError as err:
            _LOGGER.warning("Failed to get state for lock %s: %s", lock_id, err)
            return {}
