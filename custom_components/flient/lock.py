"""Lock platform for Flient Smart Lock."""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from homeassistant.components.lock import LockEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import FlientCoordinator

_LOGGER = logging.getLogger(__name__)

# State convention: 0 = locked, 1 = unlocked, 2 = unknown.
STATE_LOCKED = 0
STATE_UNLOCKED = 1

# Seconds to wait after a command before confirming the real state (the hub
# relays the command to the lock over the air, which takes a moment).
_CONFIRM_DELAY = 3


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Flient locks from a config entry."""
    coordinator: FlientCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(
        FlientLock(coordinator, lock_id, lock_data)
        for lock_id, lock_data in coordinator.data.items()
    )


class FlientLock(CoordinatorEntity[FlientCoordinator], LockEntity):
    """Representation of a Flient Smart Lock."""

    _attr_has_entity_name = True
    _attr_name = None  # the device name is the lock name

    def __init__(
        self,
        coordinator: FlientCoordinator,
        lock_id: int,
        lock_data: dict[str, Any],
    ) -> None:
        """Initialize the lock."""
        super().__init__(coordinator)
        self._lock_id = lock_id
        self._attr_unique_id = f"flient_lock_{lock_id}"
        self._attr_is_locking = False
        self._attr_is_unlocking = False

    @property
    def device_info(self) -> dict[str, Any]:
        """Return device info."""
        lock_data = self.coordinator.data.get(self._lock_id, {})
        return {
            "identifiers": {(DOMAIN, str(self._lock_id))},
            "name": lock_data.get("lock_name", f"Flient Lock {self._lock_id}"),
            "manufacturer": "Flient",
            "model": lock_data.get("lock_model", "Smart Lock"),
        }

    @property
    def is_locked(self) -> bool | None:
        """Return true if locked, false if unlocked, None if unknown."""
        state = self.coordinator.data.get(self._lock_id, {}).get("state")
        if state == STATE_LOCKED:
            return True
        if state == STATE_UNLOCKED:
            return False
        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes."""
        lock_data = self.coordinator.data.get(self._lock_id, {})
        attrs: dict[str, Any] = {}
        if (mac := lock_data.get("mac")) is not None:
            attrs["mac"] = mac
        if (door := lock_data.get("door_state")) is not None:
            attrs["door_state"] = door
        return attrs

    async def async_lock(self, **kwargs: Any) -> None:
        """Lock the device."""
        await self._run_action(STATE_LOCKED)

    async def async_unlock(self, **kwargs: Any) -> None:
        """Unlock the device."""
        await self._run_action(STATE_UNLOCKED)

    async def _run_action(self, target: int) -> None:
        """Send a lock/unlock command, update optimistically, then confirm."""
        self._attr_is_locking = target == STATE_LOCKED
        self._attr_is_unlocking = target == STATE_UNLOCKED
        self.async_write_ha_state()

        try:
            if target == STATE_LOCKED:
                ok = await self.coordinator.api.lock(self._lock_id)
            else:
                ok = await self.coordinator.api.unlock(self._lock_id)
        finally:
            self._attr_is_locking = False
            self._attr_is_unlocking = False

        if ok and self._lock_id in self.coordinator.data:
            # Optimistic: reflect the requested state immediately in the UI.
            self.coordinator.data[self._lock_id]["state"] = target
        self.async_write_ha_state()

        if ok:
            # Confirm the real state shortly after (getOpenStateLock is live).
            self.hass.async_create_task(self._confirm_state())

    async def _confirm_state(self) -> None:
        """Re-read the real lock state after the hub has acted."""
        await asyncio.sleep(_CONFIRM_DELAY)
        await self.coordinator.async_refresh_lock_state(self._lock_id)
        self.async_write_ha_state()

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        self.async_write_ha_state()
