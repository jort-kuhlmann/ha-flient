"""Flient API client for Home Assistant.

The Flient backend is a white-label of the TTLock/Sciener cloud, reached at
``https://api.flient.net/api``. The route names and field names used here were
reverse-engineered from the Flient mobile app (a Flutter release build, so only
the string table was available) plus live probing of the server.

IMPORTANT: the exact success envelope, the login/OTP flow and the lock/unlock
request parameters are ASSUMPTIONS and have not been verified against a real
authenticated session. Each assumption is marked with ``ASSUMPTION:`` below.
The parsing is written defensively (it accepts several field-name variants) so
that small differences degrade gracefully, but a traffic capture of a real
login + unlock is still needed to confirm this works end to end.
"""
from __future__ import annotations

import logging
import time
from typing import Any

import aiohttp

from .const import (
    API_BASE_URL,
    ENDPOINT_BATTERY,
    ENDPOINT_GATEWAY_UNLOCK,
    ENDPOINT_LOCK_LIST,
    ENDPOINT_LOCK_STATE,
    ENDPOINT_LOGIN,
    ENDPOINT_RECORDS,
    ENDPOINT_REFRESH,
)

_LOGGER = logging.getLogger(__name__)

# TTLock lock state convention: 0 = locked, 1 = unlocked, 2 = unknown.
STATE_LOCKED = 0
STATE_UNLOCKED = 1
STATE_UNKNOWN = 2


class FlientApiError(Exception):
    """Flient API error."""


class FlientAuthError(FlientApiError):
    """Flient authentication error (credentials invalid or token unrecoverable)."""


class FlientOtpRequired(FlientAuthError):
    """The login requires a one-time passcode (2FA)."""


def _first(data: dict[str, Any], *keys: str) -> Any:
    """Return the first present, non-None value among ``keys``."""
    for key in keys:
        if key in data and data[key] is not None:
            return data[key]
    return None


def _result_ok(payload: dict[str, Any]) -> bool:
    """Decide whether an API envelope represents success.

    ASSUMPTION: the server wraps responses as
    ``{"ResponseCode": <int>, "ResponseMsg": <str>, "Result": "True"/"False"}``.
    Observed failures use ``Result: "False"`` with codes 0/401/433. We treat a
    truthy ``Result`` (or an explicit 200 code) as success and also accept the
    lowercase ``status``/``result`` variants seen in the string table.
    """
    result = _first(payload, "Result", "result")
    if isinstance(result, str):
        return result.strip().lower() == "true"
    if isinstance(result, bool):
        return result
    code = _first(payload, "ResponseCode", "status")
    return code in (200, 1)


def _message(payload: dict[str, Any]) -> str:
    return str(
        _first(payload, "ResponseMsg", "Message", "message") or "Unknown error"
    )


def _data(payload: dict[str, Any]) -> Any:
    """Return the data body of an envelope, tolerating casing variants."""
    return _first(payload, "data", "Data", "Result") or {}


# Keys whose values must never reach the log (credentials/tokens/OTP).
_SENSITIVE_KEYS = frozenset(
    {
        "password",
        "access_token",
        "accesstoken",
        "refresh_token",
        "refreshtoken",
        "token",
        "authorization",
        "otp",
        "otpcode",
        "verifycode",
        "verificationcode",
    }
)


def _redact(value: Any) -> Any:
    """Recursively copy a JSON-ish structure, masking sensitive values."""
    if isinstance(value, dict):
        return {
            key: ("***" if key.lower() in _SENSITIVE_KEYS else _redact(val))
            for key, val in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


class FlientApi:
    """Client for the Flient (TTLock white-label) API."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        email: str,
        password: str,
        user_id: int | str | None = None,
        access_token: str | None = None,
        refresh_token: str | None = None,
        token_updated_cb: Any | None = None,
    ) -> None:
        """Initialize the API client.

        ``token_updated_cb`` is an optional async callable invoked with
        ``(access_token, refresh_token)`` whenever new tokens are obtained, so
        the caller can persist them to the config entry.
        """
        self._session = session
        self._email = email
        self._password = password
        self._user_id = user_id
        self._access_token = access_token
        self._refresh_token = refresh_token
        self._expires_at: float = 0.0  # epoch seconds; 0 = unknown
        self._token_updated_cb = token_updated_cb

    @property
    def tokens(self) -> dict[str, Any]:
        """Return the current tokens/user id for persistence by the caller."""
        return {
            "access_token": self._access_token,
            "refresh_token": self._refresh_token,
            "user_id": self._user_id,
        }

    # ------------------------------------------------------------------ auth

    async def async_login(self, otp: str | None = None) -> dict[str, Any]:
        """Perform a full email/password (optionally + OTP) login.

        ``POST /login`` with ``{email_or_phone, password, otp?}``. When 2FA is
        enabled the first call (no otp) responds with "Please enter otp" and the
        server emails/texts a code; the code is then submitted on a second call.
        Raises :class:`FlientOtpRequired` in that case.

        The identifier field name ``email_or_phone`` and the ``otp`` field name
        were confirmed by probing the server's validation messages.
        """
        body: dict[str, Any] = {
            "email_or_phone": self._email,
            "password": self._password,
        }
        if otp:
            body["otp"] = otp

        payload = await self._raw_request("POST", ENDPOINT_LOGIN, json=body, auth=False)

        if not _result_ok(payload):
            msg = _message(payload)
            if "otp" in msg.lower() or "code" in msg.lower():
                raise FlientOtpRequired(msg)
            raise FlientAuthError(msg)

        await self._store_tokens(_data(payload))
        if not self._access_token:
            raise FlientAuthError("Login succeeded but no access token was returned")
        return {"user_id": self._user_id}

    async def _store_tokens(self, data: dict[str, Any]) -> None:
        """Extract and persist tokens from a login/refresh data body."""
        if not isinstance(data, dict):
            return
        self._access_token = _first(data, "access_token", "accessToken") or self._access_token
        self._refresh_token = (
            _first(data, "refresh_token", "refreshToken") or self._refresh_token
        )
        self._user_id = _first(data, "user_id", "userId", "uid") or self._user_id

        # ASSUMPTION: an expiry hint may come back as seconds-to-live
        # (expires_in) or an absolute timestamp (Expire/expireTime). Unknown
        # TTL is left at 0, in which case we refresh reactively on 401/433.
        ttl = _first(data, "expires_in", "expiresIn")
        if ttl:
            try:
                self._expires_at = time.time() + int(ttl)
            except (TypeError, ValueError):
                self._expires_at = 0.0

        if self._token_updated_cb is not None:
            await self._token_updated_cb(self._access_token, self._refresh_token)

    async def _async_refresh(self) -> bool:
        """Try to refresh the access token. Returns True on success.

        ASSUMPTION: ``POST /refreshToken`` with ``{refresh_token}`` returns a
        new token in the same envelope as login.
        """
        if not self._refresh_token:
            return False
        try:
            payload = await self._raw_request(
                "POST",
                ENDPOINT_REFRESH,
                json={
                    "refresh_token": self._refresh_token,
                    "refreshToken": self._refresh_token,
                },
                auth=False,
            )
        except FlientApiError:
            return False
        if not _result_ok(payload):
            return False
        await self._store_tokens(_data(payload))
        return bool(self._access_token)

    async def _ensure_token(self) -> None:
        """Ensure we have a (probably) valid access token."""
        if self._access_token and (
            self._expires_at == 0.0 or time.time() < self._expires_at - 30
        ):
            return
        if self._access_token and self._expires_at and await self._async_refresh():
            return
        # No token at all, or refresh failed: a fresh login is required. With
        # 2FA this cannot be done silently, so surface it as an auth error and
        # let Home Assistant trigger the reauth flow.
        if not self._access_token:
            raise FlientAuthError("Not authenticated; reauthentication required")

    # --------------------------------------------------------------- queries

    async def get_locks(self) -> list[dict[str, Any]]:
        """Return all locks, normalized to the integration's field names."""
        payload = await self._request("POST", ENDPOINT_LOCK_LIST, data={})
        if not _result_ok(payload):
            raise FlientApiError(_message(payload))
        body = _data(payload)
        # ASSUMPTION: the list may be the data body itself or nested under
        # "list"/"locks".
        raw_list = body
        if isinstance(body, dict):
            raw_list = _first(body, "list", "locks", "data") or []
        return [self._normalize_lock(item) for item in raw_list or []]

    async def get_lock_state(self, lock_id: int) -> dict[str, Any]:
        """Return normalized state + battery for a single lock."""
        result: dict[str, Any] = {}
        payload = await self._request(
            "POST", ENDPOINT_LOCK_STATE, data={"lockId": lock_id}
        )
        if _result_ok(payload):
            body = _data(payload)
            state = _first(body, "state", "lockState") if isinstance(body, dict) else body
            if state is not None:
                try:
                    result["state"] = int(state)
                except (TypeError, ValueError):
                    pass

        battery = await self._get_battery(lock_id)
        if battery is not None:
            result["battery_level"] = battery
        return result

    async def _get_battery(self, lock_id: int) -> int | None:
        """Return battery percentage for a lock, or None."""
        try:
            payload = await self._request(
                "POST", ENDPOINT_BATTERY, data={"lockId": lock_id}
            )
        except FlientApiError:
            return None
        if not _result_ok(payload):
            return None
        body = _data(payload)
        value = (
            _first(body, "electricQuantity", "battery_level", "battery")
            if isinstance(body, dict)
            else body
        )
        try:
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    async def get_events(self, since: int = 60) -> list[dict[str, Any]]:
        """Return recent lock records.

        ASSUMPTION: ``POST /getLockRecordList``. The parameters for time
        filtering are unknown, so we fetch the latest page and let the
        coordinator diff. Returns [] on any problem rather than raising, since
        events are a best-effort enhancement.
        """
        try:
            payload = await self._request(
                "POST", ENDPOINT_RECORDS, data={"pageNo": 1, "pageSize": 20}
            )
        except FlientApiError:
            return []
        if not _result_ok(payload):
            return []
        body = _data(payload)
        records = body
        if isinstance(body, dict):
            records = _first(body, "list", "records", "data") or []
        return list(records or [])

    # ---------------------------------------------------------------- actions

    async def lock(self, lock_id: int) -> bool:
        """Lock via the gateway (cloud) path."""
        return await self._lock_action(lock_id, STATE_LOCKED)

    async def unlock(self, lock_id: int) -> bool:
        """Unlock via the gateway (cloud) path."""
        return await self._lock_action(lock_id, STATE_UNLOCKED)

    async def _lock_action(self, lock_id: int, target_state: int) -> bool:
        """Lock or unlock a lock through its gateway.

        ASSUMPTION: ``POST /gatewayLockUnlock`` with ``{lockId, action}`` where
        action is 0 (lock) / 1 (unlock), matching the TTLock state convention.
        Alternatives the app references: a ``type`` field, or a separate
        ``lockUnlock`` route. Sent redundantly to improve the odds.
        """
        body = {
            "lockId": lock_id,
            "action": target_state,
            "type": target_state,
        }
        payload = await self._request("POST", ENDPOINT_GATEWAY_UNLOCK, data=body)
        if not _result_ok(payload):
            _LOGGER.error(
                "Gateway %s failed for lock %s: %s",
                "unlock" if target_state == STATE_UNLOCKED else "lock",
                lock_id,
                _message(payload),
            )
            return False
        return True

    # -------------------------------------------------------------- internals

    @staticmethod
    def _normalize_lock(item: dict[str, Any]) -> dict[str, Any]:
        """Map TTLock-style fields onto the names the integration expects."""
        if not isinstance(item, dict):
            return {}
        return {
            "lock_id": _first(item, "lockId", "lock_id", "id"),
            "lock_name": _first(item, "lockAlias", "lockName", "lock_name", "name"),
            "lock_model": _first(item, "lockModel", "modelNum", "lock_model"),
            "state": _first(item, "state", "lockState"),
            "battery_level": _first(item, "electricQuantity", "battery_level"),
            "auto_lock_time": _first(item, "autoLockTime", "auto_lock_time"),
            "gateway_id": _first(item, "gatewayId", "gateway_id"),
            "_raw": item,
        }

    async def _request(
        self, method: str, endpoint: str, data: dict | None = None
    ) -> dict[str, Any]:
        """Authenticated request with one refresh/retry on 401/433."""
        await self._ensure_token()
        try:
            return await self._raw_request(method, endpoint, json=data, auth=True)
        except FlientAuthError:
            # Token may have expired mid-use: try one refresh, then retry.
            if await self._async_refresh():
                return await self._raw_request(method, endpoint, json=data, auth=True)
            raise

    async def _raw_request(
        self,
        method: str,
        endpoint: str,
        json: dict | None = None,
        auth: bool = True,
    ) -> dict[str, Any]:
        """Perform a single HTTP request and return the parsed JSON envelope."""
        url = f"{API_BASE_URL}/{endpoint}"
        headers = {"Accept": "application/json"}
        if auth and self._access_token:
            headers["Authorization"] = f"Bearer {self._access_token}"

        if _LOGGER.isEnabledFor(logging.DEBUG):
            _LOGGER.debug(
                "Flient request %s %s body=%s auth=%s",
                method,
                endpoint,
                _redact(json) if json else None,
                auth and bool(self._access_token),
            )

        try:
            async with self._session.request(
                method,
                url,
                headers=headers,
                json=json if method == "POST" else None,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                status = resp.status
                try:
                    payload = await resp.json(content_type=None)
                except (ValueError, aiohttp.ContentTypeError) as err:
                    text = await resp.text()
                    raise FlientApiError(
                        f"Non-JSON response (HTTP {status}): {text[:200]}"
                    ) from err
        except aiohttp.ClientError as err:
            raise FlientApiError(f"API request failed: {err}") from err

        if _LOGGER.isEnabledFor(logging.DEBUG):
            _LOGGER.debug(
                "Flient response %s %s -> HTTP %s body=%s",
                method,
                endpoint,
                status,
                _redact(payload) if isinstance(payload, (dict, list)) else payload,
            )

        if status in (401, 403):
            raise FlientAuthError("Authentication expired")

        if not isinstance(payload, dict):
            raise FlientApiError(f"Unexpected response: {payload!r}")

        # ASSUMPTION: 433 is the backend's own "not authenticated" code.
        if _first(payload, "ResponseCode", "status") in (401, 403, 433):
            raise FlientAuthError(_message(payload))
        return payload
