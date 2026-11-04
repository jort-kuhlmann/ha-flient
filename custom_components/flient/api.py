"""Flient API client for Home Assistant.

The Flient backend is a white-label of the TTLock/Sciener cloud, reached at
``https://api.flient.net/api`` (a Laravel app). Routes, field names and the
auth scheme were recovered by decompiling the Flient app (Flutter release AOT,
via Blutter) and verified against a live account:

- send OTP:           POST /sendOTP     {email_or_phone, password, type:"login"}
- login:              POST /login       {email_or_phone, password, otp}
- token refresh:      POST /refreshToken {user_id, refresh_token}  (+ bearer)
- list locks:         POST /getLockList  {user_id}
- lock state:         POST /getOpenStateLock {user_id, lock_id} -> data = state
- records:            POST /getLockRecordList {user_id, lock_id, page}
- lock/unlock (hub):  POST /gatewayLockUnlock {user_id, lock_id, type}
                      where type is "lock" | "unlock"

Auth notes (verified):
- The password is sent as its MD5 hex digest, not plaintext.
- Login returns many fields; the bearer for ``Authorization: Bearer`` is the
  ``token`` field (distinct from the ``access_token``/``refresh_token`` pair).
- Battery and lock_state come from /getLockList (battery_percentage,
  lock_state); there is no working per-lock battery endpoint.

Responses use a {ResponseCode, ResponseMsg, Result, data} envelope. Parsing
stays defensive (accepts field-name variants). Lock/unlock request shape is
confirmed from the decompile but not yet exercised against a physical lock.
"""
from __future__ import annotations

import hashlib
import logging
import time
from typing import Any

import aiohttp

from .const import (
    API_BASE_URL,
    ENDPOINT_GATEWAY_UNLOCK,
    ENDPOINT_LOCK_LIST,
    ENDPOINT_LOCK_STATE,
    ENDPOINT_LOGIN,
    ENDPOINT_RECORDS,
    ENDPOINT_REFRESH,
    ENDPOINT_SEND_OTP,
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
    """Return the data body of an envelope, tolerating casing variants.

    Must not use ``or {}`` here: ``getOpenStateLock`` returns ``data: 0`` for a
    LOCKED lock, and ``0`` is falsy, so ``or {}`` would discard a valid state.
    """
    value = _first(payload, "data", "Data", "Result")
    return value if value is not None else {}


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
        # The API authenticates with an MD5 hash of the password, not the
        # plaintext (confirmed against the live /sendOTP endpoint).
        self._password_hash = hashlib.md5(password.encode("utf-8")).hexdigest()
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
        enabled the first call (no otp) is rejected asking for the code; the
        caller must then trigger :meth:`async_send_otp` to have the server send
        it, and submit the code on a second call. Raises
        :class:`FlientOtpRequired` only when no otp was supplied.

        The identifier field ``email_or_phone`` and the ``otp`` field were
        confirmed from the decompiled app and the server's validation messages.
        """
        body: dict[str, Any] = {
            "email_or_phone": self._email,
            "password": self._password_hash,
        }
        if otp:
            body["otp"] = otp

        payload = await self._raw_request("POST", ENDPOINT_LOGIN, json=body, auth=False)

        if not _result_ok(payload):
            msg = _message(payload)
            # Only route to the OTP step when we haven't already supplied one;
            # otherwise a wrong/expired code (message often contains "otp") is a
            # genuine auth failure, not a prompt to re-enter.
            if otp is None and ("otp" in msg.lower() or "code" in msg.lower()):
                raise FlientOtpRequired(msg)
            raise FlientAuthError(msg)

        await self._store_tokens(_data(payload))
        if not self._access_token:
            raise FlientAuthError("Login succeeded but no access token was returned")
        return {"user_id": self._user_id}

    async def async_send_otp(self) -> None:
        """Ask the server to send a login OTP to the account.

        ``POST /sendOTP`` with ``{email_or_phone, password, type}`` and
        ``type="login"``. Field names and the required set were confirmed by
        probing the server's validation messages (type, then password, then
        email_or_phone). Best effort: a non-success envelope is logged, not
        raised, so the user can still enter a code (or retry) if delivery is
        merely delayed.
        """
        body = {
            "email_or_phone": self._email,
            "password": self._password_hash,
            "type": "login",
        }
        payload = await self._raw_request(
            "POST", ENDPOINT_SEND_OTP, json=body, auth=False
        )
        if not _result_ok(payload):
            _LOGGER.debug("sendOTP did not report success: %s", _message(payload))

    async def _store_tokens(self, data: dict[str, Any]) -> None:
        """Extract and persist tokens from a login/refresh data body.

        The bearer sent in ``Authorization: Bearer`` is the ``token`` field
        (the app's interceptor reads ``UserData.token``), which is distinct from
        the ``access_token``/``refresh_token`` pair also present in the response.
        """
        if not isinstance(data, dict):
            return
        self._access_token = _first(data, "token", "access_token", "accessToken") or self._access_token
        self._refresh_token = (
            _first(data, "refresh_token", "refreshToken") or self._refresh_token
        )
        self._user_id = _first(data, "user_id", "userId", "uid", "id") or self._user_id

        # Token expiry: the login body carries token_expiry/token_expiry_datetime
        # in an unconfirmed unit, so we don't trust it for proactive refresh.
        # Refresh happens reactively when a call returns 401/403/433.
        self._expires_at = 0.0

        if self._token_updated_cb is not None:
            await self._token_updated_cb(self._access_token, self._refresh_token)

    async def _async_refresh(self) -> bool:
        """Try to refresh the bearer token. Returns True on success.

        ``POST /refreshToken`` with ``{user_id, refresh_token}`` returns a new
        ``token`` in the same envelope as login.
        """
        if not self._refresh_token:
            return False
        try:
            payload = await self._raw_request(
                "POST",
                ENDPOINT_REFRESH,
                json={
                    "user_id": self._user_id,
                    "refresh_token": self._refresh_token,
                },
                auth=True,  # the refresh call carries the (expired) bearer too
            )
        except FlientApiError:
            return False
        if not _result_ok(payload):
            return False
        await self._store_tokens(_data(payload))
        return bool(self._access_token)

    async def _ensure_token(self) -> None:
        """Ensure we have a bearer token, refreshing if we only have a refresh token."""
        if self._access_token:
            return
        if self._refresh_token and await self._async_refresh():
            return
        # No usable token: a fresh login is required. With 2FA this cannot be
        # done silently, so surface it as an auth error and let Home Assistant
        # trigger the reauth flow.
        raise FlientAuthError("Not authenticated; reauthentication required")

    # --------------------------------------------------------------- queries

    async def get_locks(self) -> list[dict[str, Any]]:
        """Return all locks, normalized to the integration's field names."""
        payload = await self._request(
            "POST", ENDPOINT_LOCK_LIST, data={"user_id": self._user_id}
        )
        if not _result_ok(payload):
            raise FlientApiError(_message(payload))
        body = _data(payload)
        # The list may be the data body itself or nested under "list"/"locks".
        raw_list = body
        if isinstance(body, dict):
            raw_list = _first(body, "list", "locks", "data") or []
        return [self._normalize_lock(item) for item in raw_list or []]

    async def get_lock_state(self, lock_id: int) -> dict[str, Any]:
        """Return the current open/closed state for a single lock.

        ``POST /getOpenStateLock`` with ``{user_id, lock_id}`` returns the state
        directly in the ``data`` field as an int (0 locked / 1 unlocked /
        2 unknown). Battery is not returned here; it comes from the lock list.
        """
        result: dict[str, Any] = {}
        payload = await self._request(
            "POST",
            ENDPOINT_LOCK_STATE,
            data={"user_id": self._user_id, "lock_id": lock_id},
        )
        if _result_ok(payload):
            body = _data(payload)
            # data is the state int itself; tolerate a wrapped {state: ...} too.
            state = _first(body, "state", "lockState") if isinstance(body, dict) else body
            if state is not None:
                try:
                    result["state"] = int(state)
                except (TypeError, ValueError):
                    pass
        return result

    async def get_events(self, lock_id: int, page: int = 1) -> list[dict[str, Any]]:
        """Return recent lock records for a lock.

        ``POST /getLockRecordList`` with ``{user_id, lock_id, page}``. Returns []
        on any problem rather than raising, since events are a best-effort
        enhancement (the coordinator polls state directly for lock status).
        """
        try:
            payload = await self._request(
                "POST",
                ENDPOINT_RECORDS,
                data={"user_id": self._user_id, "lock_id": lock_id, "page": page},
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
        return await self._lock_action(lock_id, "lock")

    async def unlock(self, lock_id: int) -> bool:
        """Unlock via the gateway (cloud) path."""
        return await self._lock_action(lock_id, "unlock")

    async def _lock_action(self, lock_id: int, action: str) -> bool:
        """Lock or unlock a lock through its gateway.

        ``POST /gatewayLockUnlock`` with ``{user_id, lock_id, type}`` where
        ``type`` is the string ``"lock"`` or ``"unlock"``. The app sends this as
        multipart form data; the Laravel backend also reads JSON, so we send
        JSON for consistency with the other calls.
        """
        body = {
            "user_id": self._user_id,
            "lock_id": lock_id,
            "type": action,
        }
        payload = await self._request("POST", ENDPOINT_GATEWAY_UNLOCK, data=body)
        if not _result_ok(payload):
            _LOGGER.error(
                "Gateway %s failed for lock %s: %s",
                action,
                lock_id,
                _message(payload),
            )
            return False
        return True

    # -------------------------------------------------------------- internals

    @staticmethod
    def _normalize_lock(item: dict[str, Any]) -> dict[str, Any]:
        """Map the API's lock fields onto the names the integration expects.

        Confirmed fields from /getLockList: lock_id, lock_name, lock_type,
        lock_state, battery_percentage, mac_or_id (all values are strings).
        """
        if not isinstance(item, dict):
            return {}

        def as_int(value: Any) -> Any:
            try:
                return int(value)
            except (TypeError, ValueError):
                return value

        return {
            "lock_id": as_int(_first(item, "lock_id", "lockId", "id")),
            "lock_name": _first(item, "lock_name", "lockAlias", "lockName", "name"),
            "lock_model": _first(item, "lock_type", "lock_variant", "lockModel"),
            "state": as_int(_first(item, "lock_state", "state", "lockState")),
            "battery_level": as_int(
                _first(item, "battery_percentage", "electricQuantity", "battery_level")
            ),
            "mac": _first(item, "mac_or_id", "lockMac"),
            "door_state": _first(item, "door_state"),
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
