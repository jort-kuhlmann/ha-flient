"""Constants for the Flient Smart Lock integration."""

DOMAIN = "flient"

API_BASE_URL = "https://api.flient.net/api"

SCAN_INTERVAL_SECONDS = 30  # Poll lock state every 30 seconds

# Config entry keys
CONF_ACCESS_TOKEN = "access_token"
CONF_REFRESH_TOKEN = "refresh_token"
CONF_USER_ID = "user_id"

# API endpoints (relative to API_BASE_URL).
ENDPOINT_LOGIN = "login"
ENDPOINT_REFRESH = "refreshToken"
ENDPOINT_SEND_OTP = "sendOTP"
ENDPOINT_LOCK_LIST = "getLockList"
ENDPOINT_LOCK_STATE = "getOpenStateLock"
ENDPOINT_GATEWAY_UNLOCK = "gatewayLockUnlock"
ENDPOINT_RECORDS = "getLockRecordList"
