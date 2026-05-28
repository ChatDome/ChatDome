"""
Codex OAuth authentication client.

Implements the OAuth 2.0 Device Authorization Grant flow for OpenAI Codex backend,
including device code generation, auth polling, token exchange, persistence, and refresh.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# Default Client ID associated with Codex CLI
DEFAULT_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"


class NotAuthenticatedError(RuntimeError):
    """Raised when authentication is missing or has expired and cannot be refreshed."""
    pass


class CodexOAuth:
    """Manages OAuth 2.0 Device Code flow and token lifecycle for OpenAI Codex."""

    DEVICE_CODE_URL = "https://auth.openai.com/api/accounts/deviceauth/usercode"
    DEVICE_TOKEN_URL = "https://auth.openai.com/api/accounts/deviceauth/token"
    TOKEN_URL = "https://auth.openai.com/oauth/token"

    def __init__(
        self,
        client_id: str | None = None,
        token_file: str | Path | None = None,
    ) -> None:
        self.client_id = client_id or DEFAULT_CLIENT_ID
        
        if token_file:
            self.token_file = Path(token_file).expanduser().resolve()
        else:
            self.token_file = Path.home() / ".chatdome" / "auth.json"

    def _load_stored_token(self) -> dict[str, Any] | None:
        """Load token info from the secure storage file."""
        if not self.token_file.is_file():
            return None
        try:
            import json
            data = json.loads(self.token_file.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "access_token" in data:
                return data
        except Exception as e:
            logger.warning("Failed to load Codex token from %s: %s", self.token_file, e)
        return None

    def _save_token(self, token_data: dict[str, Any]) -> None:
        """Save token info to the secure storage file and set safe permissions."""
        import json
        try:
            self.token_file.parent.mkdir(parents=True, exist_ok=True)
            # Create file with restrictive permissions (write/read by owner only)
            # On POSIX this sets 0o600. On Windows, it handles standard file creation.
            if not self.token_file.exists():
                # Create empty file first
                self.token_file.touch()
                try:
                    os.chmod(self.token_file, 0o600)
                except OSError:
                    pass  # POSIX only, ignore on Windows
            
            self.token_file.write_text(
                json.dumps(token_data, indent=2, ensure_ascii=False),
                encoding="utf-8"
            )
            logger.info("Saved Codex token to %s", self.token_file)
        except Exception as e:
            logger.error("Failed to save Codex token to %s: %s", self.token_file, e)
            raise RuntimeError(f"Failed to persist authentication token: {e}") from e

    async def request_device_code(self) -> dict[str, Any]:
        """
        Request a new device code from OpenAI.
        
        Returns:
            A normalized dict containing device_code, user_code,
            verification_uri, interval (int), expires_in (int), etc.
        """
        payload = {
            "client_id": self.client_id,
            "scope": "openid profile email offline_access",
            "audience": "https://api.openai.com/v1",
        }
        headers = {"Content-Type": "application/json"}
        
        logger.debug("Requesting device code from OpenAI with client_id=%s", self.client_id)
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                resp = await client.post(self.DEVICE_CODE_URL, json=payload, headers=headers)
                if resp.status_code != 200:
                    logger.error("Failed to request device code: Status %d, Body %s", resp.status_code, resp.text)
                    raise RuntimeError(f"OpenAI Device Auth failed (HTTP {resp.status_code}): {resp.text}")
                
                data = resp.json()
                logger.info("Device code response keys: %s", list(data.keys()))
                
                # OpenAI uses custom field names; normalize to standard names.
                # device_auth_id -> device_code
                # expires_at (ISO str) -> expires_in (seconds int)
                # interval may be str -> int
                if "device_auth_id" in data and "device_code" not in data:
                    data["device_code"] = data["device_auth_id"]
                
                if "expires_at" in data and "expires_in" not in data:
                    try:
                        from datetime import datetime, timezone
                        exp = datetime.fromisoformat(data["expires_at"])
                        data["expires_in"] = max(int((exp - datetime.now(timezone.utc)).total_seconds()), 30)
                    except Exception:
                        data["expires_in"] = 300  # safe default
                
                if "interval" in data:
                    try:
                        data["interval"] = int(data["interval"])
                    except (ValueError, TypeError):
                        data["interval"] = 5
                
                if "verification_uri" not in data:
                    data["verification_uri"] = "https://auth.openai.com/authorize/device"
                
                # Final validation
                if "device_code" not in data:
                    logger.error("Device code response missing identifier. Full response: %s", data)
                    raise RuntimeError(
                        f"OpenAI Device Auth returned unexpected response (missing device identifier). "
                        f"Keys: {list(data.keys())}. Check your client_id."
                    )
                return data
            except httpx.HTTPError as e:
                logger.error("Network error requesting device code: %s", e)
                raise RuntimeError(f"Failed to connect to OpenAI Device Auth: {e}") from e

    async def poll_device_token(
        self,
        device_code: str,
        interval: int = 5,
        timeout: int = 300,
    ) -> tuple[str, str]:
        """
        Poll OpenAI's device token endpoint waiting for user authorization.
        
        Args:
            device_code: The code returned from request_device_code.
            interval: Polling frequency in seconds.
            timeout: Maximum polling duration in seconds.
            
        Returns:
            A tuple of (authorization_code, code_verifier) on success.
        """
        payload = {
            "client_id": self.client_id,
            "device_code": device_code,
            "device_auth_id": device_code,
        }
        headers = {"Content-Type": "application/json"}
        start_time = time.time()
        
        # Ensure interval is sensible
        interval = max(interval, 2)
        
        logger.debug("Starting OAuth device auth polling...")
        async with httpx.AsyncClient(timeout=10.0) as client:
            while time.time() - start_time < timeout:
                try:
                    resp = await client.post(self.DEVICE_TOKEN_URL, json=payload, headers=headers)
                    
                    if resp.status_code == 200:
                        data = resp.json()
                        code = data.get("code")
                        code_verifier = data.get("code_verifier")
                        if code and code_verifier:
                            logger.info("Device auth token polling success")
                            return code, code_verifier
                        raise ValueError(f"Unexpected successful response schema: {data}")
                        
                    elif resp.status_code == 400:
                        data = resp.json()
                        error_code = data.get("error")
                        if error_code == "authorization_pending":
                            # Still waiting for user, continue polling
                            logger.debug("Device auth poll: authorization_pending, retrying in %ds", interval)
                        elif error_code == "slow_down":
                            interval += 2
                            logger.warning("Received slow_down error, increasing polling interval to %ds", interval)
                        else:
                            raise RuntimeError(f"OAuth polling failed: {error_code} - {data.get('error_description')}")
                    else:
                        raise RuntimeError(f"Unexpected OAuth polling HTTP status: {resp.status_code}")
                        
                except httpx.HTTPError as e:
                    logger.warning("Network warning during token polling: %s", e)
                
                await asyncio.sleep(interval)
                
            raise TimeoutError("OpenAI OAuth Device Login timed out. Please run the command again.")

    async def exchange_token(self, code: str, code_verifier: str) -> dict[str, Any]:
        """
        Exchange the authorization code and verifier for access/refresh tokens.
        
        Returns:
            The parsed token data dictionary.
        """
        payload = {
            "client_id": self.client_id,
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": code_verifier,
            "redirect_uri": "https://auth.openai.com/oauth2/redirection",
        }
        headers = {"Content-Type": "application/json"}
        
        logger.debug("Exchanging OAuth authorization code for tokens")
        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                resp = await client.post(self.TOKEN_URL, json=payload, headers=headers)
                if resp.status_code != 200:
                    logger.error("OAuth token exchange failed: Status %d, Body %s", resp.status_code, resp.text)
                    raise RuntimeError(f"OAuth token exchange failed (HTTP {resp.status_code}): {resp.text}")
                
                data = resp.json()
                expires_in = int(data.get("expires_in", 3600))
                
                token_data = {
                    "access_token": data["access_token"],
                    "refresh_token": data.get("refresh_token", ""),
                    "expires_at": int(time.time() + expires_in),
                    "client_id": self.client_id,
                    "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }
                
                self._save_token(token_data)
                return token_data
            except httpx.HTTPError as e:
                raise RuntimeError(f"Failed to connect to OAuth Token endpoint during exchange: {e}") from e

    async def refresh_access_token(self, refresh_token: str) -> dict[str, Any]:
        """
        Refresh an expired access token using the refresh token.
        
        Returns:
            The newly updated token data dictionary.
        """
        payload = {
            "client_id": self.client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }
        headers = {"Content-Type": "application/json"}
        
        logger.info("Attempting to refresh Codex OAuth access token")
        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                resp = await client.post(self.TOKEN_URL, json=payload, headers=headers)
                if resp.status_code != 200:
                    logger.error("OAuth token refresh failed: Status %d, Body %s", resp.status_code, resp.text)
                    raise RuntimeError(f"OAuth token refresh failed (HTTP {resp.status_code}): {resp.text}")
                
                data = resp.json()
                expires_in = int(data.get("expires_in", 3600))
                
                token_data = {
                    "access_token": data["access_token"],
                    "refresh_token": data.get("refresh_token") or refresh_token,  # Fallback to old refresh token if new one is not sent
                    "expires_at": int(time.time() + expires_in),
                    "client_id": self.client_id,
                    "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }
                
                self._save_token(token_data)
                return token_data
            except httpx.HTTPError as e:
                raise RuntimeError(f"Failed to connect to OAuth Token endpoint during refresh: {e}") from e

    async def ensure_valid_token(self) -> str:
        """
        Get a valid access token. Performs automatic token refresh if expired.
        
        Returns:
            A valid access_token string.
            
        Raises:
            NotAuthenticatedError: if credentials are missing or refresh failed.
        """
        token = self._load_stored_token()
        if not token:
            raise NotAuthenticatedError("Codex is not authenticated. Please run /codex_login first.")
        
        # Buffer of 60 seconds before actual expiration time
        if time.time() >= token["expires_at"] - 60:
            refresh_token = token.get("refresh_token")
            if not refresh_token:
                raise NotAuthenticatedError("Codex token has expired, and no refresh token is available. Please re-authenticate using /codex_login.")
            try:
                token = await self.refresh_access_token(refresh_token)
            except Exception as e:
                logger.error("Failed to automatically refresh Codex access token: %s", e)
                raise NotAuthenticatedError(f"Codex token refresh failed. Please re-authenticate using /codex_login. Details: {e}") from e
                
        return token["access_token"]
