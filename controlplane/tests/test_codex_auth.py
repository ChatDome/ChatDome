import asyncio
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
from chatdome.llm.codex_auth import CodexOAuth, NotAuthenticatedError


class CodexOAuthTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.token_file = Path(self.tmp_dir.name) / "auth.json"
        self.oauth = CodexOAuth(client_id="test_client", token_file=self.token_file)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_request_device_code_success(self):
        asyncio.run(self._run_request_device_code_success())

    @patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    async def _run_request_device_code_success(self, mock_post):
        mock_response = httpx.Response(
            200,
            json={
                "device_code": "dev_123",
                "user_code": "user_456",
                "verification_uri": "http://verify",
                "expires_in": 300,
                "interval": 5,
            },
        )
        mock_post.return_value = mock_response

        res = await self.oauth.request_device_code()

        self.assertEqual(res["device_code"], "dev_123")
        self.assertEqual(res["user_code"], "user_456")
        self.assertEqual(res["verification_uri"], "http://verify")
        mock_post.assert_called_once_with(
            self.oauth.DEVICE_CODE_URL,
            json={"client_id": "test_client"},
            headers={"Content-Type": "application/json"},
        )

    def test_poll_device_token_success(self):
        asyncio.run(self._run_poll_device_token_success())

    @patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    async def _run_poll_device_token_success(self, mock_post):
        # First call: authorization_pending
        resp_pending = httpx.Response(400, json={"error": "authorization_pending"})
        # Second call: success
        resp_success = httpx.Response(
            200,
            json={"code": "auth_code_999", "code_verifier": "verifier_888"},
        )
        mock_post.side_effect = [resp_pending, resp_success]

        # Use interval=0.01 to speed up test execution
        code, verifier = await self.oauth.poll_device_token(
            device_code="dev_123",
            interval=0,
            timeout=5,
        )

        self.assertEqual(code, "auth_code_999")
        self.assertEqual(verifier, "verifier_888")
        self.assertEqual(mock_post.call_count, 2)

    def test_poll_device_token_timeout(self):
        asyncio.run(self._run_poll_device_token_timeout())

    @patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    async def _run_poll_device_token_timeout(self, mock_post):
        resp_pending = httpx.Response(400, json={"error": "authorization_pending"})
        mock_post.return_value = resp_pending

        with self.assertRaises(TimeoutError):
            await self.oauth.poll_device_token(
                device_code="dev_123",
                interval=0,
                timeout=0.05,
            )

    def test_exchange_token_success(self):
        asyncio.run(self._run_exchange_token_success())

    @patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    async def _run_exchange_token_success(self, mock_post):
        mock_response = httpx.Response(
            200,
            json={
                "access_token": "acc_tok",
                "refresh_token": "ref_tok",
                "expires_in": 3600,
            },
        )
        mock_post.return_value = mock_response

        res = await self.oauth.exchange_token("auth_code", "verifier")

        self.assertEqual(res["access_token"], "acc_tok")
        self.assertEqual(res["refresh_token"], "ref_tok")
        self.assertTrue(self.token_file.is_file())

        # Verify saved content
        saved_data = json.loads(self.token_file.read_text(encoding="utf-8"))
        self.assertEqual(saved_data["access_token"], "acc_tok")
        self.assertEqual(saved_data["refresh_token"], "ref_tok")
        self.assertGreater(saved_data["expires_at"], time.time())

    def test_ensure_valid_token_no_refresh(self):
        asyncio.run(self._run_ensure_valid_token_no_refresh())

    async def _run_ensure_valid_token_no_refresh(self):
        # Pre-seed token file with a token valid for 1 hour
        token_data = {
            "access_token": "valid_tok",
            "refresh_token": "ref_tok",
            "expires_at": int(time.time() + 3600),
            "client_id": "test_client",
        }
        self.token_file.write_text(json.dumps(token_data), encoding="utf-8")

        # Calling ensure_valid_token should return the token without hitting the network
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            tok = await self.oauth.ensure_valid_token()
            self.assertEqual(tok, "valid_tok")
            mock_post.assert_not_called()

    def test_ensure_valid_token_requires_refresh(self):
        asyncio.run(self._run_ensure_valid_token_requires_refresh())

    @patch("httpx.AsyncClient.post", new_callable=AsyncMock)
    async def _run_ensure_valid_token_requires_refresh(self, mock_post):
        # Pre-seed token file with an expired token
        token_data = {
            "access_token": "expired_tok",
            "refresh_token": "ref_tok",
            "expires_at": int(time.time() - 10),
            "client_id": "test_client",
        }
        self.token_file.write_text(json.dumps(token_data), encoding="utf-8")

        mock_post.return_value = httpx.Response(
            200,
            json={
                "access_token": "new_tok",
                "refresh_token": "new_ref_tok",
                "expires_in": 3600,
            },
        )

        tok = await self.oauth.ensure_valid_token()

        self.assertEqual(tok, "new_tok")
        mock_post.assert_called_once()
        
        # Verify refreshed token saved to file
        saved_data = json.loads(self.token_file.read_text(encoding="utf-8"))
        self.assertEqual(saved_data["access_token"], "new_tok")
        self.assertEqual(saved_data["refresh_token"], "new_ref_tok")

    def test_ensure_valid_token_no_auth_raises_error(self):
        asyncio.run(self._run_ensure_valid_token_no_auth_raises_error())

    async def _run_ensure_valid_token_no_auth_raises_error(self):
        # File is empty/missing
        with self.assertRaises(NotAuthenticatedError):
            await self.oauth.ensure_valid_token()


if __name__ == "__main__":
    unittest.main()
