import asyncio
import unittest
from unittest.mock import patch

from chatdome.config import AIConfig
from chatdome.llm.manager import LLMManager, LLMProfileNotReady


class DummyClient:
    def __init__(self, model: str):
        self.model = model


class LLMManagerTests(unittest.TestCase):
    def test_openai_profile_missing_key_rejects_switch(self):
        profiles = {
            "codex": AIConfig(provider="codex", api_mode="codex_responses", model="gpt-5.5"),
            "openai": AIConfig(
                provider="openai",
                api_mode="openai_api",
                model="gpt-4o",
                api_key="",
            ),
        }
        manager = LLMManager(profiles, "codex")

        async def run():
            with self.assertRaises(LLMProfileNotReady):
                await manager.switch_profile("openai")

        asyncio.run(run())
        self.assertEqual(manager.get_active_profile_name(), "codex")

    def test_openai_profile_uses_direct_key_before_client_creation(self):
        profiles = {
            "openai": AIConfig(
                provider="openai",
                api_mode="openai_api",
                model="gpt-4o",
                api_key="secret-key",
            ),
        }
        manager = LLMManager(profiles, "openai")
        captured = {}

        def fake_create(profile):
            captured["api_key"] = profile.api_key
            return DummyClient(profile.model)

        async def run():
            with patch("chatdome.llm.manager.create_llm_client", side_effect=fake_create):
                snapshot = await manager.get_active_snapshot()
                self.assertEqual(snapshot.client.model, "gpt-4o")

        asyncio.run(run())
        self.assertEqual(captured["api_key"], "secret-key")
        self.assertEqual(manager.get_active_profile_name(), "openai")

    def test_codex_profile_missing_token_rejects_switch(self):
        profiles = {
            "openai": AIConfig(
                provider="openai",
                api_mode="openai_api",
                model="gpt-4o",
                api_key="secret-key",
            ),
            "codex": AIConfig(provider="codex", api_mode="codex_responses", model="gpt-5.5"),
        }
        manager = LLMManager(profiles, "openai")

        class FakeOAuth:
            def __init__(self, *args, **kwargs):
                pass

            async def ensure_valid_token(self):
                from chatdome.llm.codex_auth import NotAuthenticatedError

                raise NotAuthenticatedError("not authenticated")

        async def run():
            with patch("chatdome.llm.manager.CodexOAuth", FakeOAuth):
                with self.assertRaises(LLMProfileNotReady):
                    await manager.switch_profile("codex")

        asyncio.run(run())
        self.assertEqual(manager.get_active_profile_name(), "openai")

    def test_codex_profile_valid_token_can_switch(self):
        profiles = {
            "openai": AIConfig(
                provider="openai",
                api_mode="openai_api",
                model="gpt-4o",
                api_key="secret-key",
            ),
            "codex": AIConfig(provider="codex", api_mode="codex_responses", model="gpt-5.5"),
        }
        manager = LLMManager(profiles, "openai")

        class FakeOAuth:
            def __init__(self, *args, **kwargs):
                pass

            async def ensure_valid_token(self):
                return "token"

        def fake_create(profile):
            return DummyClient(profile.model)

        async def run():
            with patch("chatdome.llm.manager.CodexOAuth", FakeOAuth):
                with patch("chatdome.llm.manager.create_llm_client", side_effect=fake_create):
                    snapshot = await manager.switch_profile("codex")
                    self.assertEqual(snapshot.profile_name, "codex")

        asyncio.run(run())
        self.assertEqual(manager.get_active_profile_name(), "codex")

    def test_cached_client_is_reused(self):
        profiles = {
            "openai": AIConfig(
                provider="openai",
                api_mode="openai_api",
                model="gpt-4o",
                api_key="secret-key",
            ),
        }
        manager = LLMManager(profiles, "openai")
        calls = {"count": 0}

        def fake_create(profile):
            calls["count"] += 1
            return DummyClient(profile.model)

        async def run():
            with patch("chatdome.llm.manager.create_llm_client", side_effect=fake_create):
                first = await manager.get_active_snapshot()
                second = await manager.get_active_snapshot()
                self.assertIs(first.client, second.client)

        asyncio.run(run())
        self.assertEqual(calls["count"], 1)

    def test_reload_profiles_replaces_pool_and_clears_cached_clients(self):
        profiles = {
            "openai": AIConfig(
                provider="openai",
                api_mode="openai_api",
                model="gpt-4o",
                api_key="secret-key",
            ),
        }
        manager = LLMManager(profiles, "openai")
        calls = {"count": 0}

        def fake_create(profile):
            calls["count"] += 1
            return DummyClient(profile.model)

        async def run():
            with patch("chatdome.llm.manager.create_llm_client", side_effect=fake_create):
                first = await manager.get_active_snapshot()
                self.assertEqual(first.client.model, "gpt-4o")
                await manager.reload_profiles(
                    {
                        "new": AIConfig(
                            provider="openai",
                            api_mode="openai_api",
                            model="gpt-4.1",
                            api_key="new-key",
                        )
                    },
                    "new",
                )
                second = await manager.get_active_snapshot()
                self.assertEqual(second.client.model, "gpt-4.1")

        asyncio.run(run())
        self.assertEqual(calls["count"], 2)


if __name__ == "__main__":
    unittest.main()
