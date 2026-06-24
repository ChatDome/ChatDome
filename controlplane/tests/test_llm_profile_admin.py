import asyncio
import os
import stat
import tempfile
import unittest
from pathlib import Path

import yaml

from chatdome.errors import (
    LLMProfileChanged,
    LLMProfileConflict,
    LLMProfileDeleteForbidden,
)
from chatdome.llm.profile_admin import (
    CreateCodexProfileRequest,
    CreateOpenAIProfileRequest,
    LLMProfileAdminService,
    ProfileActor,
    ProfileConfigStore,
)


class LLMProfileAdminTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config_path = self.root / "config.yaml"
        self.lock_path = self.root / "llm-profile.lock"
        self.config_path.write_text(
            yaml.safe_dump(
                {
                    "chatdome": {
                        "active_ai_profile": "base",
                        "ai_profiles": {
                            "base": {
                                "provider": "openai",
                                "api_mode": "openai_api",
                                "base_url": "https://api.openai.com/v1",
                                "model": "gpt-4o",
                                "api_key": "sk-base",
                            }
                        },
                    }
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        self.applied = []
        self.events = []

        async def runtime_apply(config, action):
            self.applied.append((config.active_ai_profile, action, sorted(config.ai_profiles)))

        def audit(event_type, actor, fields):
            self.events.append((event_type, actor, fields))

        self.store = ProfileConfigStore(self.config_path, self.lock_path)
        self.service = LLMProfileAdminService(
            self.store,
            runtime_apply=runtime_apply,
            audit_recorder=audit,
        )
        self.actor = ProfileActor(source="test", chat_id=1, user_id=2)

    def tearDown(self):
        self.tmp.cleanup()

    def run_async(self, awaitable):
        return asyncio.run(awaitable)

    def load_root(self):
        return yaml.safe_load(self.config_path.read_text(encoding="utf-8"))["chatdome"]

    def test_create_openai_without_telegram_token(self):
        result = self.run_async(
            self.service.create_openai(
                CreateOpenAIProfileRequest(
                    name="new",
                    model="new-model",
                    base_url="https://example.com/v1",
                    api_key="sk-new",
                ),
                self.actor,
            )
        )

        self.assertEqual(result.action, "created")
        self.assertEqual(self.load_root()["ai_profiles"]["new"]["api_key"], "sk-new")
        self.assertEqual(self.applied[-1][1], "created")
        self.assertEqual(self.events[-1][0], "llm_profile_created")
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(self.config_path.stat().st_mode), 0o600)

    def test_overwrite_requires_flag_and_matching_fingerprint(self):
        with self.assertRaises(LLMProfileConflict):
            self.run_async(
                self.service.create_openai(
                    CreateOpenAIProfileRequest(
                        name="base",
                        model="changed",
                        base_url="https://example.com/v1",
                        api_key="sk-new",
                    ),
                    self.actor,
                )
            )

        summary = self.run_async(self.service.get_profile_summary("base"))
        with self.assertRaises(LLMProfileChanged):
            self.run_async(
                self.service.create_openai(
                    CreateOpenAIProfileRequest(
                        name="base",
                        model="changed",
                        base_url="https://example.com/v1",
                        api_key="sk-new",
                        overwrite_existing=True,
                        expected_profile_fingerprint="stale",
                    ),
                    self.actor,
                )
            )

        result = self.run_async(
            self.service.create_openai(
                CreateOpenAIProfileRequest(
                    name="base",
                    model="changed",
                    base_url="https://example.com/v1",
                    api_key="",
                    overwrite_existing=True,
                    expected_profile_fingerprint=summary.fingerprint,
                ),
                self.actor,
            )
        )

        profile = self.load_root()["ai_profiles"]["base"]
        self.assertEqual(result.action, "updated")
        self.assertEqual(profile["model"], "changed")
        self.assertEqual(profile["api_key"], "sk-base")

    def test_overwrite_different_type_removes_old_fields(self):
        token_file = self.root / "codex.json"
        token_file.write_text("{}", encoding="utf-8")
        summary = self.run_async(self.service.get_profile_summary("base"))

        self.run_async(
            self.service.create_codex(
                CreateCodexProfileRequest(
                    name="base",
                    model="gpt-5.5",
                    client_id="",
                    token_file=str(token_file),
                    base_url="https://chatgpt.com/backend-api/codex",
                    overwrite_existing=True,
                    expected_profile_fingerprint=summary.fingerprint,
                ),
                self.actor,
            )
        )

        profile = self.load_root()["ai_profiles"]["base"]
        self.assertEqual(profile["api_mode"], "codex_responses")
        self.assertNotIn("api_key", profile)
        self.assertNotIn("base_url", profile)

    def test_delete_and_switch_rules(self):
        self.run_async(
            self.service.create_openai(
                CreateOpenAIProfileRequest(
                    name="second",
                    model="gpt-4o-mini",
                    base_url="https://api.openai.com/v1",
                    api_key="sk-second",
                ),
                self.actor,
            )
        )
        with self.assertRaises(LLMProfileDeleteForbidden):
            self.run_async(self.service.delete_profile("base", self.actor))

        switched = self.run_async(self.service.set_active_profile("second", self.actor))
        self.assertEqual(switched.active_profile, "second")
        deleted = self.run_async(self.service.delete_profile("base", self.actor))
        self.assertEqual(deleted.action, "deleted")
        with self.assertRaises(LLMProfileDeleteForbidden):
            self.run_async(self.service.delete_profile("second", self.actor))

    def test_runtime_failure_restores_previous_document(self):
        before = self.config_path.read_text(encoding="utf-8")

        async def fail_runtime(config, action):
            raise RuntimeError("reload failed")

        service = LLMProfileAdminService(
            self.store,
            runtime_apply=fail_runtime,
            audit_recorder=lambda *args: None,
        )
        with self.assertRaisesRegex(RuntimeError, "reload failed"):
            self.run_async(
                service.create_openai(
                    CreateOpenAIProfileRequest(
                        name="broken",
                        model="gpt-4o",
                        base_url="https://api.openai.com/v1",
                        api_key="sk-broken",
                    ),
                    self.actor,
                )
            )

        self.assertEqual(
            yaml.safe_load(self.config_path.read_text(encoding="utf-8")),
            yaml.safe_load(before),
        )


    def test_concurrent_creates_are_serialized(self):
        async def create(name):
            return await self.service.create_openai(
                CreateOpenAIProfileRequest(
                    name=name,
                    model="gpt-4o",
                    base_url="https://api.openai.com/v1",
                    api_key=f"sk-{name}",
                ),
                self.actor,
            )

        async def run_both():
            await asyncio.gather(create("one"), create("two"))

        self.run_async(run_both())

        profiles = self.load_root()["ai_profiles"]
        self.assertIn("one", profiles)
        self.assertIn("two", profiles)

    def test_switch_rejects_profile_without_authentication(self):
        document = yaml.safe_load(self.config_path.read_text(encoding="utf-8"))
        document["chatdome"]["ai_profiles"]["empty"] = {
            "provider": "openai",
            "api_mode": "openai_api",
            "model": "gpt-4o",
            "api_key": "",
        }
        self.config_path.write_text(
            yaml.safe_dump(document, sort_keys=False),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(Exception, "missing api_key"):
            self.run_async(self.service.set_active_profile("empty", self.actor))


if __name__ == "__main__":
    unittest.main()
