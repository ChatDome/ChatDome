import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path

from chatdome.agent.engram import EngramStore
from chatdome.agent.tools import ToolDispatcher
from chatdome.sentinel.user_context import UserContextLedger


class TestEngramStore(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.storage_path = Path(self.temp_dir.name) / "engram.json"
        self.store = EngramStore(self.storage_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_add_and_list(self):
        self.store.add("environment", "防火墙用 iptables", "用户说用 iptables")
        self.store.add("constraint", "不要重启 nginx", "用户说工作时间不重启")
        
        all_engrams = self.store.list()
        self.assertEqual(len(all_engrams), 2)
        
        env_engrams = self.store.list(category="environment")
        self.assertEqual(len(env_engrams), 1)
        self.assertEqual(env_engrams[0].fact, "防火墙用 iptables")

    def test_persistence(self):
        self.store.add("preference", "优先使用表格输出", "测试")
        
        # Create a new instance pointing to the same file
        store2 = EngramStore(self.storage_path)
        prefs = store2.list(category="preference")
        self.assertEqual(len(prefs), 1)
        self.assertEqual(prefs[0].fact, "优先使用表格输出")

    def test_supersede(self):
        old_engram = self.store.add("environment", "用 iptables", "测试1")
        self.assertIsNone(old_engram.superseded_by)
        
        new_engram = self.store.supersede(old_engram.id, "environment", "改用 ufw", "测试2")
        
        # Verify old engram is marked
        old_engram_updated = [e for e in self.store._engrams.values() if e.id == old_engram.id][0]
        self.assertEqual(old_engram_updated.superseded_by, new_engram.id)
        
        # Verify list() filters out superseded by default
        active = self.store.list()
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0].fact, "改用 ufw")
        
        # Include superseded
        all_entries = self.store.list(include_superseded=True)
        self.assertEqual(len(all_entries), 2)

    def test_build_prompt(self):
        self.store.add("environment", "用 iptables", "测试1")
        self.store.add("topology", "8080 是内部网关", "测试2")
        self.store.add("behavior", "用户通常通过 VPN 登录服务器", "测试3")
        
        prompt = self.store.build_engram_prompt()
        self.assertIn("[Engram — 记忆印迹]", prompt)
        self.assertIn("- [environment] 用 iptables", prompt)
        self.assertIn("- [topology] 8080 是内部网关", prompt)
        self.assertIn("- [behavior] 用户通常通过 VPN 登录服务器", prompt)

    def test_find_conflicts(self):
        self.store.add("environment", "主机防火墙使用 iptables 管理，不使用 ufw", "test")
        
        # Exact match / High overlap with conflict signal
        conflicts1 = self.store.find_conflicts("environment", "主机防火墙改用 ufw 管理")
        self.assertTrue(len(conflicts1) > 0, "Should detect conflict when changing firewall tool")
        
        # Completely unrelated
        conflicts2 = self.store.find_conflicts("environment", "nginx 配置在 /opt/nginx")
        self.assertEqual(len(conflicts2), 0, "Should not detect conflict for unrelated facts")
        
        # Same category but different subject
        self.store.add("environment", "python 版本是 3.10", "test")
        conflicts3 = self.store.find_conflicts("environment", "node 版本是 18")
        self.assertEqual(len(conflicts3), 0, "Should not detect conflict between different software versions")

    def test_sentinel_user_context_syncs_durable_behavior_to_engram(self):
        asyncio.run(self._run_sentinel_user_context_syncs_durable_behavior_to_engram())

    async def _run_sentinel_user_context_syncs_durable_behavior_to_engram(self):
        ledger = UserContextLedger(Path(self.temp_dir.name) / "user_context.json")
        dispatcher = ToolDispatcher(
            object(),
            user_context_ledger=ledger,
            engram_store=self.store,
        )
        arguments = json.dumps(
            {
                "check_id": "ssh_success_login",
                "pattern": "45.77.156.221",
                "summary": "用户确认 45.77.156.221 是其 VPN 节点 IP，通过该 IP SSH 登录属于本人操作",
            },
            ensure_ascii=False,
        )

        first_result = await dispatcher.dispatch("add_user_context", arguments)
        second_result = await dispatcher.dispatch("add_user_context", arguments)

        self.assertIn("Engram 同步", first_result)
        self.assertIn("已录入 Engram", first_result)
        self.assertIn("Engram 已存在", second_result)
        self.assertEqual(len(ledger.records), 2)
        engrams = self.store.list(category="behavior")
        self.assertEqual(len(engrams), 1)
        self.assertIn("45.77.156.221 是用户的 VPN 节点 IP", engrams[0].fact)
        self.assertIn("SSH 登录属于用户本人操作", engrams[0].fact)
        self.assertIn("ssh_success_login", engrams[0].source_context)

    def test_sentinel_user_context_syncs_recurring_operation_to_behavior(self):
        asyncio.run(self._run_sentinel_user_context_syncs_recurring_operation_to_behavior())

    async def _run_sentinel_user_context_syncs_recurring_operation_to_behavior(self):
        ledger = UserContextLedger(Path(self.temp_dir.name) / "user_context.json")
        dispatcher = ToolDispatcher(
            object(),
            user_context_ledger=ledger,
            engram_store=self.store,
        )
        result = await dispatcher.dispatch(
            "add_user_context",
            json.dumps(
                {
                    "check_id": "open_ports",
                    "pattern": "nginx",
                    "summary": "用户确认每次发布后会重启 nginx 并检查日志，端口变化属正常操作",
                },
                ensure_ascii=False,
            ),
        )

        self.assertIn("Engram 同步", result)
        engrams = self.store.list(category="behavior")
        self.assertEqual(len(engrams), 1)
        self.assertIn("每次发布后会重启 nginx", engrams[0].fact)

    def test_sentinel_user_context_syncs_stable_port_purpose_to_topology(self):
        asyncio.run(self._run_sentinel_user_context_syncs_stable_port_purpose_to_topology())

    async def _run_sentinel_user_context_syncs_stable_port_purpose_to_topology(self):
        ledger = UserContextLedger(Path(self.temp_dir.name) / "user_context.json")
        dispatcher = ToolDispatcher(
            object(),
            user_context_ledger=ledger,
            engram_store=self.store,
        )
        result = await dispatcher.dispatch(
            "add_user_context",
            json.dumps(
                {
                    "check_id": "open_ports",
                    "pattern": "6011",
                    "summary": "用户确认 6011 是本地调试代理端口，长期存在属正常",
                },
                ensure_ascii=False,
            ),
        )

        self.assertIn("Engram 同步", result)
        engrams = self.store.list(category="topology")
        self.assertEqual(len(engrams), 1)
        self.assertIn("6011 是本地调试代理端口", engrams[0].fact)

    def test_transient_sentinel_user_context_does_not_sync_to_engram(self):
        asyncio.run(self._run_transient_sentinel_user_context_does_not_sync_to_engram())

    async def _run_transient_sentinel_user_context_does_not_sync_to_engram(self):
        ledger = UserContextLedger(Path(self.temp_dir.name) / "user_context.json")
        dispatcher = ToolDispatcher(
            object(),
            user_context_ledger=ledger,
            engram_store=self.store,
        )
        result = await dispatcher.dispatch(
            "add_user_context",
            json.dumps(
                {
                    "check_id": "open_ports",
                    "pattern": "Xray",
                    "summary": "用户确认手动停止了 Xray 代理服务，端口变化属正常操作",
                },
                ensure_ascii=False,
            ),
        )

        self.assertIn("写入 ledger", result)
        self.assertNotIn("Engram 同步", result)
        self.assertEqual(self.store.list(), [])


if __name__ == '__main__':
    unittest.main()
