import json
import os
import tempfile
import unittest
from pathlib import Path

from chatdome.agent.engram import EngramStore


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
        
        prompt = self.store.build_engram_prompt()
        self.assertIn("[Engram — 记忆印迹]", prompt)
        self.assertIn("- [environment] 用 iptables", prompt)
        self.assertIn("- [topology] 8080 是内部网关", prompt)

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


if __name__ == '__main__':
    unittest.main()
