import tempfile
import unittest
from pathlib import Path

from chatdome.reload_control import ReloadControl


class ReloadControlTests(unittest.TestCase):
    def test_request_and_status_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            control = ReloadControl(base_dir=Path(tmp))
            request = control.request_reload(["llm", "agent"], source="test")

            loaded = control.load_request()
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded.request_id, request.request_id)
            self.assertEqual(loaded.domains, ["llm", "agent"])
            self.assertEqual(loaded.source, "test")

            status = control.mark_status(
                request.request_id,
                ok=True,
                message="done",
                applied_domains=["llm"],
            )
            loaded_status = control.load_status()
            self.assertIsNotNone(loaded_status)
            self.assertEqual(loaded_status.request_id, status.request_id)
            self.assertTrue(loaded_status.ok)
            self.assertEqual(loaded_status.applied_domains, ["llm"])

            self.assertTrue(control.clear_request(request.request_id))
            self.assertIsNone(control.load_request())

    def test_invalid_domain_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unsupported reload domain"):
            ReloadControl.normalize_domains(["llm", "telegram"])


if __name__ == "__main__":
    unittest.main()
