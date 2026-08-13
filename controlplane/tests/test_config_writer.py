import os
from pathlib import Path

import yaml

from chatdome.config_writer import TemplateConfigWriter


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_template_writer_keeps_template_and_overlays_user_values(tmp_path: Path) -> None:
    template = tmp_path / "config.example.yaml"
    config = tmp_path / "config.yaml"
    template.write_text(
        """# ChatDome Configuration
chatdome:
  telegram:
    bot_token: ""  # Telegram token
    allowed_ids: []
    admin_ids: []
  active_ai_profile: ""
  ai_profiles: {}
  sentinel:
    enabled: true
    alert_targets: {}
    new_default: 42  # Added by a newer release
""",
        encoding="utf-8",
    )
    config.write_text("chatdome: {}\n", encoding="utf-8")
    os.chmod(config, 0o640)
    document = {
        "chatdome": {
            "telegram": {
                "bot_token": "secret-token",
                "allowed_ids": [11],
                "admin_ids": [22],
            },
            "active_ai_profile": "Nvidia",
            "ai_profiles": {
                "Nvidia": {
                    "provider": "openai",
                    "api_mode": "openai_api",
                    "base_url": "https://integrate.api.nvidia.com/v1",
                    "model": "z-ai/glm-5.2",
                    "api_key": "nvapi-secret",
                }
            },
            "sentinel": {
                "enabled": False,
                "alert_targets": {"telegram": {"user_ids": [22]}},
            },
        }
    }

    TemplateConfigWriter(config, template).write(document)

    rendered = config.read_text(encoding="utf-8")
    loaded = yaml.safe_load(rendered)["chatdome"]
    assert "# ChatDome Configuration" in rendered
    assert "# Telegram token" in rendered
    assert "# Added by a newer release" in rendered
    assert all(not line.endswith((" ", "\t")) for line in rendered.splitlines())
    assert rendered.index("telegram:") < rendered.index("active_ai_profile:")
    assert loaded["telegram"]["bot_token"] == "secret-token"
    assert loaded["ai_profiles"]["Nvidia"]["api_key"] == "nvapi-secret"
    assert loaded["sentinel"]["alert_targets"]["telegram"]["user_ids"] == [22]
    assert loaded["sentinel"]["new_default"] == 42
    assert loaded["sentinel"]["enabled"] is False
    if os.name != "nt":
        assert config.stat().st_mode & 0o777 == 0o600


def test_template_writer_does_not_modify_config_when_template_is_invalid(
    tmp_path: Path,
) -> None:
    template = tmp_path / "config.example.yaml"
    config = tmp_path / "config.yaml"
    template.write_text("chatdome: [\n", encoding="utf-8")
    original = "chatdome:\n  active_ai_profile: preserved\n"
    config.write_text(original, encoding="utf-8")

    try:
        TemplateConfigWriter(config, template).write({"chatdome": {}})
    except ValueError:
        pass
    else:
        raise AssertionError("invalid template was accepted")

    assert config.read_text(encoding="utf-8") == original


def test_repository_template_accepts_every_sentinel_runtime_setting(
    tmp_path: Path,
) -> None:
    template = REPO_ROOT / "config.example.yaml"
    config = tmp_path / "config.yaml"
    document = yaml.safe_load(template.read_text(encoding="utf-8"))
    sentinel = document["chatdome"]["sentinel"]
    sentinel.update(
        {
            "aggregation_window": 25,
            "daily_report": False,
            "daily_report_time": "18:30",
            "ai_analysis_min_severity": 9,
        }
    )

    TemplateConfigWriter(config, template).write(document)

    rendered = yaml.safe_load(config.read_text(encoding="utf-8"))
    assert rendered["chatdome"]["sentinel"]["aggregation_window"] == 25
    assert rendered["chatdome"]["sentinel"]["daily_report"] is False
    assert rendered["chatdome"]["sentinel"]["daily_report_time"] == "18:30"
    assert rendered["chatdome"]["sentinel"]["ai_analysis_min_severity"] == 9
