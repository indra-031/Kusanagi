import json
import os


DEFAULT_CONFIG = {
    "telegram": {
        "enabled": False,
        "bot_token": "",
        "chat_id": "",
        "thread_id": ""
    },
    "bypass403": {
        "enabled": True,
        "script_path": "./third-party/bypass-403/bypass-403.sh",
        "timeout": 300
    },
    "zero3": {
        "enabled": True,
        "script_path": "./third-party/4-ZERO-3/403-bypass.sh",
        "timeout": 600,
        "mode": "exploit"
    },
    "forbidra": {
        "enabled": True,
        "script_path": "./third-party/Forbidra/forbidra.sh",
        "timeout": 600
    }
}


def load_config(path: str = "config.json") -> dict:
    """Load config from disk, merged over defaults."""
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                user_cfg = json.load(f)
            for section, values in user_cfg.items():
                if isinstance(values, dict) and section in cfg:
                    cfg[section].update(values)
                else:
                    cfg[section] = values
        except Exception as e:
            print(f"[!] Could not load config {path}: {e}")
    return cfg