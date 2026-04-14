import json
import os


class Config:
    DEFAULT_CONFIG = {
        "timeout": 30,
        "retries": 3,
        "threads": 5,
        "delay": 0,
        "verify_ssl": True,
        "detectors": ["error_based", "boolean_based"],
        "payloads": ["authentication_bypass", "data_extraction"]
    }

    def __init__(self, config_path=None):
        self.config_path = config_path or self._find_config()
        self.settings = self.DEFAULT_CONFIG.copy()

        if self.config_path and os.path.exists(self.config_path):
            self.load()

    def _find_config(self):
        paths = [
            ".ldapmaprc",
            os.path.expanduser("~/.ldapmaprc"),
            "/etc/ldapmaprc"
        ]
        for path in paths:
            if os.path.exists(path):
                return path
        return None

    def load(self):
        try:
            with open(self.config_path, 'r') as f:
                loaded = json.load(f)
                self.settings.update(loaded)
        except (json.JSONDecodeError, IOError) as e:
            print("Warning: Could not load config: " + str(e))

    def save(self, path):
        with open(path, 'w') as f:
            json.dump(self.settings, f, indent=2)

    def get(self, key, default=None):
        return self.settings.get(key, default)

    def set(self, key, value):
        self.settings[key] = value
