
from abc import ABC, abstractmethod
import requests


class BasePayload(ABC):
    def __init__(self, options=None):
        self.options = options or {}
        self.name = self.__class__.__name__

    @abstractmethod
    def generate(self):
        pass

    def get_info(self):
        return {"name": self.name, "description": "payload plugin"}


class BaseDetector(ABC):
    def __init__(self, options=None):
        self.options = options or {}
        self.name = self.__class__.__name__

    @abstractmethod
    def detect(self, response, payload, baseline=None):
        pass

    def get_info(self):
        return {"name": self.name, "description": "detector plugin"}


class PluginManager:
    def __init__(self):
        self.payload_plugins = {}
        self.detector_plugins = {}
        self._load_builtin_plugins()

    def _load_builtin_plugins(self):
        from ldapmap_attacker.plugins.payloads import (
            authentication_bypass,
            data_extraction,
            blind
        )
        from ldapmap_attacker.plugins.detectors import (
            error_based,
            boolean_based,
            time_based
        )

        self.register_payload("authentication_bypass", authentication_bypass.AuthenticationBypassPayload)
        self.register_payload("data_extraction", data_extraction.DataExtractionPayload)
        self.register_payload("blind", blind.BlindPayload)

        self.register_detector("error_based", error_based.ErrorBasedDetector)
        self.register_detector("boolean_based", boolean_based.BooleanBasedDetector)
        self.register_detector("time_based", time_based.TimeBasedDetector)

    def register_payload(self, name, plugin_class):
        self.payload_plugins[name] = plugin_class

    def register_detector(self, name, plugin_class):
        self.detector_plugins[name] = plugin_class

    def get_payload(self, name):
        return self.payload_plugins.get(name)

    def get_detector(self, name):
        return self.detector_plugins.get(name)

    def list_payloads(self):
        return list(self.payload_plugins.keys())

    def list_detectors(self):
        return list(self.detector_plugins.keys())
