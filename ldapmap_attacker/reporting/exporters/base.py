
from abc import ABC, abstractmethod


class BaseExporter(ABC):
    def __init__(self, output_dir):
        self.output_dir = output_dir

    @abstractmethod
    def export(self, report_data, filename):
        pass

    @abstractmethod
    def get_extension(self):
        pass
