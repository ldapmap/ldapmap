import json
import os

from ldapmap_attacker.reporting.exporters.base import BaseExporter


class JSONExporter(BaseExporter):
    def export(self, report_data, filename):
        if not filename.endswith('.json'):
            filename += '.json'

        filepath = os.path.join(self.output_dir, filename)

        with open(filepath, 'w') as f:
            json.dump(report_data, f, indent=2)

        return filepath

    def get_extension(self):
        return "json"
