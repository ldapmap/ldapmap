
import json
import os
from datetime import datetime

from ldapmap_attacker.core.session import Session
from ldapmap_attacker.lib.logger import setup_logger

logger = setup_logger()


class Report:

    def __init__(self, session, output_dir="./output"):
        self.session = session
        self.output_dir = output_dir
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def generate(self):
        summary = self.session.get_summary()
        
        vuln_results = [
            {
                "payload": r.payload,
                "payload_type": r.payload_type,
                "url": r.url,
                "status_code": r.status_code,
                "response_time": r.response_time,
                "evidence": r.evidence
            }
            for r in self.session.results if r.vulnerable
        ]
        
        all_results = [
            {
                "payload": r.payload,
                "vulnerable": r.vulnerable,
                "status_code": r.status_code,
                "error": r.error
            }
            for r in self.session.results
        ]
        
        return {
            "scan_info": {
                "tool": "LDAPMap",
                "version": "1.0.0",
                "timestamp": self.timestamp,
                "target": summary["target"],
                "method": summary["method"]
            },
            "summary": {
                "duration_seconds": summary["duration_seconds"],
                "tests_count": summary["tests_count"],
                "vulnerabilities_found": summary["vulnerabilities_found"],
                "errors_count": summary["errors_count"]
            },
            "vulnerabilities": vuln_results,
            "all_results": all_results
        }
    
    def export_json(self, filename=None):
        if not filename:
            filename = f"ldapmap_report_{self.timestamp}.json"
        
        filepath = os.path.join(self.output_dir, filename)
        report_data = self.generate()
        
        with open(filepath, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        logger.success(f"Report exported: {filepath}")
        return filepath
    
    def print_console(self):
        summary = self.session.get_summary()
        vuln_results = [r for r in self.session.results if r.vulnerable]
        
        print()
        logger.info("=" * 60)
        logger.info("SCAN REPORT")
        logger.info("=" * 60)
        logger.info(f"Target: {summary['target']}")
        logger.info(f"Method: {summary['method']}")
        logger.info(f"Duration: {summary['duration_seconds']:.1f}s")
        logger.info(f"Tests: {summary['tests_count']}")
        logger.info(f"Vulnerabilities: {summary['vulnerabilities_found']}")
        
        if vuln_results:
            logger.vuln(f"\nCONFIRMED VULNERABILITIES ({len(vuln_results)})")
            logger.vuln("-" * 60)
            for i, r in enumerate(vuln_results, 1):
                logger.vuln(f"\n{i}. Payload: {r.payload}")
                logger.info(f"   Type: {r.payload_type}")
                logger.info(f"   URL: {r.url}")
                logger.info(f"   Status: {r.status_code}")
                
                for detector in r.evidence.get("detectors", []):
                    logger.info(f"   Detector: {detector['name']}")
        
        logger.info("\n" + "=" * 60)
