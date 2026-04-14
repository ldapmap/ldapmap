import argparse
from ldapmap_target.app import create_app


def main():
    parser = argparse.ArgumentParser(
        prog="ldapmap-target",
        description="Vulnerable LDAP server for testing LDAPMap"
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=5000,
        help="Server port (default: 5000)"
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Server host (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Flask debug mode"
    )
    
    args = parser.parse_args()
    
    print(fr"""
    _    _                            
   | |__| |__ _ _ __ _ __  __ _ _ __ 
   | / _` / _` | '_ \ '  \/ _` | '_ \
   |_\__,_\__,_| .__/_|_|_\__,_| .__/
               |_|             |_|

          Vuln server started now !

    Server: http://{args.host}:{args.port}
    """)
    
    app = create_app()
    app.run(
        host=args.host,
        port=args.port,
        debug=args.debug,
        threaded=True
    )


if __name__ == "__main__":
    main()
