
from flask import Flask, jsonify
from ldapmap_target.ldap_server import FakeLDAPServer
from ldapmap_target.routes.login import create_login_routes
from ldapmap_target.routes.search import create_search_routes


def create_app():
    app = Flask(__name__)
    app.config['JSON_SORT_KEYS'] = False
    app.secret_key = 'techcorp-secret-key-2024'

    ldap_server = FakeLDAPServer()

    login_routes = create_login_routes(ldap_server)
    search_routes = create_search_routes(ldap_server)
    
    app.register_blueprint(login_routes)
    app.register_blueprint(search_routes)
    
    @app.route('/')
    def index():
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>TechCorp Industries - Employee Portal</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; }
                .navbar { background: #1e3a8a; color: white; padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; }
                .navbar h1 { font-size: 1.5rem; }
                .nav-links a { color: white; text-decoration: none; margin-left: 2rem; }
                .hero { background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%); color: white; padding: 4rem 2rem; text-align: center; }
                .hero h2 { font-size: 2.5rem; margin-bottom: 1rem; }
                .hero p { font-size: 1.2rem; opacity: 0.9; }
                .features { max-width: 1200px; margin: 3rem auto; padding: 0 2rem; display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 2rem; }
                .feature { background: #f8fafc; padding: 2rem; border-radius: 8px; border: 1px solid #e2e8f0; }
                .feature h3 { color: #1e3a8a; margin-bottom: 1rem; }
                .feature p { color: #64748b; }
                .feature a { display: inline-block; margin-top: 1rem; color: #3b82f6; text-decoration: none; font-weight: 500; }
                .footer { background: #0f172a; color: #94a3b8; text-align: center; padding: 2rem; margin-top: 4rem; }
            </style>
        </head>
        <body>
            <nav class="navbar">
                <h1>TechCorp Industries</h1>
                <div class="nav-links">
                    <a href="/">Home</a>
                    <a href="/search">Employee Directory</a>
                    <a href="/login">Login</a>
                </div>
            </nav>

            <section class="hero">
                <h2>Welcome to TechCorp Employee Portal</h2>
                <p>Secure access to company resources and employee information</p>
            </section>

            <section class="features">
                <div class="feature">
                    <h3>Employee Directory</h3>
                    <p>Search and browse employee contact information, departments, and roles.</p>
                    <a href="/search">Access Directory &rarr;</a>
                </div>
                <div class="feature">
                    <h3>Secure Login</h3>
                    <p>Access your personal dashboard, payroll information, and benefits.</p>
                    <a href="/login">Employee Login &rarr;</a>
                </div>
                <div class="feature">
                    <h3>API Access</h3>
                    <p>Developer resources and API documentation for internal systems integration.</p>
                    <a href="/api/docs">View API Docs &rarr;</a>
                </div>
            </section>

            <footer class="footer">
                <p>&copy; 2024 TechCorp Industries. All rights reserved. | Internal Use Only</p>
            </footer>
        </body>
        </html>
        """
    
    @app.route('/health')
    def health():
        return jsonify({
            "status": "healthy",
            "service": "techcorp-portal",
            "version": "2.1.0"
        })

    @app.route('/api/docs')
    def api_docs():
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>TechCorp API Documentation</title>
            <style>
                body { font-family: 'Segoe UI', sans-serif; max-width: 1000px; margin: 0 auto; padding: 2rem; }
                h1 { color: #1e3a8a; border-bottom: 2px solid #e2e8f0; padding-bottom: 1rem; }
                h2 { color: #334155; margin-top: 2rem; }
                .endpoint { background: #f8fafc; padding: 1.5rem; margin: 1rem 0; border-radius: 8px; border-left: 4px solid #3b82f6; }
                .method { display: inline-block; background: #3b82f6; color: white; padding: 0.25rem 0.75rem; border-radius: 4px; font-size: 0.875rem; font-weight: 600; }
                code { background: #e2e8f0; padding: 0.25rem 0.5rem; border-radius: 4px; font-family: monospace; }
                pre { background: #1e293b; color: #e2e8f0; padding: 1rem; border-radius: 8px; overflow-x: auto; }
            </style>
        </head>
        <body>
            <h1>TechCorp Internal API Documentation</h1>
            <p>RESTful API for employee data access and authentication.</p>

            <h2>Authentication</h2>
            <div class="endpoint">
                <span class="method">POST</span> <code>/api/login</code>
                <p>Authenticate employee credentials. Returns user profile and session token.</p>
                <pre>POST /api/login
Content-Type: application/json

{
  "username": "john_doe",
  "password": "password123"
}</pre>
            </div>

            <h2>Employee Directory</h2>
            <div class="endpoint">
                <span class="method">GET</span> <code>/api/search?cn={name}</code>
                <p>Search employees by common name. Supports wildcard matching.</p>
                <pre>GET /api/search?cn=john</pre>
            </div>

            <div class="endpoint">
                <span class="method">GET</span> <code>/api/search?filter={ldap_filter}</code>
                <p>Advanced search with custom LDAP filter syntax.</p>
                <pre>GET /api/search?filter=(uid=john_doe)</pre>
            </div>

            <h2>Administration</h2>
            <div class="endpoint">
                <span class="method">GET/POST</span> <code>/api/admin/search</code>
                <p>Administrative search endpoint. Requires Authorization header.</p>
            </div>

            <h2>Developer Tools</h2>
            <div class="endpoint">
                <span class="method">GET/POST</span> <code>/api/debug</code>
                <p>Debug endpoint for testing LDAP queries. Internal use only.</p>
            </div>

            <div class="endpoint">
                <span class="method">GET/POST</span> <code>/api/auth/verify</code>
                <p>Verify user authentication status by UID.</p>
            </div>
        </body>
        </html>
        """
    
    return app
