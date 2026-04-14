from flask import Blueprint, request, jsonify, render_template_string, session, redirect, url_for

login_bp = Blueprint('login', __name__)

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>My Dashboard - TechCorp Portal</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: #f8fafc; }
        .navbar { background: #1e3a8a; color: white; padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; }
        .navbar h1 { font-size: 1.25rem; }
        .nav-links a { color: white; text-decoration: none; margin-left: 2rem; font-size: 0.875rem; }
        .nav-links a:hover { text-decoration: underline; }
        .container { max-width: 1200px; margin: 2rem auto; padding: 0 2rem; }
        .welcome { background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%); color: white; padding: 2rem; border-radius: 12px; margin-bottom: 2rem; }
        .welcome h2 { font-size: 1.5rem; margin-bottom: 0.5rem; }
        .welcome p { opacity: 0.9; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem; }
        .card { background: white; padding: 1.5rem; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .card h3 { color: #1e3a8a; font-size: 1rem; margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 2px solid #e2e8f0; }
        .info-row { display: flex; padding: 0.75rem 0; border-bottom: 1px solid #f1f5f9; }
        .info-row:last-child { border-bottom: none; }
        .info-label { color: #64748b; font-size: 0.875rem; width: 120px; }
        .info-value { color: #1e293b; font-weight: 500; flex: 1; }
        .menu-item { display: block; padding: 0.75rem; color: #3b82f6; text-decoration: none; border-radius: 6px; transition: background 0.2s; }
        .menu-item:hover { background: #eff6ff; }
        .btn { display: inline-block; padding: 0.5rem 1rem; background: #1e3a8a; color: white; text-decoration: none; border-radius: 6px; font-size: 0.875rem; margin-top: 1rem; }
        .btn:hover { background: #1e40af; }
    </style>
</head>
<body>
    <nav class="navbar">
        <h1>TechCorp Employee Portal</h1>
        <div class="nav-links">
            <a href="/dashboard">Dashboard</a>
            <a href="/search">Directory</a>
            <a href="/logout">Logout</a>
        </div>
    </nav>

    <div class="container">
        <div class="welcome">
            <h2>Welcome back, {{ user.cn }}!</h2>
            <p>{{ user.department }} Department | {{ user.role }}</p>
        </div>

        <div class="grid">
            <div class="card">
                <h3>My Profile</h3>
                <div class="info-row">
                    <span class="info-label">Employee ID</span>
                    <span class="info-value">{{ user.uid }}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Full Name</span>
                    <span class="info-value">{{ user.cn }}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Email</span>
                    <span class="info-value">{{ user.mail }}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Department</span>
                    <span class="info-value">{{ user.department or user.ou }}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Role</span>
                    <span class="info-value">{{ user.role }}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Manager</span>
                    <span class="info-value">{{ user.manager }}</span>
                </div>
                <a href="#" class="btn">Edit Profile</a>
            </div>

            <div class="card">
                <h3>Quick Links</h3>
                <a href="/search" class="menu-item">Employee Directory</a>
                <a href="#" class="menu-item">My Payslips</a>
                <a href="#" class="menu-item">Request Time Off</a>
                <a href="#" class="menu-item">IT Support</a>
                <a href="#" class="menu-item">Company Policies</a>
            </div>

            <div class="card">
                <h3>System Status</h3>
                <div class="info-row">
                    <span class="info-label">Email</span>
                    <span class="info-value" style="color: #22c55e;">Active</span>
                </div>
                <div class="info-row">
                    <span class="info-label">VPN</span>
                    <span class="info-value" style="color: #22c55e;">Connected</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Last Login</span>
                    <span class="info-value">Today, 09:42 AM</span>
                </div>
                <div class="info-row">
                    <span class="info-label">Password Expires</span>
                    <span class="info-value">45 days</span>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
"""

LOGIN_FORM = """
<!DOCTYPE html>
<html>
<head>
    <title>Employee Login - TechCorp Portal</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: #f1f5f9; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .login-container { background: white; padding: 3rem; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); width: 100%; max-width: 400px; }
        .logo { text-align: center; margin-bottom: 2rem; }
        .logo h1 { color: #1e3a8a; font-size: 1.75rem; }
        .logo p { color: #64748b; font-size: 0.875rem; margin-top: 0.5rem; }
        .form-group { margin-bottom: 1.5rem; }
        label { display: block; margin-bottom: 0.5rem; color: #334155; font-weight: 500; font-size: 0.875rem; }
        input[type="text"], input[type="password"] { width: 100%; padding: 0.75rem; border: 1px solid #d1d5db; border-radius: 6px; font-size: 1rem; }
        input:focus { outline: none; border-color: #3b82f6; }
        button { width: 100%; padding: 0.875rem; background: #1e3a8a; color: white; border: none; border-radius: 6px; font-size: 1rem; font-weight: 500; cursor: pointer; }
        button:hover { background: #1e40af; }
        .error { color: #dc2626; background: #fef2f2; padding: 0.75rem; border-radius: 6px; margin-top: 1rem; font-size: 0.875rem; }
        .success { color: #059669; background: #f0fdf4; padding: 0.75rem; border-radius: 6px; margin-top: 1rem; font-size: 0.875rem; }
        .footer { text-align: center; margin-top: 2rem; padding-top: 1.5rem; border-top: 1px solid #e2e8f0; }
        .footer a { color: #3b82f6; text-decoration: none; font-size: 0.875rem; }
        .footer p { color: #94a3b8; font-size: 0.75rem; margin-top: 0.5rem; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <h1>TechCorp</h1>
            <p>Employee Portal</p>
        </div>
        <form method="POST" action="/login">
            <div class="form-group">
                <label>Employee ID / Username</label>
                <input type="text" name="username" placeholder="Enter your username" required>
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" placeholder="Enter your password" required>
            </div>
            <button type="submit">Sign In</button>
        </form>
        {% if error %}
        <div class="error">{{ error_msg }}</div>
        {% endif %}
        {% if success %}
        <div class="success">
            <h3>Welcome {{ user.cn }}! Login successful.</h3>
            <div style="background: #f8fafc; padding: 20px; margin-top: 15px; border-radius: 8px; text-align: left;">
                <h4 style="color: #1e3a8a; margin-bottom: 15px;">Your Profile</h4>
                <table style="width: 100%;">
                    <tr><td style="padding: 8px 0; color: #64748b;"><strong>Employee ID:</strong></td><td>{{ user.uid }}</td></tr>
                    <tr><td style="padding: 8px 0; color: #64748b;"><strong>Name:</strong></td><td>{{ user.cn }}</td></tr>
                    <tr><td style="padding: 8px 0; color: #64748b;"><strong>Email:</strong></td><td>{{ user.mail }}</td></tr>
                    <tr><td style="padding: 8px 0; color: #64748b;"><strong>Department:</strong></td><td>{{ user.department or user.ou }}</td></tr>
                    <tr><td style="padding: 8px 0; color: #64748b;"><strong>Role:</strong></td><td>{{ user.role }}</td></tr>
                    <tr><td style="padding: 8px 0; color: #64748b;"><strong>Manager:</strong></td><td>{{ user.manager }}</td></tr>
                </table>
                <div style="margin-top: 20px; padding-top: 15px; border-top: 1px solid #e2e8f0;">
                    <a href="/search" style="color: #3b82f6; text-decoration: none;">View Employee Directory &rarr;</a>
                </div>
            </div>
        </div>
        {% endif %}
        <div class="footer">
            <a href="/">&larr; Back to Home</a>
            <p>Internal Use Only &copy; 2024 TechCorp Industries</p>
        </div>
    </div>
</body>
</html>
"""


def create_login_routes(ldap_server):
    @login_bp.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'GET':
            return render_template_string(LOGIN_FORM)

        username = request.form.get('username', '')
        password = request.form.get('password', '')

        user = ldap_server.users.get(username)

        if user and user.get('password') == password:
            session['user_uid'] = user.get('uid')
            return redirect('/dashboard')
        else:
            return render_template_string(
                LOGIN_FORM,
                error=True,
                error_msg="Invalid username or password. Please try again."
            ), 401

    @login_bp.route('/dashboard')
    def dashboard():
        user_uid = session.get('user_uid')
        if not user_uid:
            return redirect('/login')

        user = ldap_server.users.get(user_uid)
        if not user:
            return redirect('/login')

        return render_template_string(DASHBOARD_TEMPLATE, user=user)

    @login_bp.route('/logout')
    def logout():
        session.clear()
        return redirect('/login')

    @login_bp.route('/api/login', methods=['POST'])
    def api_login():
        username = request.form.get('username', '') or request.json.get('username', '')
        password = request.form.get('password', '') or request.json.get('password', '')

        search_filter = f"(&(uid={username})(password={password}))"

        try:
            results = ldap_server.search(search_filter)

            if results and len(results) > 0 and not results[0].get("error"):
                user = results[0]
                return jsonify({
                    "authenticated": True,
                    "user": {
                        "uid": user.get("uid"),
                        "cn": user.get("cn"),
                        "mail": user.get("mail"),
                        "department": user.get("department"),
                        "role": user.get("role"),
                        "employeeID": user.get("employeeID"),
                        "manager": user.get("manager")
                    },
                    "token": "jwt_" + user.get("uid", "")[:20] + "_session",
                    "session": "active"
                })
            else:
                return jsonify({
                    "authenticated": False,
                    "error": "Invalid credentials"
                }), 401

        except Exception as e:
            return jsonify({
                "error": "Authentication failed",
                "code": "AUTH_FAILED"
            }), 500

    @login_bp.route('/api/auth/verify', methods=['GET', 'POST'])
    def api_auth_verify():
        uid = request.args.get('uid', '') or request.form.get('uid', '')
        if not uid:
            return jsonify({"error": "UID required"}), 400

        search_filter = f"(uid={uid})"

        try:
            results = ldap_server.search(search_filter)

            if results:
                user = results[0]
                return jsonify({
                    "verified": True,
                    "user": {
                        "uid": user.get("uid"),
                        "cn": user.get("cn"),
                        "mail": user.get("mail"),
                        "department": user.get("department"),
                        "role": user.get("role")
                    }
                })
            else:
                return jsonify({
                    "verified": False,
                    "error": "User not found"
                }), 404

        except Exception as e:
            return jsonify({
                "error": "Verification failed",
                "code": "VERIFY_ERROR"
            }), 500

    return login_bp
