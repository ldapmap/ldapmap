from flask import Blueprint, request, jsonify, render_template_string

search_bp = Blueprint('search', __name__)

SEARCH_FORM = """
<!DOCTYPE html>
<html>
<head>
    <title>Employee Directory - TechCorp Portal</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: #f8fafc; }
        .navbar { background: #1e3a8a; color: white; padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; }
        .navbar h1 { font-size: 1.5rem; }
        .nav-links a { color: white; text-decoration: none; margin-left: 2rem; }
        .container { max-width: 1200px; margin: 2rem auto; padding: 0 2rem; }
        .search-box { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 2rem; }
        .search-box h2 { color: #1e3a8a; margin-bottom: 1.5rem; }
        .form-group { display: flex; gap: 1rem; align-items: flex-end; }
        label { display: block; margin-bottom: 0.5rem; color: #334155; font-weight: 500; }
        input[type="text"] { flex: 1; padding: 0.75rem; border: 1px solid #d1d5db; border-radius: 6px; font-size: 1rem; }
        button { padding: 0.75rem 1.5rem; background: #1e3a8a; color: white; border: none; border-radius: 6px; font-size: 1rem; cursor: pointer; }
        button:hover { background: #1e40af; }
        .results { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .results h3 { color: #1e3a8a; margin-bottom: 1.5rem; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 1rem; text-align: left; border-bottom: 1px solid #e2e8f0; }
        th { background: #f1f5f9; color: #334155; font-weight: 600; }
        td { color: #475569; }
        tr:hover { background: #f8fafc; }
        .error { color: #dc2626; background: #fef2f2; padding: 1rem; border-radius: 6px; border-left: 4px solid #dc2626; }
        .no-results { color: #64748b; text-align: center; padding: 2rem; }
        .footer { text-align: center; padding: 2rem; color: #94a3b8; margin-top: 2rem; }
    </style>
</head>
<body>
    <nav class="navbar">
        <h1>TechCorp - Employee Directory</h1>
        <div class="nav-links">
            <a href="/">Home</a>
            <a href="/search">Directory</a>
            <a href="/login">Login</a>
        </div>
    </nav>

    <div class="container">
        <div class="search-box">
            <h2>Search Employees</h2>
            <form method="GET" action="/search">
                <div class="form-group">
                    <div style="flex: 1;">
                        <label>Employee Name</label>
                        <input type="text" name="cn" placeholder="Enter name (e.g., John, Smith)" value="{{ cn }}">
                    </div>
                    <button type="submit">Search</button>
                </div>
            </form>
        </div>

        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}

        {% if results %}
        <div class="results">
            <h3>Search Results ({{ results|length }} employees found)</h3>
            {% if results|length > 0 %}
            <table>
                <tr>
                    <th>Employee ID</th>
                    <th>Name</th>
                    <th>Email</th>
                    <th>Department</th>
                    <th>Role</th>
                </tr>
                {% for user in results %}
                <tr>
                    <td>{{ user.uid }}</td>
                    <td>{{ user.cn }}</td>
                    <td>{{ user.mail }}</td>
                    <td>{{ user.department or user.ou }}</td>
                    <td>{{ user.role }}</td>
                </tr>
                {% endfor %}
            </table>
            {% else %}
            <div class="no-results">No employees found matching your search.</div>
            {% endif %}
        </div>
        {% endif %}
    </div>

    <footer class="footer">
        <p>&copy; 2024 TechCorp Industries. Internal Use Only.</p>
    </footer>
</body>
</html>
"""


def create_search_routes(ldap_server):
    @search_bp.route('/search', methods=['GET'])
    def search():
        cn = request.args.get('cn', '') or request.args.get('query', '') or request.args.get('q', '') or request.args.get('name', '')

        if not cn:
            return render_template_string(SEARCH_FORM, cn='', results=None)

        search_filter = f"(cn={cn})"
        
        try:
            results = ldap_server.search(search_filter)
            
            if results and results[0].get("error"):
                return render_template_string(
                    SEARCH_FORM,
                    cn=cn,
                    results=None,
                    error=f"{results[0]['error']} (Filter: {search_filter})"
                ), 400
            
            return render_template_string(SEARCH_FORM, cn=cn, results=results, error=None)
            
        except Exception as e:
            return jsonify({
                "error": "Search query invalid",
                "code": "SEARCH_INVALID",
                "message": "Please check your search syntax and try again."
            }), 400
    
    @search_bp.route('/api/search', methods=['GET'])
    def api_search():
        cn = request.args.get('cn', '') or request.args.get('query', '') or request.args.get('q', '')
        raw_filter = request.args.get('filter', '')
        
        if raw_filter:
            search_filter = raw_filter
        else:
            search_filter = f"(cn={cn})" if cn else "(objectClass=*)"
        
        try:
            results = ldap_server.search(search_filter)
            
            return jsonify({
                "filter": search_filter,
                "count": len(results),
                "results": results
            })
            
        except Exception as e:
            return jsonify({
                "error": "Directory search failed",
                "code": "DIR_SEARCH_ERROR"
            }), 500

    @search_bp.route('/api/debug', methods=['GET', 'POST'])
    def api_debug():
        raw_filter = request.args.get('filter', '') or request.form.get('filter', '') or '*'

        try:
            results = ldap_server.search(raw_filter)

            return jsonify({
                "query": raw_filter,
                "count": len(results),
                "results": results,
                "debug_info": {
                    "all_attributes": True,
                    "server_time": "2024-01-01T00:00:00Z"
                }
            })

        except Exception as e:
            return jsonify({
                "error": "Query processing failed",
                "code": "QUERY_ERROR"
            }), 500

    @search_bp.route('/api/admin/search', methods=['GET', 'POST'])
    def api_admin_search():
        auth = request.headers.get('Authorization', '')
        raw_filter = request.args.get('filter', '') or request.form.get('filter', '') or '(objectClass=*)'

        try:
            results = ldap_server.search(raw_filter)

            admin_data = []
            for user in results:
                admin_data.append({
                    "uid": user.get("uid"),
                    "cn": user.get("cn"),
                    "department": user.get("department"),
                    "role": user.get("role"),
                    "employeeID": user.get("employeeID")
                })

            return jsonify({
                "filter": raw_filter,
                "total_records": len(results),
                "employees": admin_data
            })

        except Exception as e:
            return jsonify({
                "error": "Admin search failed",
                "code": "ADMIN_SEARCH_ERROR"
            }), 500

    return search_bp
