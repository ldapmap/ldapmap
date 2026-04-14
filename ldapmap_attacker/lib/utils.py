import re
import urllib.parse


def is_valid_url(url):
    pat = r'^https?://[^\s<>"{}|\\^`\[\]]+$'
    return bool(re.match(pat, url, re.IGNORECASE))


def parse_target_url(url):
    parsed = urllib.parse.urlparse(url)
    base_url = parsed.scheme + "://" + parsed.netloc + parsed.path
    params = urllib.parse.parse_qs(parsed.query)

    params_dict = {}
    for key, values in params.items():
        params_dict[key] = values[0] if values else ""

    return base_url, params_dict


def replace_param_in_url(url, param_name, value):
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    if param_name in params:
        params[param_name] = [value]

    new_query = urllib.parse.urlencode(params, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


def find_injection_points(url, data=None):
    points = {}

    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    for key, values in params.items():
        if values and 'INPUT' in values[0]:
            points[key] = values[0]

    if data:
        post_params = urllib.parse.parse_qs(data)
        for key, values in post_params.items():
            if values and 'INPUT' in values[0]:
                points[key] = values[0]

    return points
