import requests
import utils.utils as utils
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def validate(pluginargs, args):
    #
    # Plugin Args
    #
    # --url https://domain.com    ->  gives the URL to the application
    # --domain DOMAIN              ->  Optional Input domain name
    #
    if 'url' in pluginargs.keys():
        if "https://" not in pluginargs['url'] and "http://" not in pluginargs['url']:
            error = "URL requires http:// or https:// prefix"
            return False, error, None
        return True, None, pluginargs
    else:
        error = "Missing url argument, specify as --url https://domain.com"
        return False, error, None


def testconnect(pluginargs, args, api_dict, useragent):

    success = True
    headers = {
        'User-Agent' : useragent,
        "X-My-X-Forwarded-For" : utils.generate_ip(),
        "x-amzn-apigateway-api-id" : utils.generate_id(),
        "X-My-X-Amzn-Trace-Id" : utils.generate_trace_id(),
    }

    headers = utils.add_custom_headers(pluginargs, headers)

    resp = requests.get(api_dict['proxy_url'] + "/+webvpn+/index.html", headers=headers, verify=False, proxies=pluginargs["proxy"])

    if resp.status_code != 200:
        output = "Testconnect: Connection failed, endpoint timed out, exiting"
        success = False
    elif "/+CSCOE+/logon.html" in resp.text:
        output = "Testconnect: Verified Cisco VPN instance, connected"
    else:
        output = "Testconnect: Warning, Cisco VPN not indicated, continuing"

    return success, output, pluginargs
