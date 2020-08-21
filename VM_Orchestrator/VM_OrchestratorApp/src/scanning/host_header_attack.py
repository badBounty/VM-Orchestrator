# pylint: disable=import-error
from VM_OrchestratorApp.src.utils import slack, utils, mongo, redmine
from VM_OrchestratorApp.src import constants
from VM_OrchestratorApp.src.objects.vulnerability import Vulnerability

import urllib3
import requests
import tldextract
import traceback
import copy
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MODULE_NAME = 'Host header attack module'
MODULE_IDENTIFIER = 'hha_module'
SLACK_NOTIFICATION_CHANNEL = '#vm-hha'

def send_module_status_log(info, status):
    mongo.add_module_status_log({
            'module_keyword': MODULE_IDENTIFIER,
            'state': status,
            'domain': info['domain'],
            'found': None,
            'arguments': info
        })
    return

def handle_target(info):
    info = copy.deepcopy(info)
    print('Module Host Header Attack starting against %s alive urls from %s' % (str(len(info['target'])), info['domain']))
    slack.send_module_start_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    send_module_status_log(info, 'start')

    for url in info['target']:
        sub_info = copy.deepcopy(info)
        sub_info['target'] = url
        scan_target(sub_info, sub_info['target'])

    print('Module Host Header Attack finished against %s' % info['domain'])
    slack.send_module_end_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    send_module_status_log(info, 'end')
    return


def handle_single(info):
    info = copy.deepcopy(info)
    print('Module Host Header Attack starting against %s' % info['target'])
    slack.send_module_start_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    scan_target(info, info['target'])
    slack.send_module_end_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    print('Module Host Header Attack finished against %s' % info['target'])
    return


def add_vulnerability_to_mongo(scan_info):
    vulnerability = Vulnerability(constants.HOST_HEADER_ATTACK, scan_info, "Host header attack possible")

    slack.send_vuln_to_channel(vulnerability, SLACK_NOTIFICATION_CHANNEL)
    redmine.create_new_issue(vulnerability)
    mongo.add_vulnerability(vulnerability)
    return

def get_response(url):
    try:
        response = requests.get(url, verify=False, timeout=3, headers={'Host': 'test.com'})
    except requests.exceptions.SSLError:
        slack.send_error_to_channel('Url %s raised SSL Error' % url, SLACK_NOTIFICATION_CHANNEL)
        return None
    except requests.exceptions.ConnectionError:
        slack.send_error_to_channel('Url %s raised Connection Error' % url, SLACK_NOTIFICATION_CHANNEL)
        return None
    except requests.exceptions.ReadTimeout:
        slack.send_error_to_channel('Url %s raised Read Timeout' % url, SLACK_NOTIFICATION_CHANNEL)
        return None
    except requests.exceptions.TooManyRedirects:
        slack.send_error_to_channel('Url %s raised Too Many Redirects' % url, SLACK_NOTIFICATION_CHANNEL)
        return None
    except Exception:
        error_string = traceback.format_exc()
        final_error = 'On {0}, was Found: {1}'.format(url,error_string)
        slack.send_error_to_channel(final_error, SLACK_NOTIFICATION_CHANNEL)
        return None
    return response

def scan_target(scan_info, url_to_scan):
    response = get_response(url_to_scan)
    if response is None:
        return

    host_header_attack = 0
    # Tests if the host sent in the request is being reflected in the URL
    response_url = response.url
    extract = tldextract.extract(response_url)
    findvalue = response_url.find("test.com")

    if findvalue >= 0:
        host_header_attack = 1

    # Tests if the host sent in the request is being reflected in any header
    resp_headers = response.headers
    for x in resp_headers:  # Searchs if any header value reflects the value sent.
        value_in_header = resp_headers[x]
        findvalue = value_in_header.find('test.com')
        if findvalue >= 0:
            host_header_attack = 1
            break

    # Tests if the host sent in the requests is reflected in the response body
    response_body_inbytes = response.content  # Saves response's body
    response_body_str = str(response_body_inbytes)
    findvalue = response_body_str.find('test.com')
    if findvalue >= 0:
        host_header_attack = 1
    # If it's vulnerable to host
    # header attack, appends the information to the output file.
    if host_header_attack == 1:
        add_vulnerability_to_mongo(scan_info)

