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
SLACK_NOTIFICATION_CHANNEL = '#vm-hha'

def handle_target(info):
    info = copy.deepcopy(info)
    print('Module Host Header Attack starting against %s alive urls from %s' % (str(len(info['url_to_scan'])), info['domain']))
    slack.send_module_start_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    for url in info['url_to_scan']:
        sub_info = copy.deepcopy(info)
        sub_info['url_to_scan'] = url
        scan_target(sub_info, sub_info['url_to_scan'])
    slack.send_module_end_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    print('Module Host Header Attack finished against %s' % info['domain'])
    return


def handle_single(info):
    info = copy.deepcopy(info)
    print('Module Host Header Attack starting against %s' % info['url_to_scan'])
    slack.send_module_start_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    scan_target(info, info['url_to_scan'])
    slack.send_module_end_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    print('Module Host Header Attack finished against %s' % info['url_to_scan'])
    return


def add_vulnerability_to_mongo(scan_info):
    vulnerability = Vulnerability(constants.HOST_HEADER_ATTACK, scan_info, "Host header attack possible")

    slack.send_vuln_to_channel(vulnerability, SLACK_NOTIFICATION_CHANNEL)
    redmine.create_new_issue(vulnerability)
    mongo.add_vulnerability(vulnerability)
    return


def scan_target(scan_info, url_to_scan):
    try:
        # Sends the request to test if it's vulnerable to a Host Header Attack
        response = requests.get(url_to_scan, verify=False, headers={'Host': 'test.com'}, timeout=3)
    except Exception:
        error_string = traceback.format_exc()
        slack.send_error_to_channel(error_string, SLACK_NOTIFICATION_CHANNEL)
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

