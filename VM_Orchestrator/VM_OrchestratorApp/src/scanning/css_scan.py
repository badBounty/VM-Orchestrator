# pylint: disable=import-error
from VM_OrchestratorApp.src.utils import slack, utils, mongo, redmine
from VM_OrchestratorApp.src import constants
from VM_OrchestratorApp.src.objects.vulnerability import Vulnerability

import requests
import urllib3
import copy
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MODULE_NAME = 'Css scan module'
SLACK_NOTIFICATION_CHANNEL = '#vm-css'

def handle_target(info):
    info = copy.deepcopy(info)
    print('Module CSS Scan starting against %s alive urls from %s' % (str(len(info['url_to_scan'])), info['domain']))
    slack.send_module_start_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    for url in info['url_to_scan']:
        sub_info = copy.deepcopy(info)
        sub_info['url_to_scan'] = url
        scan_target(sub_info, sub_info['url_to_scan'])
    slack.send_module_end_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    print('Module CSS Scan finished against %s' % info['domain'])
    return


def handle_single(info):
    info = copy.deepcopy(info)
    print('Module CSS Scan starting against %s' % info['url_to_scan'])
    slack.send_module_start_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    scan_target(info, info['url_to_scan'])
    slack.send_module_end_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    print('Module CSS Scan finished against %s' % info['url_to_scan'])
    return


def add_vulnerability_to_mongo(scan_info, css_url, vuln_type):
    if vuln_type == 'Access':
        description = "Possible css injection found at %s. File could not be accessed" \
                      % (css_url)
    elif vuln_type == 'Status':
        description = "Possible css injection found at %s. File did not return 200" \
                      % (css_url)

    vulnerability = Vulnerability(constants.CSS_INJECTION, scan_info, description)
    slack.send_vuln_to_channel(vulnerability, SLACK_NOTIFICATION_CHANNEL)
    redmine.create_new_issue(vulnerability)
    mongo.add_vulnerability(vulnerability)


def scan_target(scan_info, url_to_scan):
    # We take every .css file from our linkfinder utils
    css_files_found = utils.get_css_files(url_to_scan)
    slack.send_notification_to_channel('Found %s css files at %s' % (str(len(css_files_found)), url_to_scan), SLACK_NOTIFICATION_CHANNEL)
    for css_file in css_files_found:
        url_split = css_file.split('/')
        host_split = url_to_scan.split('/')

        if css_file[-1] == '\\' or css_file[-1] == '/':
            css_file = css_file[:-1]
        try:
            response = requests.get(css_file, verify=False)
        except Exception:
            if url_split[2] != host_split[2]:
                add_vulnerability_to_mongo(scan_info, css_file, 'Access')

        if response.status_code != 200:
            if url_split[2] != host_split[2]:
                add_vulnerability_to_mongo(scan_info, css_file, 'Status')

    return
