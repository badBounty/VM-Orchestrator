from VM_OrchestratorApp.src.utils import slack, utils, mongo, redmine
from VM_OrchestratorApp.src import constants
from VM_OrchestratorApp.src.objects.vulnerability import Vulnerability

import urllib3
import requests
import re
import traceback

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MODULE_NAME = 'Firebase module'
SLACK_NOTIFICATION_CHANNEL = '#vm-firebase'

def handle_target(info):
    print('Module Firebase Scan starting against %s alive urls from %s' % (str(len(info['url_to_scan'])), info['domain']))
    slack.send_module_start_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    for url in info['url_to_scan']:
        sub_info = info
        sub_info['url_to_scan'] = url
        scan_target(sub_info, sub_info['url_to_scan'])
    slack.send_module_end_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    print('Module Firebase Scan finished against %s' % info['domain'])
    return


def handle_single(info):
    print('Module Firebase Scan starting against %s' % info['url_to_scan'])
    slack.send_module_start_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    scan_target(info, info['url_to_scan'])
    slack.send_module_end_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    print('Module Firebase Scan finished against %s' % info['url_to_scan'])
    return


def add_vulnerability(scan_info, firebase_name):
    vulnerability = Vulnerability(constants.OPEN_FIREBASE, scan_info, 'Found open firebase %s' % (firebase_name))

    slack.send_vuln_to_channel(vulnerability, SLACK_NOTIFICATION_CHANNEL)
    redmine.create_new_issue(vulnerability)
    mongo.add_vulnerability(vulnerability)


def filter_invalids(some_list):
    res = []
    # ------ Filter invalid matches
    for item in some_list:
        if all(char not in item for char in ['\\', '=', '>', '<', '[', ']', '{', '}', ';', '(', ')', '_']):
            res.append(item)
    return res


def scan_target(scan_info, url_to_scan):
    try:
        response = requests.get(url_to_scan, verify=False, timeout=3)
    except Exception as e:
        error_string = traceback.format_exc()
        slack.send_error_to_channel(error_string, SLACK_NOTIFICATION_CHANNEL)
        return

    # Firebases come in the form
    # https://*.firebaseio.com

    # ---------Way I----------
    firebase_HTTPS = re.findall('"https://([^\"/,]+).firebaseio.com"', response.text)
    firebase_HTTPS = filter_invalids(firebase_HTTPS)
    firebase_HTTP = re.findall('"http://([^\"/,]+).firebaseio.com"', response.text)
    firebase_HTTP = filter_invalids(firebase_HTTP)

    firebase_list = firebase_HTTPS + firebase_HTTP
    firebase_list = list(dict.fromkeys(firebase_list))

    for i in range(len(firebase_list)):
        firebase_list[i] = 'http://' + firebase_list[i] + '.firebaseio.com/.json'

    for firebase in firebase_list:
        try:
            firebase_response = requests.get(firebase, verify=False, timeout=3)
        except Exception as e:
            error_string = traceback.format_exc()
            slack.send_error_to_channel(error_string, SLACK_NOTIFICATION_CHANNEL)
            continue
        if firebase_response.status_code == 200:
            add_vulnerability(scan_info, firebase)
