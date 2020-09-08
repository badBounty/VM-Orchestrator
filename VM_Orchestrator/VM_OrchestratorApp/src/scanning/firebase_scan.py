# pylint: disable=import-error
from VM_OrchestratorApp.src.utils import slack, utils, mongo, redmine
from VM_OrchestratorApp.src import constants
from VM_OrchestratorApp.src.objects.vulnerability import Vulnerability

import urllib3
import requests
import re
import traceback
import copy

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MODULE_NAME = 'Firebase module'
MODULE_IDENTIFIER = 'firebase_module'
SLACK_NOTIFICATION_CHANNEL = '#vm-firebase'

def send_module_status_log(scan_info, status):
    mongo.add_module_status_log({
            'module_keyword': MODULE_IDENTIFIER,
            'state': status,
            'domain': scan_info['domain'],
            'found': None,
            'arguments': scan_info
        })
    return

def handle_target(info):
    info = copy.deepcopy(info)
    print('Module Firebase Scan starting against %s alive urls from %s' % (str(len(info['target'])), info['domain']))
    slack.send_module_start_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    send_module_status_log(info, 'start')

    for url in info['target']:
        sub_info = copy.deepcopy(info)
        sub_info['target'] = url
        scan_target(sub_info, sub_info['target'])
        
    print('Module Firebase Scan finished against %s' % info['domain'])
    slack.send_module_end_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    send_module_status_log(info, 'end')

    return


def handle_single(info):
    info = copy.deepcopy(info)
    print('Module Firebase Scan starting against %s' % info['target'])
    slack.send_module_start_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    send_module_status_log(info, 'start')
    scan_target(info, info['target'])
    slack.send_module_end_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    print('Module Firebase Scan finished against %s' % info['target'])
    send_module_status_log(info, 'end')
    return


def add_vulnerability(scan_info, firebase_name):
    vulnerability = Vulnerability(constants.OPEN_FIREBASE, scan_info, 'Found open firebase %s' % (firebase_name))

    slack.send_vuln_to_channel(vulnerability, SLACK_NOTIFICATION_CHANNEL)
    vulnerability.id = mongo.add_vulnerability(vulnerability)
    redmine.create_new_issue(vulnerability)

def get_response(url):
    try:
        response = requests.get(url, verify=False, timeout=3)
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

def filter_invalids(some_list):
    res = []
    # ------ Filter invalid matches
    for item in some_list:
        if all(char not in item for char in ['\\', '=', '>', '<', '[', ']', '{', '}', ';', '(', ')', '_']):
            res.append(item)
    return res


def scan_target(scan_info, url_to_scan):
    response = get_response(url_to_scan)
    if response is None:
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
        except Exception:
            error_string = traceback.format_exc()
            final_error = 'On {0}, was Found: {1}'.format(url_to_scan,error_string)
            slack.send_error_to_channel(final_error, SLACK_NOTIFICATION_CHANNEL)
            continue
        if firebase_response.status_code == 200:
            add_vulnerability(scan_info, firebase)
