# pylint: disable=import-error
from VM_OrchestratorApp.src.utils import slack, utils, mongo, redmine
from VM_OrchestratorApp.src import constants
from VM_OrchestratorApp.src.objects.vulnerability import Vulnerability

import requests
import copy

MODULE_NAME = 'HTTP method module'
SLACK_NOTIFICATION_CHANNEL = '#vm-http-methods'

def handle_target(info):
    info = copy.deepcopy(info)
    print('Module HTTP Method Scan starting against %s alive urls from %s' % (str(len(info['target'])), info['domain']))
    slack.send_module_start_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    for url in info['target']:
        sub_info = copy.deepcopy(info)
        sub_info['target'] = url
        scan_target(sub_info, sub_info['target'])
    slack.send_module_end_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    print('Module HTTP Method Scan finished against %s' % info['domain'])
    return


def handle_single(info):
    info = copy.deepcopy(info)
    print('Module HTTP Method Scan starting against %s' % info['target'])
    slack.send_module_start_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    scan_target(info, info['target'])
    slack.send_module_end_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    print('Module HTTP Method Scan finished against %s' % info['target'])
    return


def add_vulnerability(scan_info, message):
    vulnerability = Vulnerability(constants.UNSECURE_METHOD, scan_info, message)

    slack.send_vuln_to_channel(vulnerability, SLACK_NOTIFICATION_CHANNEL)
    redmine.create_new_issue(vulnerability)
    mongo.add_vulnerability(vulnerability)


def scan_target(scan_info, url_to_scan):
    responses = list()
    try:
        put_response = requests.put(url_to_scan, data={'key': 'value'})
        responses.append({'method': 'PUT', 'response': put_response})
    except requests.exceptions.SSLError:
        return
    except requests.exceptions.ConnectionError:
        return
    except requests.exceptions.TooManyRedirects:
        return
    
    try:
        delete_response = requests.delete(url_to_scan)
        responses.append({'method': 'DELETE', 'response': delete_response})
    except requests.exceptions.SSLError:
        return
    except requests.exceptions.ConnectionError:
        return
    except requests.exceptions.TooManyRedirects:
        return

    try:
        options_response = requests.options(url_to_scan)
        responses.append({'method': 'OPTIONS', 'response': options_response})
    except requests.exceptions.SSLError:
        return
    except requests.exceptions.ConnectionError:
        return
    except requests.exceptions.TooManyRedirects:
        return

    extensive_methods = False
    message = "Found extended HTTP Methods:" + '\n'
    if not responses:
        return
    for response in responses:
        if response['response'].status_code == 200:
            extensive_methods = True
            message = message + "Method " + response['method'] + " found." + "\n"
    if extensive_methods:
        add_vulnerability(scan_info, message)
