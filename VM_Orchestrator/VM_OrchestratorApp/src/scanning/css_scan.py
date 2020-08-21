# pylint: disable=import-error
from VM_OrchestratorApp.src.utils import slack, utils, mongo, redmine
from VM_OrchestratorApp.src import constants
from VM_OrchestratorApp.src.objects.vulnerability import Vulnerability

import requests
import urllib3
import copy
import time
import traceback
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MODULE_NAME = 'Css scan module'
MODULE_IDENTIFIER = 'css_module'
SLACK_NOTIFICATION_CHANNEL = '#vm-css'

def send_module_status_log(scan_info, status):
    mongo.add_module_status_log({
            'module_keyword': MODULE_IDENTIFIER,
            'state': status,
            'domain': scan_info['domain'],
            'found': None,
            'target': scan_info['target']
        })
    return

def handle_target(info):
    info = copy.deepcopy(info)
    print('Module CSS Scan starting against %s alive urls from %s' % (str(len(info['target'])), info['domain']))
    slack.send_module_start_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    send_module_status_log(info, 'start')

    for url in info['target']:
        sub_info = copy.deepcopy(info)
        sub_info['target'] = url
        scan_target(sub_info, sub_info['target'])
        
    print('Module CSS Scan finished against %s' % info['domain'])
    slack.send_module_end_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    send_module_status_log(info, 'end')

    return


def handle_single(info):
    info = copy.deepcopy(info)
    print('Module CSS Scan starting against %s' % info['target'])
    slack.send_module_start_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    send_module_status_log(info, 'start')

    scan_target(info, info['target'])
    
    slack.send_module_end_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    print('Module CSS Scan finished against %s' % info['target'])
    send_module_status_log(info, 'end')
    return

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
    if css_files_found:
        slack.send_notification_to_channel('_ Found %s css files at %s _' % (str(len(css_files_found)), url_to_scan), SLACK_NOTIFICATION_CHANNEL)
    for css_file in css_files_found:
        url_split = css_file.split('/')
        host_split = url_to_scan.split('/')

        if css_file[-1] == '\\' or css_file[-1] == '/':
            css_file = css_file[:-1]
        
        response = get_response(url_to_scan)
        if response is None:
            if url_split[2] != host_split[2]:
                add_vulnerability_to_mongo(scan_info, css_file, 'Access')
                return
            return

        if response.status_code != 200:
            if url_split[2] != host_split[2]:
                add_vulnerability_to_mongo(scan_info, css_file, 'Status')

    return
