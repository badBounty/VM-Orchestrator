# pylint: disable=import-error
from VM_OrchestratorApp.src.utils import slack, utils, mongo, image_creator, redmine
from VM_OrchestratorApp.src import constants
from VM_OrchestratorApp.src.objects.vulnerability import Vulnerability

import requests
import os
import uuid
import base64
import traceback
import copy
from PIL import Image
from io import BytesIO
from datetime import datetime

MODULE_NAME = 'Header scan module'
MODULE_IDENTIFIER = 'header_module'
SLACK_NOTIFICATION_CHANNEL = '#vm-header-scan'

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
    print('Module Header Scan starting against %s alive urls from %s' % (str(len(info['target'])), info['domain']))
    slack.send_module_start_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    send_module_status_log(info, 'start')

    for url in info['target']:
        sub_info = copy.deepcopy(info)
        sub_info['target'] = url
        scan_target(sub_info, sub_info['target'])

    print('Module Header Scan finished against %s' % info['domain'])
    slack.send_module_end_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    send_module_status_log(info, 'end')
    return


def handle_single(info):
    info = copy.deepcopy(info)
    print('Module Header Scan starting against %s' % info['target'])
    slack.send_module_start_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    send_module_status_log(info, 'start')

    scan_target(info, info['target'])
    
    slack.send_module_end_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    print('Module Header Scan finished against %s' % info['target'])
    send_module_status_log(info, 'end')
    return


def check_header_value(header_to_scan, value_received):
    if header_to_scan == 'x-frame-options':
        if 'SAMEORIGIN' not in value_received:
            return False
    if header_to_scan == 'X-Content-Type-options':
        if 'nosniff' not in value_received:
            return False
    if header_to_scan == 'Strict-Transport-Security':
        if 'max-age' not in value_received:
            return False
    if header_to_scan == 'Access-Control-Allow-Origin':
        if '*' in value_received:
            return False

    return True

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

def add_header_value_vulnerability(scan_info, img_string, description):
    vulnerability = Vulnerability(constants.INVALID_VALUE_ON_HEADER, scan_info, description)
    vulnerability.add_image_string(img_string)

    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    random_filename = uuid.uuid4().hex
    output_dir = ROOT_DIR + '/tools_output/' + random_filename + '.png'
    im = Image.open(BytesIO(base64.b64decode(img_string)))
    im.save(output_dir, 'PNG')

    vulnerability.add_attachment(output_dir, 'headers-result.png')

    slack.send_vuln_to_channel(vulnerability, SLACK_NOTIFICATION_CHANNEL)
    redmine.create_new_issue(vulnerability)
    os.remove(output_dir)
    mongo.add_vulnerability(vulnerability)


def add_header_missing_vulnerability(scan_info, img_string, description):
    vulnerability = Vulnerability(constants.HEADER_NOT_FOUND, scan_info, description)
    vulnerability.add_image_string(img_string)

    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    random_filename = uuid.uuid4().hex
    output_dir = ROOT_DIR+'/tools_output/' + random_filename + '.png'
    im = Image.open(BytesIO(base64.b64decode(img_string)))
    im.save(output_dir, 'PNG')

    vulnerability.add_attachment(output_dir, 'headers-result.png')

    slack.send_vuln_to_channel(vulnerability, SLACK_NOTIFICATION_CHANNEL)
    redmine.create_new_issue(vulnerability)
    os.remove(output_dir)
    mongo.add_vulnerability(vulnerability)


def scan_target(scan_info, url_to_scan):
    response = get_response(url_to_scan)
    if response is None:
        return
    message = 'Response Headers From: ' + url_to_scan+'\n'
    for h in response.headers:
        message += h + " : " + response.headers[h]+'\n'
    img_b64 = image_creator.create_image_from_string(message)

    important_headers = ['Content-Security-Policy', 'X-XSS-Protection', 'x-frame-options', 'X-Content-Type-options',
                         'Strict-Transport-Security', 'Access-Control-Allow-Origin']
    reported_invalid = False
    reported_exists = False
    message_invalid = "Headers with invalid values were found \n"
    message_exists = "Headers were not found \n"
    if response.status_code != 404:
        for header in important_headers:
            try:
                # If the header exists
                if response.headers[header]:
                    if not check_header_value(header, response.headers[header]):
                        message_invalid = message_invalid + "Header %s was found with invalid value \n" % header
                        # No header differenciation, so we do this for now
                        if not reported_invalid:
                            reported_invalid = True
            except KeyError:
                message_exists = message_exists + "Header %s was not found \n" % header
                if not reported_exists:
                    reported_exists = True

        if reported_exists:
            add_header_missing_vulnerability(scan_info, img_b64, message_exists)
        if reported_invalid:
            add_header_value_vulnerability(scan_info, img_b64, message_invalid)
    return
