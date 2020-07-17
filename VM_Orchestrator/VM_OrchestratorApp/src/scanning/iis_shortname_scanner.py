# pylint: disable=import-error
from VM_OrchestratorApp.src.utils import slack, utils, mongo, image_creator, redmine
from VM_OrchestratorApp.src import constants
from VM_OrchestratorApp.src.objects.vulnerability import Vulnerability

import requests
import os
import subprocess
import base64
import traceback
import copy
from PIL import Image
from io import BytesIO
from datetime import datetime
import uuid

MODULE_NAME = 'IIS shortname module'
SLACK_NOTIFICATION_CHANNEL = '#vm-iis'

def handle_target(info):
    info = copy.deepcopy(info)
    print('Module IIS Shortname starting against %s alive urls from %s' % (str(len(info['url_to_scan'])), info['domain']))
    slack.send_module_start_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    for url in info['url_to_scan']:
        sub_info = copy.deepcopy(info)
        sub_info['url_to_scan'] = url
        scan_target(sub_info, sub_info['url_to_scan'])
    slack.send_module_end_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    print('Module IIS Shortname finished against %s' % info['domain'])
    return


def handle_single(info):
    info = copy.deepcopy(info)
    print('Module IIS Shortname starting against %s' % info['url_to_scan'])
    slack.send_module_start_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    scan_target(info, info['url_to_scan'])
    slack.send_module_end_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    print('Module IIS Shortname finished against %s' % info['url_to_scan'])
    return


def scan_target(scan_info, url_to_scan):
    try:
        resp = requests.get(url_to_scan)
    except requests.exceptions.SSLError:
        return
    except Exception:
        error_string = traceback.format_exc()
        slack.send_error_to_channel(error_string, SLACK_NOTIFICATION_CHANNEL)
        return
    try:
        if 'IIS' in resp.headers['Server']:
            ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
            TOOL_DIR = ROOT_DIR + '/tools/IIS-ShortName-Scanner/iis_shortname_scanner.jar'
            CONFIG_DIR = ROOT_DIR + '/tools/IIS-ShortName-Scanner/config.xml'
            iis_process = subprocess.run(['java', '-jar', TOOL_DIR, '0', '10', url_to_scan, CONFIG_DIR],
                                         capture_output=True)
            message = iis_process.stdout.decode()
            if "NOT VULNERABLE" not in message:
                img_str = image_creator.create_image_from_string(message)
                random_filename = uuid.uuid4().hex
                output_dir = ROOT_DIR + '/tools_output/' + random_filename + '.png'
                im = Image.open(BytesIO(base64.b64decode(img_str)))
                im.save(output_dir, 'PNG')

                vulnerability = Vulnerability(constants.IIS_SHORTNAME_MICROSOFT, scan_info,
                                              "IIS Microsoft files and directories enumeration found")

                vulnerability.add_image_string(img_str)
                vulnerability.add_attachment(output_dir, 'IIS-Result.png')
                slack.send_vuln_to_channel(vulnerability, SLACK_NOTIFICATION_CHANNEL)
                redmine.create_new_issue(vulnerability)
                mongo.add_vulnerability(vulnerability)
                os.remove(output_dir)
    except KeyError:
        pass
    except Exception:
        pass
    return