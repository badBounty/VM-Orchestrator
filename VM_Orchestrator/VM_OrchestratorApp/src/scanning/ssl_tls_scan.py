from VM_OrchestratorApp.src.utils import slack, utils, mongo, redmine
from VM_OrchestratorApp.src import constants
from VM_OrchestratorApp.src.objects.vulnerability import Vulnerability

import json
import xmltodict
import uuid
import xml
from datetime import datetime
import subprocess
import os

MODULE_NAME = 'SSL/TLS module'
SLACK_NOTIFICATION_CHANNEL = '#vm-ssl-tls'

def handle_target(info):
    print('Module SSL/TLS starting against %s alive urls from %s' % (str(len(info['url_to_scan'])), info['domain']))
    slack.send_module_start_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    valid_ports = ['443']
    for url in info['url_to_scan']:
        sub_info = info
        sub_info['url_to_scan'] = url

        split_url = url.split('/')
        try:
            final_url = split_url[2]
        except IndexError:
            final_url = url
        for port in valid_ports:
            scan_target(sub_info, url, final_url+':'+port)
    slack.send_module_end_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    print('Module SSL/TLS finished against %s' % info['domain'])
    return


def handle_single(info):
    # Url will come with http or https, we will strip and append ports that could have tls/ssl
    url = info['url_to_scan']
    slack.send_module_start_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    valid_ports = ['443']
    split_url = url.split('/')
    try:
        final_url = split_url[2]
    except IndexError:
        final_url = url
    print('Module SSL/TLS starting against %s' % info['url_to_scan'])
    for port in valid_ports:
        scan_target(info, url, final_url+':'+port)
    slack.send_module_end_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    print('Module SSL/TLS finished against %s' % info['url_to_scan'])
    return


def checker(scan_info, url_with_port, result):
    timestamp = datetime.now()
    # testssl has a bunch of vulns, we could test more
    if result['id'] == 'SSLv2' and result['finding'] != 'not offered':
        add_vulnerability(scan_info, "SSLv2 is available at %s" % url_with_port)
    elif result['id'] == 'SSLv3' and result['finding'] != 'not offered':
        add_vulnerability(scan_info, "SSLv3 is available at %s" % url_with_port)
    elif result['id'] == 'TLS1' and result['finding'] != 'not offered':
        add_vulnerability(scan_info, "TLS1.0 is available at %s" % url_with_port)


def cleanup(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    return


def add_vulnerability(scan_info, message):
    vulnerability = Vulnerability(constants.SSL_TLS, scan_info, message)

    slack.send_vuln_to_channel(vulnerability, SLACK_NOTIFICATION_CHANNEL)
    redmine.create_new_issue(vulnerability)
    mongo.add_vulnerability(vulnerability)


# In cases where single url is provided, port will default to 80 or 443 in most cases
def scan_target(scan_info, url, url_with_port):

    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    TOOL_DIR = ROOT_DIR + '/tools/testssl.sh/testssl.sh'
    random_filename = uuid.uuid4().hex
    OUTPUT_FULL_NAME = ROOT_DIR + '/tools_output/' + random_filename + '.json'

    cleanup(OUTPUT_FULL_NAME)
    # We first run the subprocess that creates the xml output file
    testssl_process = subprocess.run(
       ['bash', TOOL_DIR, '--fast', '--warnings=off', '-oj', OUTPUT_FULL_NAME, url_with_port], capture_output=True)

    with open(OUTPUT_FULL_NAME) as f:
        results = json.load(f)

    for result in results:
        checker(scan_info, url_with_port, result)

    cleanup(OUTPUT_FULL_NAME)

    return