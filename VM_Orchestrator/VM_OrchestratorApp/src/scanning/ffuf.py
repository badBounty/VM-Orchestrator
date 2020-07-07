from VM_OrchestratorApp.src.utils import slack, utils, mongo, redmine
from VM_OrchestratorApp.src import constants
from VM_OrchestratorApp.src.vulnerability.vulnerability import Vulnerability
from VM_Orchestrator.settings import settings,FFUF_LIST

import subprocess
import os
import json
import uuid
from datetime import datetime


def cleanup(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    return


def handle_target(info):
    if FFUF_LIST:
        print('Module ffuf starting against %s alive urls from %s' % (str(len(info['url_to_scan'])), info['domain']))
        slack.send_simple_message("Directory bruteforce scan started against target: %s. %d alive urls found!"
                                        % (info['domain'], len(info['url_to_scan'])))
        for url in info['url_to_scan']:
            sub_info = info
            sub_info['url_to_scan'] = url
            scan_target(sub_info, sub_info['url_to_scan'])
        print('Module ffuf finished from %s' % info['domain'])
    return


def handle_single(scan_info):
    if FFUF_LIST:
        print('Module ffuf starting against %s' % scan_info['url_to_scan'])
        slack.send_simple_message("Directory bruteforce scan started against %s" % scan_info['url_to_scan'])
        scan_target(scan_info, scan_info['url_to_scan'])
        print('Module ffuf finished against %s' % scan_info['url_to_scan'])
    return


def add_vulnerability(scan_info, affected_resource, description):
    timestamp = datetime.now()
    vulnerability = Vulnerability(constants.ENDPOINT, scan_info, description)

    slack.send_vulnerability(vulnerability)
    redmine.create_new_issue(vulnerability)
    mongo.add_vulnerability(vulnerability)


def scan_target(scan_info, url_with_http):
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    TOOL_DIR = ROOT_DIR + '/tools/ffuf'
    WORDLIST_DIR = ROOT_DIR + '/tools/ffuf_wordlist.txt'
    random_filename = uuid.uuid4().hex
    JSON_RESULT = ROOT_DIR + '/tools_output/' + random_filename + '.json'
    cleanup(JSON_RESULT)

    if url_with_http[-1] != '/':
        url_with_http = url_with_http + '/'

    ffuf_process = subprocess.run(
        [TOOL_DIR, '-w', WORDLIST_DIR, '-u', url_with_http + 'FUZZ', '-c', '-v', '-mc', '200,403',
         '-o', JSON_RESULT], capture_output=True)

    with open(JSON_RESULT) as json_file:
        json_data = json.load(json_file)

    count = 0
    with open(WORDLIST_DIR, 'r') as f:
        for line in f:
            count += 1

    vulns = json_data['results']

    #If more than half of the endpoints are found, the result is discarded
    if len(vulns) > count/2:
        return

    valid_codes = [200, 403]
    one_found = False
    extra_info_message = ""
    for vuln in vulns:
        if vuln['status'] in valid_codes:
            extra_info_message = extra_info_message + "%s\n"% vuln['input']['FUZZ']
            one_found = True

    if one_found:
        description = "The following endpoints were found:\n %s" % (extra_info_message)
        add_vulnerability(scan_info, url_with_http, description)

    cleanup(JSON_RESULT)
    return
