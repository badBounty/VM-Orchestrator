from VM_OrchestratorApp.src.utils import slack, utils, mongo, redmine
from VM_OrchestratorApp.src import constants
from VM_OrchestratorApp.src.vulnerability.vulnerability import Vulnerability

import requests

def handle_target(info):
    print('Module HTTP Method Scan starting against %s alive urls from %s' % (str(len(info['url_to_scan'])), info['domain']))
    slack.send_simple_message("HTTP method scan started against target: %s. %d alive urls found!"
                                     % (info['domain'], len(info['url_to_scan'])))
    for url in info['url_to_scan']:
        sub_info = info
        sub_info['url_to_scan'] = url
        scan_target(sub_info, sub_info['url_to_scan'])
    print('Module HTTP Method Scan finished against %s' % info['domain'])
    return


def handle_single(scan_info):
    print('Module HTTP Method Scan starting against %s' % scan_info['url_to_scan'])
    slack.send_simple_message("HTTP method scan started against %s" % scan_info['url_to_scan'])
    scan_target(scan_info, scan_info['url_to_scan'])
    print('Module HTTP Method Scan finished against %s' % scan_info['url_to_scan'])
    return


def add_vulnerability(scan_info, message):
    vulnerability = Vulnerability(constants.UNSECURE_METHOD, scan_info, message)

    slack.send_vulnerability(vulnerability)
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
