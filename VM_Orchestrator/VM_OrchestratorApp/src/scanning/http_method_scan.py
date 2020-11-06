# pylint: disable=import-error
from VM_OrchestratorApp.src.utils import slack, utils, mongo, redmine, image_creator
from VM_OrchestratorApp.src import constants
from VM_OrchestratorApp.src.objects.vulnerability import Vulnerability

import requests
import json
import xmltodict
import uuid
import xml
import copy
from datetime import datetime
import subprocess
import traceback
import os
import re
import base64
from os.path import isdir, isfile, join
from PIL import Image
from io import BytesIO
from contextlib import suppress

MODULE_NAME = 'HTTP method module'
MODULE_IDENTIFIER = 'httpmethod_module'
SLACK_NOTIFICATION_CHANNEL = '#vm-http-methods'

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
    print('Module HTTP Method Scan starting against %s alive urls from %s' % (str(len(info['target'])), info['domain']))
    slack.send_module_start_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    send_module_status_log(info, 'start')
    
    for url in info['target']:
        sub_info = copy.deepcopy(info)
        split_url = url.split('/')
        try: final_url = split_url[2] 
        except IndexError: final_url = url
        sub_info['target'] = final_url
        scan_target(sub_info, sub_info['target'])

    print('Module HTTP Method Scan finished against %s' % info['domain'])
    slack.send_module_end_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    send_module_status_log(info, 'end')

    return


def handle_single(info):
    info = copy.deepcopy(info)
    print('Module HTTP Method Scan starting against %s' % info['target'])
    slack.send_module_start_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    send_module_status_log(info, 'start')

    scan_target(info, info['target'])

    slack.send_module_end_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
    print('Module HTTP Method Scan finished against %s' % info['target'])
    send_module_status_log(info, 'end')
    return

def put_response(url):
    try:
        response = requests.put(url, verify=False, timeout=3, data={'key': 'value'})
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

def options_response(url):
    try:
        response = requests.options(url, verify=False, timeout=3, data={'key': 'value'})
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

def delete_response(url):
    try:
        response = requests.delete(url, verify=False, timeout=3, data={'key': 'value'})
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

def add_vulnerability(scan_info, data, message, cvssScore):
    vulnerability = Vulnerability(constants.UNSECURE_METHOD, scan_info, message)

    img_str = image_creator.create_image_from_string(data)
    vulnerability.add_image_string(img_str)
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    output_dir = ROOT_DIR+'/tools_output/' + str(uuid.uuid4().hex) + '.png'
    im = Image.open(BytesIO(base64.b64decode(img_str)))
    im.save(output_dir, 'PNG')
    vulnerability.add_attachment(output_dir, 'NMAP-result.png')

    vulnerability.cvss = cvssScore

    slack.send_vuln_to_channel(vulnerability, SLACK_NOTIFICATION_CHANNEL)
    vulnerability.id = mongo.add_vulnerability(vulnerability)
    redmine.create_new_issue(vulnerability)
    with suppress(Exception): os.remove(output_dir)


def scan_target(scan_info, url_to_scan):
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    OUTPUT_FULL_NAME = ROOT_DIR + '/tools_output/' + str(uuid.uuid4().hex) + '.txt'
    
    # TODO Add http-put
    # nmap -p 80 <ip> --script http-put --script-args http-put.url='/uploads/rootme.php',http-put.file='/tmp/rootme.php'
    # https://nmap.org/nsedoc/scripts/http-put.html
    sp = subprocess.run(['nmap', '-Pn', '--script', 'http-methods,http-trace', '--script-args', 'http-methods.test-all=true', url_to_scan], capture_output=True, timeout=500)
    data = sp.stdout.decode()

    dataList = data.splitlines()
    
    listVulnerablePorts = []
    listMethodsFoundForCVSS = []

    for i in range(len(dataList)):
        match = re.search("([0-9]{1,5})/tcp|udp.*open", dataList[i])
        if match:
            portStr = str(match.group(1))
            cnt = i + 1
            while dataList[cnt].startswith("| ") or dataList[cnt].startswith("|_ "):
                if dataList[cnt].startswith("|_ "):
                    if " methods: " in dataList[cnt]:
                        methodsFound = str(dataList[cnt])[str(dataList[cnt]).find(" methods: ")+10:].replace("\t", " ").replace("  ", " ")
                        listMethodsFoundForCVSS += methodsFound.split(" ")
                        listVulnerablePorts.append([portStr, methodsFound])
                        break
                else: cnt += 1
    if listVulnerablePorts:
        sumCVSS = 0
        cantCVSS = 0
        # Write in description what methods were found in every port
        message = "\n*Potentially vulnerable HTTP methods were found in the target:*\n\n"
        for i in range(len(listVulnerablePorts)):
            message += "* On port " + listVulnerablePorts[i][0] + " the following HTTP methods were found: " + listVulnerablePorts[i][1].strip().replace(" ", ", ") + "\n\n"
        # Separator...
        # Write the CVSS for every HTTP Method found.
        if len(listMethodsFoundForCVSS) == 1: message += "*CVSS Analysis for the detected method:*\n\n"
        else:                                 message += "*CVSS Analysis for the detected methods:*\n\n"
        alreadyChosen = []
        for i in range(len(listMethodsFoundForCVSS)):
            if listMethodsFoundForCVSS[i] not in alreadyChosen:
                alreadyChosen.append(listMethodsFoundForCVSS[i])
                cnt = 0
                for j in range(len(listMethodsFoundForCVSS)):
                    if listMethodsFoundForCVSS[j] == listMethodsFoundForCVSS[i]: cnt += 1
                if cnt == 1: message += "* Method " + listMethodsFoundForCVSS[i] + " found in 1 port: "
                else:        message += "* Method " + listMethodsFoundForCVSS[i] + " found in " + str(cnt) + " ports: "
                if listMethodsFoundForCVSS[i] in ["PUT", "DELETE"]:
                    sumCVSS += 7.3*cnt
                    cantCVSS += cnt
                    message += "7.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L)\n\n"
                elif listMethodsFoundForCVSS[i] == "CONNECT":
                    sumCVSS += 5.8*cnt
                    cantCVSS += cnt
                    message += "5.8 (AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N)\n\n"
                elif listMethodsFoundForCVSS[i] in ["TRACE", "DEBUG"]:
                    sumCVSS += 5.3*cnt
                    cantCVSS += cnt
                    message += "5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)\n\n"
                else:
                    message += "To be calculated (don't forget changing the final average value)...\n\n"
        cvssScore = round(sumCVSS/cantCVSS,1)
        add_vulnerability(scan_info, data, message, cvssScore)
    else:
        print("No vulnerable HTTP methods were found.")
