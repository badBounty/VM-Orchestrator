# pylint: disable=import-error
from VM_OrchestratorApp.src.utils import slack, utils, mongo, redmine
from VM_OrchestratorApp.src import constants
from VM_OrchestratorApp.src.objects.vulnerability import Vulnerability
from VM_Orchestrator.settings import settings,BURP_FOLDER,BURP_BLACKLIST

import time
import copy
import requests
import subprocess
import os
import uuid
import xmltodict
import json
import base64
from datetime import datetime

MODULE_NAME = 'Burp module'

MODULE_IDENTIFIER = 'burp_module'
SLACK_NOTIFICATION_CHANNEL = '#vm-burp'

#Put
add_to_scope_url = "http://localhost:8090/burp/target/scope?url=%s"
#Get
query_in_scope_url = "http://localhost:8090/burp/target/scope?url=%s"
#Post
spider_url = "http://localhost:8090/burp/spider?baseUrl=%s"
#Get
spider_status_url = "http://localhost:8090/burp/spider/status"
#Post
passive_scan_url = "http://localhost:8090/burp/scanner/scans/passive?baseUrl=%s"
#Get
scan_status_url = "http://localhost:8090/burp/scanner/status"
#Post
active_scan_url = "http://localhost:8090/burp/scanner/scans/active?baseUrl=%s&insertionPoint="
#Get
download_report = "http://localhost:8090/burp/report?reportType=XML&urlPrefix=%s"
#Get
stop_burp = "http://localhost:8090/burp/stop"

def send_module_status_log(scan_info, status):
    mongo.add_module_status_log({
            'module_keyword': MODULE_IDENTIFIER,
            'state': status,
            'domain': scan_info['domain'],
            'found': None,
            'arguments': str(scan_info)
        })
    return

def handle_target(info):
    info = copy.deepcopy(info)
    if BURP_FOLDER and info['burp_scan']:
        print('Module Burp Scan starting against %s alive urls from %s' % (str(len(info['target'])), info['domain']))
        slack.send_module_start_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
        send_module_status_log(info, 'start')

        for url in info['target']:
            sub_info = copy.deepcopy(info)
            sub_info['target'] = url
            scan_target(sub_info)

        print('Module Burp Scan finished against %s' % info['domain'])
        slack.send_module_end_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
        send_module_status_log(info, 'end')
    return


def handle_single(info):
    info = copy.deepcopy(info)
    if BURP_FOLDER and info['burp_scan']:
        print('Module Burp Scan starting against %s' % info['target'])
        slack.send_module_start_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
        send_module_status_log(info, 'start')

        scan_target(info)

        slack.send_module_end_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
        print('Module Burp Scan finished against %s' % info['target'])
        send_module_status_log(info, 'end')
    return


def add_vulnerability(scan_info, file_string, file_dir, file_name):
    my_dict = xmltodict.parse(file_string)
    json_data = json.dumps(my_dict)
    json_data = json.loads(json_data)
    description = 'Burp scan completed against %s' % scan_info['target'] +'\n'
    try:
        for issue in json_data['issues']['issue']:
            if issue['name'] not in BURP_BLACKLIST:
                name = copy.deepcopy(constants.BURP_SCAN)
                name['english_name'] = name['english_name'] + issue['name']
                extra='Burp Request: \n'+base64.b64decode(issue['requestresponse']['request']['#text']).decode("utf-8")
                vulnerability = Vulnerability(name, scan_info, description+extra)
                vulnerability.add_file_string(file_string)
                vulnerability.add_attachment(file_dir, file_name)
                slack.send_vuln_to_channel(vulnerability, SLACK_NOTIFICATION_CHANNEL)
                redmine.create_new_issue(vulnerability)
                mongo.add_vulnerability(vulnerability)
    except KeyError:
        return


def scan_target(scan_info):
    is_burp_already_running = True
    #Check if is already a burp process running
    #if exists wait and dont run
    while is_burp_already_running:
        proc1 = subprocess.Popen(['ps','aux'],stdout=subprocess.PIPE)
        proc2 = subprocess.Popen(['grep', 'burp-rest-api.sh'], stdin=proc1.stdout,stdout=subprocess.PIPE, stderr=subprocess.PIPE)    
        proc_list = proc2.stdout.readline().decode('utf-8').split()
        if len(proc_list)>1:
            burp_fold = proc_list[len(proc_list)-1]
        else:
            burp_fold = ''
        proc1.kill()
        proc2.kill()
        if settings['BURP']['bash_folder'] != burp_fold:
            burp_process = subprocess.Popen(BURP_FOLDER, stdout=subprocess.PIPE)
            time.sleep(120)
            #GETTING PID FOR TERMINATE JAVA AFTER BURP SCAN
            pid = burp_process.stdout.readline().decode('utf-8').split()[3]
            header = {'accept': '*/*'}
            
            subprocess.run(['curl', '-k', '-x', 'http://127.0.0.1:8080', '-L', scan_info['target']],
                        capture_output=True)

            # Arrancamos agregando el url al scope
            add_to_scope_response = requests.put(add_to_scope_url % scan_info['target'], headers=header)
            if add_to_scope_response.status_code != 200:
                return
            query_scope_response = requests.get(query_in_scope_url % scan_info['target'], headers=header)
            if not query_scope_response.json()['inScope']:
                return

            spider_response = requests.post(spider_url % scan_info['target'], headers=header)
            if spider_response.status_code != 200:
                return
            spider_status_response = requests.get(spider_status_url, headers=header)
            while spider_status_response.json()['spiderPercentage'] != 100:
                spider_status_response = requests.get(spider_status_url, headers=header)
                time.sleep(1)

            passive_scan_response = requests.post(passive_scan_url % scan_info['target'], headers=header)
            if passive_scan_response.status_code != 200:
                return
            scanner_status_response = requests.get(scan_status_url, headers=header)
            while scanner_status_response.json()['scanPercentage'] != 100:
                scanner_status_response = requests.get(scan_status_url, headers=header)
                time.sleep(5)

            ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
            random_filename = uuid.uuid4().hex
            OUTPUT_DIR = ROOT_DIR + '/tools_output/' + random_filename + '.xml'

            download_response = requests.get(download_report % scan_info['target'], headers=header)

            open(OUTPUT_DIR, 'wb').write(download_response.content)
            add_vulnerability(scan_info, download_response.content,OUTPUT_DIR, 'burp_result.xml')
            
            burp_process.kill()
            os.system("kill -9 "+pid)
            is_burp_already_running = False
            try:
                os.remove(OUTPUT_DIR)
            except FileNotFoundError:
                return