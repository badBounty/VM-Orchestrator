# pylint: disable=import-error
from VM_OrchestratorApp.src.utils import slack, mongo, redmine
from VM_OrchestratorApp.src import constants
from VM_OrchestratorApp.src.objects.vulnerability import Vulnerability
from VM_Orchestrator.settings import acunetix,acunetix_info
from collections import defaultdict

import time
import requests
import json
import re
import copy

MODULE_NAME = 'Acunetix module'

MODULE_IDENTIFIER = 'acu_module'
SLACK_NOTIFICATION_CHANNEL = '#vm-acunetix'

login_json = {
    'email':acunetix_info['USER'],
    'password':acunetix_info['PASSWORD_HASH'],
    'remember_me':acunetix_info['REMEMBER_ME'],
    'logout_previous':acunetix_info['LOGOUT_PREVIOUS']
}
headers = {
    'X-auth':'',
    'X-Cookie':''
}
verify = False
#Changes according to the acunetix license key
max_scans_possible = acunetix_info['MAX_SCANS_POSSIBLE']
profile_id = acunetix_info['SCAN_PROFILE']
ui_session_id = acunetix_info['UI_SESSION_ID']
basic_url = acunetix_info['URL']
#LOGIN - POST
login_url = '/api/v1/me/login'
#TARGET - IF POST -> CREATE
target_url = '/api/v1/targets'
#LAUNCH / START SCAN - POST -- IF GET -> Obtains the scans running
launch_scan_url = '/api/v1/scans'

def send_module_status_log(scan_info, status):
    mongo.add_module_status_log({
            'module_keyword': MODULE_IDENTIFIER,
            'state': status,
            'domain': scan_info['domain'],
            'found': None,
            'arguments': scan_info
        })
    return

def is_url(url):
    split_url = url.split('/')
    try:
        url = split_url[2]
        return True
    except IndexError:
        return False

def already_exists(url,l1):
    for l in l1:
        if url in l:
            return True
    return False

def remove_duplicates_if_exists(url_list):
    final_list = list()
    for url in url_list:
        creal_url = url.split('/')[2]
        if not already_exists(creal_url,final_list):
            final_list.append(url)
    return final_list


def handle_target(info):
    info_copy = copy.deepcopy(info)
    if info_copy['acunetix_scan'] and acunetix:

        print('Module Acunetix Scan starting against %s alive urls from %s' % (str(len(info_copy['target'])), info_copy['domain']))
        slack.send_module_start_notification_to_channel(info_copy, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
        send_module_status_log(info_copy, 'start')

        #We can have repeated urls differenced by http o https so we get only one (The https one's)
        full_list = remove_duplicates_if_exists(sorted(info_copy['target'],reverse=True))
        info_for_scan = copy.deepcopy(info_copy)
        info_for_scan['target'] = full_list
        scan_target(info_for_scan)
        
        print('Module Acunetix Scan Finished against %s alive urls from %s' % (str(len(full_list)), info_copy['domain']))
        slack.send_module_end_notification_to_channel(info_copy, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
        send_module_status_log(info_copy, 'end')
    return


def handle_single(info):
    info_copy = copy.deepcopy(info)
    if info_copy['acunetix_scan'] and acunetix and is_url(info_copy['target']):
        print('Module Acunetix Single Scan Starting against %s' % info_copy['target'])
        slack.send_module_start_notification_to_channel(info_copy, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
        send_module_status_log(info_copy, 'start')

        urls = [info_copy['target']]
        info_copy['target'] = urls
        scan_target(info_copy)

        print('Module Acunetix Single Scan Finished against %s' % info_copy['target'])
        slack.send_module_end_notification_to_channel(info_copy, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
        send_module_status_log(info_copy, 'end')
    return

def add_vulnerability(scan_info,scan_id,vulns):
    info = copy.deepcopy(scan_info)
    info['target'] = scan_id[1]
    default_dict = defaultdict(list)
    default_dict_extra = defaultdict(list)
    for vul in vulns:
        default_dict[vul['vt_name']].append(vul['affects_url'])
        default_dict_extra[vul['vt_name']].append(vul['request'])
    result = [{"title": k, "resourceAf": v} for k, v in default_dict.items()]
    result_extra = [{"title": k, "request_info": v} for k, v in default_dict_extra.items()]
    for r, re in zip(result, result_extra):
        r['request_info'] = re['request_info'][0]
    for res in result:
        #Checking if is not a vulnerability already reported by other tool
        if res['title'] not in acunetix_info['BLACK_LIST']:
            affected_urls = ('\n'.join(res['resourceAf'])+'\n'+''.join(res['request_info']))
            name = copy.deepcopy(constants.ACUNETIX_SCAN)
            name['english_name'] = name['english_name'] + res['title']
            description = 'Acunetix scan completed against %s' % info['target'] +'\n Affecteds URLS>'
            vulnerability = Vulnerability(name, info, description+affected_urls)
            slack.send_vuln_to_channel(vulnerability, SLACK_NOTIFICATION_CHANNEL)
            vulnerability.id = mongo.add_vulnerability(vulnerability)
            redmine.create_new_issue(vulnerability)
    return

def start_acu_scan(scan_info,headers,session):
    id_list = list()
    for url in scan_info['target']:        
        target_json = {'address':url,
                        'description':'Created by orchestrator'
            }
        #Creating target to scan
        r = session.post(basic_url+target_url,json=target_json,verify=verify,headers=headers)
        target_id = json.loads(r.text)['target_id']
        scan_json = {'target_id':target_id,
                'profile_id':profile_id,
                'schedule':{'disable':False,'start_date':None,'time_sensitive':False},
                'ui_session_id':ui_session_id
                }
        #Creating scan and launch it
        r = session.post(basic_url+launch_scan_url,json=scan_json,verify=verify,headers=headers)
        scan_url_with_id = r.headers['Location']
        tup = (scan_url_with_id,url)
        id_list.append(tup)
    return id_list

def check_acu_status_and_create_vuln(scan_info,id_list,headers,session):
    all_finished = False
    #Check the status of each scan
    time.sleep(10)
    while not all_finished:
        for scan_id in id_list:
            scan_url_with_id = scan_id[0]
            #Getting status of the project
            r = session.get(basic_url+scan_url_with_id,verify=verify,headers=headers)
            json_scan = json.loads(r.text)
            #Just in case we get disconnected from some reason
            try:
                json_scan['code']
                if json_scan['message'] == 'Unauthorized':
                    r = session.post(basic_url+login_url,json=login_json,verify=verify)
                    #Get login values
                    headers['X-Auth'] = r.headers['X-Auth']
                    headers['X-Cookie'] = r.headers['Set-Cookie']
                    r = session.get(basic_url+scan_url_with_id,verify=verify,headers=headers)
                    json_scan = json.loads(r.text)
            except KeyError:
                pass
            status_scan = json_scan['current_session']['status']
            scan_session_id = ''
            if status_scan != 'processing' and status_scan != 'completed':
                id_list.remove(scan_id)
            elif status_scan == 'completed':
                
                target_id = json_scan['target_id']
                #Scan finished getting vulnerabilities
                id_list.remove(scan_id)
                scan_session_id = json_scan['current_session']['scan_session_id']
                vulns_scan_url = scan_url_with_id+'/results/{}/vulnerabilities'.format(scan_session_id)
                r = session.get(basic_url+vulns_scan_url,verify=verify,headers=headers)
                vulns = json.loads(r.text)['vulnerabilities']
                final_vulns = list()
                #White listing the vulnerabilties
                for vul in vulns:
                    if vul['severity'] >= acunetix_info['WHITE_LIST_SEVERITY']:
                        vuln_complete = scan_url_with_id+'/results/{}/vulnerabilities/{}'.format(scan_session_id,vul['vuln_id'])
                        #Get Requests from vulnerability
                        r = session.get(basic_url+vuln_complete,verify=verify,headers=headers)
                        vuln_request = json.loads(r.text)['request']
                        #Adding request info to vul
                        vul['request'] = vuln_request
                        final_vulns.append(vul)
                add_vulnerability(scan_info,scan_id, final_vulns)
                #Deleting target after scan is performed
                session.delete(basic_url+target_url+'/'+target_id,verify=verify,headers=headers)
        time.sleep(180)
        if len(id_list) == 0:
            all_finished = True
    return 

def check_if_scan_is_possible(headers,session):
    try:
        #Get already runned scans
        r = session.get(basic_url+launch_scan_url,verify=verify,headers=headers)
        json_scan = json.loads(r.text)
        #Just in case we get disconnected for some reason   
        try:
            json_scan['code']
            if json_scan['message'] == 'Unauthorized':
                r = session.post(basic_url+login_url,json=login_json,verify=verify)
                #Get login values
                headers['X-Auth'] = r.headers['X-Auth']
                headers['X-Cookie'] = r.headers['Set-Cookie']
                r = session.get(basic_url+launch_scan_url,verify=verify,headers=headers)
                json_scan = json.loads(r.text)
        except KeyError:
                pass
        try:
            scans_running = len(json_scan['scans'])
        except KeyError:
            return False,0
        if scans_running < max_scans_possible:
            #We can launch a scan
            return True,max_scans_possible if scans_running == 0 else (max_scans_possible-scans_running)
        else:
            return False,0
    except requests.exceptions.ReadTimeout:
        return False,0

def scan_target(scan_info):
    wait_until_its_free = True
    session = requests.Session()
    #Login against acunetix
    r = session.post(basic_url+login_url,json=login_json,verify=verify)
    #Get login values
    headers['X-Auth'] = r.headers['X-Auth']
    headers['X-Cookie'] = r.headers['Set-Cookie']
    while wait_until_its_free:
        is_possible,scans_number = check_if_scan_is_possible(headers,session)
        if is_possible:
            for i in range(0,len(scan_info['target']),scans_number):
                url_to_scan = scan_info['target'][i:i+scans_number]
                info_for_scan = copy.deepcopy(scan_info)
                info_for_scan['target'] = url_to_scan
                id_list = start_acu_scan(scan_info,headers,session)                
                check_acu_status_and_create_vuln(scan_info, id_list,headers,session)
            wait_until_its_free = False
        else:
            #Acunetix is busy send notifications via slack - redmine ??
            pass
    return
