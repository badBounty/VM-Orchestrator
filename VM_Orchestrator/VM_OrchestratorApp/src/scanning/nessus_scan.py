from VM_OrchestratorApp.src.utils import slack, mongo, redmine
from VM_OrchestratorApp.src import constants
from VM_OrchestratorApp.src.objects.vulnerability import Vulnerability
from VM_Orchestrator.settings import settings,nessus,nessus_info

import time
import requests
import copy
import json
import re
import uuid

MODULE_NAME = 'Nessus module'
SLACK_NOTIFICATION_CHANNEL = '#vm-nessus'

username = nessus_info['USER']
password = nessus_info['PASSWORD']
verify = False
json_scan = {}
# POST - LOGIN
login_url = nessus_info['URL']+'/session'
# POST - CREATE SCAN
create_url = nessus_info['URL']+'/scans'
# GET - SCAN STATUS
scan_url = nessus_info['URL']+'/scans/'
# POST - STOP -- URL/scans/{SCAN_ID}/stop

header = {'X-Cookie':'',
            'X-API-Token':nessus_info['API'],
            'Content-Type':'application/json'
        }
def perform_login():
    r = requests.post(login_url,data={'username':username,'password':password},verify=verify)
    return 'token='+json.loads(r.text)['token']

def get_only_url(url):
    split_url = url.split('/')
    try:
        return split_url[2]
    except IndexError:
        return url

def is_not_ip(url):
    clean = get_only_url(url)
    pat = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    return not pat.match(clean)

def handle_target(info):
    if info['nessus_scan'] and nessus:
        print('Module Nessus Scan starting against %s alive urls from %s' % (str(len(info['url_to_scan'])), info['domain']))
        slack.send_module_start_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
        targets = len(info['url_to_scan'])
        if targets > 0:
            url_list = info['url_to_scan']
            divider = targets//2
            #Plain list for nessus scan
            urls = ','.join(get_only_url(l) for l in url_list[divider:])
            sub_info = info
            sub_info['url_to_scan'] = url_list[divider:]
            sub_info['nessus_target'] = urls
            scan_target(sub_info)
            #Plain list for nessus scan
            urls = ','.join(get_only_url(l) for l in url_list[:divider])
            sub_info = info
            sub_info['url_to_scan'] = url_list[:divider]
            sub_info['nessus_target'] = urls
            scan_target(sub_info)
        slack.send_module_end_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
        print('Module Nessus Scan Finished against %s alive urls from %s' % (str(len(targets)), info['domain']))
    return


def handle_single(info):
    if info['nessus_scan'] and nessus and is_not_ip(info['url_to_scan']):
        print('Module Nessus Single Scan Starting against %s' % info['url_to_scan'])
        slack.send_module_start_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
        url_plain = get_only_url(info['url_to_scan'])
        info['nessus_target'] = url_plain
        info['url_to_scan'] = list().append(info['url_to_scan'])
        scan_target(info)
        slack.send_module_end_notification_to_channel(info, MODULE_NAME, SLACK_NOTIFICATION_CHANNEL)
        print('Module Nessus Scan Finished against %s' % info['nessus_target'])
    else:
        pass
        #print('Scan not started: the url was an IP number or couldn\'t connect to the nessus server')
    return

def add_vulnerability(scan_info,json_data,header):
    #Save the list of urls scanned  
    l = scan_info['url_to_scan']
    scan_id = str(json_data['info']['object_id'])
    for nessus_hosts in json_data['hosts']:
        #Get the vulnerabilities for the scanned host
        r = requests.get(scan_url+scan_id+'/hosts/'+str(nessus_hosts['host_id']),verify=verify,headers=header) 
        for host_vuln in json.loads(r.text)['vulnerabilities']:
            #Only update the vulnerabilities with severity medium or more
            if host_vuln['severity'] >= nessus_info['WHITE_LIST_SEVERITY'] and host_vuln['plugin_name'] not in nessus_info['BLACK_LIST']:
                name = copy.deepcopy(constants.NESSUS_SCAN)
                name['english_name'] = name['english_name'] + host_vuln['plugin_name']
                plug_id = str(host_vuln['plugin_id'])
                #Get full detail of the vulnerability
                r = requests.get(scan_url+scan_id+'/plugins/'+plug_id,verify=verify,headers=header)
                out_list = json.loads(r.text)['outputs']
                extra = ''
                for out in out_list:
                    extra = (out['plugin_output'] if out['plugin_output'] != None else '')+'\n'
                    extra +=str(out['ports'])
                for url in l:
                    if host_vuln['hostname'] in url:
                        scan_info['url_to_scan'] = url
                description = 'Nessus scan completed against %s' % scan_info['url_to_scan'] +'\n'
                vulnerability = Vulnerability(name, scan_info, description+extra)
                slack.send_vuln_to_channel(vulnerability, SLACK_NOTIFICATION_CHANNEL)
                redmine.create_new_issue(vulnerability)
                mongo.add_vulnerability(vulnerability)

def scan_target(scan_info):
    scan_name = settings['PROJECT']['NAME']+'-'+uuid.uuid4().hex
    #Connect to the nessus
    token = perform_login()
    # Getting the session token
    header['X-Cookie']=token
    # Create the scan
    json_scan =  {
        'uuid':nessus_info['SCAN_TEMPLATE'],
        'settings':{'launch_now':False,
                'enabled':False,
                'text_targets':scan_info['nessus_target'],
                'policy_id':'170',
                'scanner_id':'1',
                'folder_id':int(nessus_info['FOLDER_ID']),
                'description':'Scan created and launched via orchestrator',
                'name':scan_name
                }
        }
    # Creating the scan and getting the id for the launching
    r = requests.post(create_url,data=json.dumps(json_scan,separators=(',', ':')),verify=verify,headers=header)
    # Getting the scan id for launch the scan
    scan_id = str(json.loads(r.text)['scan']['id'])
    #Launch the scan
    launch_url = nessus_info['URL']+'/scans/'+scan_id+'/launch'
    r = requests.post(launch_url,verify=verify,headers=header)
    #Monitoring the scan until it's finished
    scan_status = 'running'
    while scan_status == 'running':
        time.sleep(180)
        resp = requests.get(scan_url+scan_id,verify=verify,headers=header)
        json_scan = json.loads(resp.text)
        #Credentials expired getting new ones
        try:
            json_scan['error']
            token = perform_login()
            # Getting the session token
            header['X-Cookie']=token
            resp = requests.get(scan_url+scan_id,verify=verify,headers=header)
            json_scan = json.loads(resp.text)
        except KeyError:
            pass
        scan_status = json_scan['info']['status']
    if json_scan['info']['status'] == 'completed':
        add_vulnerability(scan_info, json_scan,header)
    else:
        print('The scan with id: '+scan_id+' has been paused or stopped go to nessus and checked manually')
