from VM_Orchestrator.settings import WAPPA_KEY
from VM_OrchestratorApp.src.utils import slack, utils, mongo, image_creator, redmine
from VM_OrchestratorApp.src import constants
from VM_OrchestratorApp.src.vulnerability.vulnerability import Vulnerability

import json, requests, itertools, collections, os
from bs4 import BeautifulSoup
from datetime import datetime

endpoint = 'https://api.wappalyzer.com/lookup/v1/?url='

def get_latest_version(name):
    return mongo.find_last_version_of_librarie(name)


def get_cves_and_last_version(librarie):
    cve_list = []
    version = librarie["versions"][0] if librarie["versions"] else ""
    name = librarie["name"]
    name = "Internet Information Server" if name == "IIS" else name
    url = "https://www.cvedetails.com/version-search.php?vendor=&product=%"+name+"%&version="+version
    resp = requests.get(url)
    html = BeautifulSoup(resp.text, "html.parser")
    table_div = html.find('div', {'id': 'searchresults'})
    if table_div is not None:
        last_version = get_latest_version(name)
        table_data = []
        table_headers = [[cell.text.replace('\n', '').replace('\t', '') for cell in row("th")] for row in
                         table_div.find('table')("tr")][0]
        for row in table_div.find('table')("tr"):
            if row.has_attr('class'):
                for cell in row("td"):
                    table_data.append(cell.text.replace('\n', '').replace('\t', ''))

        len_headers = len(table_headers)
        len_data = len(table_data)
        result = collections.defaultdict(list)
        for key, val in zip(itertools.cycle(table_headers), table_data):
            result[key].append(val)
        result = json.loads(json.dumps(result))
        result = [{key: value[index] for key, value in result.items()} for index in
                  range(max(map(len, result.values())))]
        return result, last_version
    else:
        return {}, ""


def add_libraries_vulnerability(scan_info, message):
    vulnerability = Vulnerability(constants.OUTDATED_3RD_LIBRARIES, scan_info, message)
    slack.send_vulnerability(vulnerability)
    redmine.create_new_issue(vulnerability)
    mongo.add_vulnerability(vulnerability)


def fastPrint(libraries):
    message= ""
    for info in libraries:
        info_title= "Name: "+info['name']
        version = info['versions'][0] if info['versions'] else ""
        last_version = info['last_version']
        if version or last_version:
            info_title += ' Version: '+version+' Last Version :'+last_version
        message += "\t"+info_title+'\n'
        for cve in info['cves']:
            cve_info = 'CVE ID: '+cve['CVE ID']+' - Vulnerability: '+cve['Vulnerability Type(s)']+'- CVSS Score: '+cve['Score']
            message += "\t"+cve_info+'\n'
    return message


def analyze(scan_info, url_to_scan):
    target = endpoint + url_to_scan
    headers = {'x-api-key': WAPPA_KEY}
    try:
        response = requests.get(target, headers=headers)
        libraries = response.json()[0]['applications']
        for lib in libraries:
            lib['cves'], lib['last_version'] = get_cves_and_last_version(lib)

        message = fastPrint(libraries)
        add_libraries_vulnerability(scan_info,  message)
    except Exception as e:
        print(str(e))


def handle_target(info):
    if WAPPA_KEY:
        print('Module Libraries Scan starting against %s alive urls from %s' % (str(len(info['url_to_scan'])), info['domain']))
        slack.send_simple_message("Libraries scan started against target: %s. %d alive urls found!"
                                        % (info['domain'], len(info['url_to_scan'])))
        for url in info['url_to_scan']:
            sub_info = info
            sub_info['url_to_scan'] = url
            analyze(sub_info, sub_info['url_to_scan'])
        print('Module Libraries Scan finished against %s' % info['domain'])
    return


def handle_single(scan_info):
    if WAPPA_KEY:
        print('Module Libraries Scan starting against %s' % scan_info['url_to_scan'])
        slack.send_simple_message("Libraries scan started against %s" % scan_info['url_to_scan'])
        analyze(scan_info, scan_info['url_to_scan'])
        print('Module Libraries Scan finished against %s' % scan_info['url_to_scan'])
    return
