# pylint: disable=import-error
from VM_OrchestratorApp import MONGO_CLIENT
from VM_Orchestrator.settings import settings
from VM_Orchestrator.settings import REDMINE_IDS
from VM_Orchestrator.settings import MONGO_INFO
from VM_OrchestratorApp import ELASTIC_CLIENT
from VM_OrchestratorApp.src.utils import slack, redmine, utils

from datetime import datetime
import json
import ast
import urllib3

domains = MONGO_CLIENT[MONGO_INFO['DATABASE']][MONGO_INFO['DOMAINS_COLLECTION']]
logs = MONGO_CLIENT[MONGO_INFO['DATABASE']][MONGO_INFO['LOGS_COLLECTION']]
resources = MONGO_CLIENT[MONGO_INFO['DATABASE']][MONGO_INFO['RESOURCES_COLLECTION']]
observations = MONGO_CLIENT[MONGO_INFO['DATABASE']][MONGO_INFO['OBSERVATIONS_COLLECTION']]
vulnerabilities = MONGO_CLIENT[MONGO_INFO['DATABASE']][MONGO_INFO['VULNERABILITIES_COLLECTION']]
libraries_versions = MONGO_CLIENT[MONGO_INFO['DATABASE']][MONGO_INFO['LIBRARIES_COLLECTION']]

def add_vulnerability(vulnerability):
    exists = vulnerabilities.find_one({'domain': vulnerability.domain, 'resource': vulnerability.target,
                                          'vulnerability_name': vulnerability.vulnerability_name,
                                          'language': vulnerability.language})
    if exists:
        vulnerabilities.update_one({'_id': exists.get('_id')}, {'$set': {
            'extra_info': vulnerability.custom_description,
            'last_seen': vulnerability.time,
            'image_string': vulnerability.image_string,
            'file_string': vulnerability.file_string,
            'state': 'new' if exists['state'] != 'rejected' else exists['state']
        }})
    else:
        resource = {
            'domain': vulnerability.domain,
            'resource': vulnerability.target,
            'vulnerability_name': vulnerability.vulnerability_name,
            'observation': vulnerability.get_json_observation(),
            'extra_info': vulnerability.custom_description,
            'image_string': vulnerability.image_string,
            'file_string': vulnerability.file_string,
            'date_found': vulnerability.time,
            'last_seen': vulnerability.time,
            'language': vulnerability.language,
            'cvss_score': vulnerability.cvss,
            'vuln_type': vulnerability.vuln_type,
            'state': 'new'
        }
        vuln_id = vulnerabilities.insert_one(resource)
        resource['_id'] = str(vuln_id.inserted_id)
        add_found_vulnerability_log(resource, vulnerability)
        add_vuln_to_elastic(resource)
    return


# For flagging resources as "scanned"
def add_scanned_resources(scan_information_received):
    if scan_information_received['type'] == 'domain':
        for url in scan_information_received['target']:
            resource = resources.find_one({'domain': scan_information_received['domain'], 'subdomain': url, 'scanned': False, 'type': scan_information_received['type']})
            if resource is not None:
                resources.update_one({'_id': resource.get('_id')},
                {'$set': 
                    {
                    'scanned': True
                    }})
    else:
        if scan_information_received['type'] == 'url':
            #Url case, we search for url from mongo
            resource = resources.find_one({'domain': scan_information_received['domain'], 'url': scan_information_received['target'], 'scanned': False, 'type': scan_information_received['type']})
        else:
            #IP case, we will search for ip here instead of url
            resource = resources.find_one({'domain': scan_information_received['domain'], 'ip': scan_information_received['target'], 'scanned': False, 'type': scan_information_received['type']})
        if resource is not None:
            resources.update_one({'_id': resource.get('_id')},
            {'$set': 
                {
                'scanned': True
                }})

# Removing the scanned flag on all resources
def remove_scanned_flag():
    cursor = resources.find({})
    for document in cursor:
        resources.update_one({'_id': document.get('_id')}, {'$set': {
            'scanned': False
        }})

# This will return every url with http/https
def get_responsive_http_resources(target):
    subdomains = resources.find({'domain': target, 'has_urls': True, 'scanned': False, 'approved': True, 'is_alive': 'True'})
    subdomain_list = list()
    for subdomain in subdomains:
        valid_urls_found = utils.get_distinct_urls(subdomain['url'])
        for url_with_http in valid_urls_found:
            if url_with_http:
                current_subdomain = {
                    'domain': subdomain['domain'],
                    'ip': subdomain['ip'],
                    'subdomain': subdomain['subdomain'],
                    'url': url_with_http
                }
                subdomain_list.append(current_subdomain)
    return subdomain_list

# Searches for vulnerability information in observations collection
def get_observation_for_object(vuln_name,language):
    finding_kb = observations.find_one({'TITLE': vuln_name, 'LANGUAGE': language})
    return finding_kb

# Returns a list similar to the one generated by the start csv file
def get_data_for_approved_scan():
    all_data = resources.find({'approved': True, 'scanned': False})
    information = list()
    for data in all_data:
        if data['type'] == 'url':
            resource = data['url']
        elif data['type'] == 'ip':
            resource = data['ip']
        else:
            resource = data['domain']
        information.append({
            'is_first_run': False,
            'invasive_scans': False,
            'language': settings['LANGUAGE'],
            'type': data['type'],
            'priority': data['priority'],
            'exposition': data['exposition'],
            'domain': data['domain'],
            'resource': resource
        })
    import pandas as pd
    info_to_return = pd.DataFrame(information).drop_duplicates().to_dict('records')

    return info_to_return


def find_last_version_of_librarie(name):
    librarie = libraries_versions.find({'name':name})
    if librarie.count() != 0:
        return librarie[0]['version']
    else:
        return ''

def approve_resources(info):
    for resource in info['data']:
        exists = resources.find_one({'domain': resource['domain'], 'subdomain': resource['subdomain'], 'type':resource['type']})
        if not exists:
            print('RESOURCE %s FROM %s WAS IN THE CSV BUT NOT IN OUR DATABASE. ADDING' % (resource['subdomain'], resource['domain']))
            new_resource = {
                'domain': resource['domain'],
                'subdomain': resource['subdomain'],
                'url': ast.literal_eval(resource['url']),
                'ip': resource['ip'],
                'additional_info':{
                    'isp': resource['isp'],
                    'asn': resource['asn'],
                    'country': resource['country'],
                    'region': resource['region'],
                    'city': resource['city'],
                    'org': resource['org'],
                    'geoloc': resource['geoloc']
                },
                'first_seen': datetime.now(),
                'last_seen': datetime.now(),
                'is_alive': resource['is_alive'],
                'has_urls': resource['has_urls'],
                'approved': resource['approved'],
                'type': resource['type'],
                'priority': resource['priority'],
                'exposition': resource['exposition'],
                'asset_value': resource['asset_value'],
                'nmap_information': None,
                'scanned': False
            }
            resources.insert_one(new_resource)
            continue
        resources.update_one({'_id': exists.get('_id')},
         {'$set': 
            {
            'approved': resource['approved'],
            'priority': resource['priority'],
            'exposition': resource['exposition'],
            'asset_value': resource['asset_value']
            }})

# ------------------- RECON -------------------
def add_simple_url_resource(scan_info):
    exists = resources.find_one({'domain': scan_info['domain'], 'url': scan_info['resource']})
    timestamp = datetime.now()
    if not exists:
        resource ={
                'domain': scan_info['domain'],
                'subdomain': None,
                'url': [{'url': scan_info['resource']}],
                'ip': None,
                'is_alive': True,
                'additional_info':{
                    'isp': None,
                    'asn': None,
                    'country': None,
                    'region': None,
                    'city': None,
                    'org': None,
                    'geoloc': '0 , 0'
                },
                'first_seen': timestamp,
                'last_seen': timestamp,
                'scanned': False,
                'type': scan_info['type'],
                'priority': scan_info['priority'],
                'exposition': scan_info['exposition'],
                'asset_value': None,
                'has_urls': False,
                'nmap_information': None,
                'approved': False,
        }
        resources.insert_one(resource)
    else:
        resources.update_one({'_id': exists.get('_id')},
         {'$set': 
            {
            'last_seen': timestamp
            }})

def add_simple_ip_resource(scan_info):
    exists = resources.find_one({'domain': scan_info['domain'], 'ip': scan_info['resource']})
    timestamp = datetime.now()
    if not exists:
        resource ={
                'domain': scan_info['domain'],
                'subdomain': None,
                'url': None,
                'ip': scan_info['resource'],
                'is_alive': True,
                'additional_info':{
                    'isp': None,
                    'asn': None,
                    'country': None,
                    'region': None,
                    'city': None,
                    'org': None,
                    'geoloc': '0 , 0'
                },
                'first_seen': timestamp,
                'last_seen': timestamp,
                'scanned': False,
                'type': scan_info['type'],
                'priority': scan_info['priority'],
                'exposition': scan_info['exposition'],
                'asset_value': None,
                'has_urls': False,
                'nmap_information': None,
                'approved': False,
        }
        resources.insert_one(resource)
    else:
        resources.update_one({'_id': exists.get('_id')},
         {'$set': 
            {
            'last_seen': timestamp
            }})

def add_resource(url_info, scan_info):
    # This makes it so only subdomains containing the domain will be added
    domain_with_dot = '.'+url_info['domain']
    if domain_with_dot not in url_info['subdomain']:
        return
    exists = resources.find_one({'domain': url_info['domain'], 'subdomain': url_info['subdomain']})
    timestamp = datetime.now()
    ip = url_info['ip']
    if ip is not None:
        #Rare case in which an IP is actually a string
        if not ip.split('.')[0].isnumeric():
            ip = None
    if not exists:
        resource ={
                'domain': url_info['domain'],
                'subdomain': url_info['subdomain'],
                'url': '',
                'ip': ip,
                'is_alive': url_info['is_alive'],
                'additional_info':{
                    'isp': url_info['isp'],
                    'asn': url_info['asn'],
                    'country': url_info['country'],
                    'region': url_info['region'],
                    'city': url_info['city'],
                    'org': url_info['org'],
                    'geoloc': '%s , %s' % (str(url_info['lat']),str(url_info['lon']))
                },
                'first_seen': timestamp,
                'last_seen': timestamp,
                'scanned': False,
                'type': scan_info['type'],
                'priority': "50",
                'exposition': None,
                'asset_value': None,
                'has_urls': False,
                'nmap_information': None,
                'approved': False,
        }
        if not scan_info['is_first_run']:
            slack.send_new_resource_found("New resource found! %s" % url_info['subdomain'], '#vm-recon-module')
        resource_id = resources.insert_one(resource)
        resource['_id'] = str(resource_id.inserted_id)
        module_keyword = 'on_demand_recon_module' if scan_info['is_first_run'] else 'monitor_recon_module'
        add_resource_found_log(resource, module_keyword)
        add_resource_to_elastic(resource)
    else:
        resources.update_one({'_id': exists.get('_id')},
         {'$set': 
            {
            'is_alive': url_info['is_alive'],
            'ip': ip,
            'additional_info':{
                    'isp': url_info['isp'],
                    'asn': url_info['asn'],
                    'country': url_info['country'],
                    'region': url_info['region'],
                    'city': url_info['city'],
                    'org': url_info['org'],
                    'geoloc': '%s , %s' % (str(url_info['lat']),str(url_info['lon']))
                },
            'last_seen': timestamp
            }})
    return

#Returns resolved vulnerabilities
def get_resolved_vulnerabilities():
    vulns = vulnerabilities.find({'state': 'resolved'})
    return vulns

# Returns a list similar to the one generated by the start csv file
def get_domains_for_monitor():
    found = domains.find()
    return_list = list()
    for domain in found:
        return_list.append({'domain': domain['domain']})
    return return_list

def add_domain(scan_info):
    exists = domains.find_one({'domain': scan_info['domain']})
    if not exists:
        domains.insert_one({'domain': scan_info['domain']})

def get_alive_subdomains_from_target(target):
    subdomains = resources.find({'domain': target, 'is_alive': 'True', 'scanned': False, 'approved': True})
    subdomain_list = list()
    for subdomain in subdomains:
        current_subdomain = {
            'domain': subdomain['domain'],
            'subdomain': subdomain['subdomain']
        }
        subdomain_list.append(current_subdomain)
    return subdomain_list

def get_alive_subdomains_for_resolve(target):
    subdomains = resources.find({'domain': target, 'is_alive': 'True', 'scanned': False})
    subdomain_list = list()
    for subdomain in subdomains:
        current_subdomain = {
            'domain': subdomain['domain'],
            'subdomain': subdomain['subdomain']
        }
        subdomain_list.append(current_subdomain)
    return subdomain_list

def get_nmap_web_interfaces(scan_info):
    resource = resources.find_one({'domain': scan_info['domain'], 'ip': scan_info['resource'], 'type': scan_info['type']})
    to_send = list()
    if type(resource['nmap_information']) != list:
        if resource['nmap_information']['@portid'] == '80':
            to_send.append('http://'+scan_info['resource'])
        if resource['nmap_information']['@portid'] == '443':
            to_send.append('https://'+scan_info['resource'])
        return to_send
    else:
        for information in resource['nmap_information']:
            if information['@portid'] == '80':
                to_send.append('http://'+scan_info['resource'])
            if information['@portid'] == '443':
                to_send.append('https://'+scan_info['resource'])
    return to_send

def add_urls_from_aquatone(subdomain, has_urls, url_list):
    subdomain = resources.find_one({'subdomain': subdomain})
    resources.update_one({'_id': subdomain.get('_id')}, {'$set': {
        'has_urls': has_urls,
        'url': url_list}})
    return

def add_urls_from_httprobe(subdomain, url_to_add):
    subdomain = resources.find_one({'subdomain': subdomain['subdomain']})
    dict_to_add = {'url': url_to_add}
    if subdomain['url'] is None:
        list_to_add = list()
        list_to_add.append(dict_to_add)
        resources.update_one({'_id': subdomain.get('_id')}, {'$set': {
            'has_urls': True,
            'url': list_to_add}})
        return
    if dict_to_add not in subdomain['url']:
        new_list = subdomain['url']
        new_list.append(dict_to_add)    
        resources.update_one({'_id': subdomain.get('_id')}, {'$set': {
            'has_urls': True,
            'url': new_list}})
    return

def add_images_to_subdomain(subdomain, http_image, https_image):
    subdomain = resources.find_one({'subdomain': subdomain})
    resources.update_one({'_id': subdomain.get('_id')}, {'$set': {
        'http_image': http_image,
        'https_image': https_image}})
    return

def add_nmap_information_to_subdomain(scan_information, nmap_json):
    if scan_information['type'] == 'ip':
        resource = resources.find_one({'domain': scan_information['domain'], 'ip': scan_information['target']})
    elif scan_information['type'] == 'url':
        resource = resources.find_one({'domain': scan_information['domain'], 'url': scan_information['target']})
    else:
        resource = resources.find_one({'domain': scan_information['domain'], 'subdomain': scan_information['target']})
    if not resource:
        print('ERROR adding nmap information to resource, resource not found')
        return
    resources.update_one({'_id': resource.get('_id')},
         {'$set': 
            {
                'nmap_information': nmap_json
            }})
    #This is the one that we just updated
    resource_to_update_elastic = resources.find_one({'_id': resource.get('_id')})
    add_resource_to_elastic(resource_to_update_elastic)
    return

def add_custom_redmine_issue(redmine_issue):
    #We are going to suppose the resource exists on our local database
    #We will check first and send an exception if its not found
    resource_exists = resources.find_one({'domain': redmine_issue.custom_fields.get(REDMINE_IDS['DOMAIN']).value,
     'subdomain': redmine_issue.custom_fields.get(REDMINE_IDS['RESOURCE']).value})
    if not resource_exists:
        print('Failed adding custom redmine resource. Domain %s, resource %s' % 
        (redmine_issue.custom_fields.get(REDMINE_IDS['DOMAIN']).value,redmine_issue.custom_fields.get(REDMINE_IDS['RESOURCE']).value))
        return
    vuln_status = 'new'
    status = redmine_issue.status.name
    if status == 'Remediada':
        vuln_status = 'resolved'
    elif status == 'Cerrada':
        vuln_status = 'closed'
    elif status == 'Confirmada':
        vuln_status = 'confirmed'
    elif status == 'Rechazada':
        vuln_status = 'rejected'

    vuln_to_add = {
        'domain': redmine_issue.custom_fields.get(REDMINE_IDS['DOMAIN']).value,
        'resource': redmine_issue.custom_fields.get(REDMINE_IDS['RESOURCE']).value,
        'vulnerability_name': redmine_issue.subject,
        'observation': None, # TODO we will add observation in the future
        'extra_info': redmine_issue.description,
        'image_string': None,
        'file_string': None,
        'date_found': datetime.now(),
        'last_seen': datetime.now(),
        'language': None,
        'cvss_score': redmine_issue.custom_fields.get(REDMINE_IDS['CVSS_SCORE']).value,
        'state': vuln_status
    }
    vulnerabilities.insert_one(vuln_to_add)
    return


def update_issue_if_needed(redmine_issue):
    target = redmine_issue.custom_fields.get(REDMINE_IDS['DOMAIN']).value
    vuln_name = redmine_issue.subject
    scanned_url = redmine_issue.custom_fields.get(REDMINE_IDS['RESOURCE']).value
    cvss_score = redmine_issue.custom_fields.get(REDMINE_IDS['CVSS_SCORE']).value
    status = redmine_issue.status.name

    vulnerability = vulnerabilities.find_one({'vulnerability_name': vuln_name,
    'domain': target, 'resource': scanned_url})

    # This means the vuln is in redmine but not on our local database
    if not vulnerability:
        add_custom_redmine_issue(redmine_issue)
        return

    vulnerabilities.update_one({'_id': vulnerability.get('_id')}, {'$set': {
            'cvss_score': cvss_score 
        }})

    if status == 'Remediada':
        vulnerabilities.update_one({'_id': vulnerability.get('_id')}, {'$set': {
            'state': 'resolved' 
        }})
    elif status == 'Cerrada':
        vulnerabilities.update_one({'_id': vulnerability.get('_id')}, {'$set': {
            'state': 'closed' 
        }})
    elif status == 'Confirmada':
        vulnerabilities.update_one({'_id': vulnerability.get('_id')}, {'$set': {
            'state': 'confirmed' 
        }})
    elif status == 'Rechazada':
        vulnerabilities.update_one({'_id': vulnerability.get('_id')}, {'$set': {
            'state': 'rejected' 
        }})
    return

###### ELASTICSEARCH ######
def update_elasticsearch():
    new_resources = resources.find()
    resources_list = list()
    for resource in new_resources:
        resource_url = None
        if resource['url'] is not None:
            for url in resource['url']:
                resource_url = url['url']
                if 'https' in url['url']:
                    break

        resources_list.append({
            'resource_id': str(resource['_id']),
            'resource_domain': resource['domain'],
            'resource_subdomain': resource['subdomain'],
            'resource_ip': resource['ip'],
            'resource_is_alive': False if resource['is_alive'] == "False" else True,
            'resource_additional_info':{
                'resource_isp': resource['additional_info']['isp'],
                'resource_asn': resource['additional_info']['asn'],
                'resource_country': resource['additional_info']['country'],
                'resource_region': resource['additional_info']['region'],
                'resource_city': resource['additional_info']['city'],
                'resource_org': resource['additional_info']['org'],
                'resource_geoloc': '0 , 0' if resource['additional_info']['geoloc'] == 'None , None' else resource['additional_info']['geoloc']
                },
            'resource_first_seen': resource['first_seen'],
            'resource_last_seen': resource['last_seen'],
            'resource_scanned': bool(resource['scanned']),
            'resource_type': resource['type'],
            'resource_priority': resource['priority'],
            'resource_exposition': resource['exposition'],
            'resource_asset_value': resource['asset_value'],
            'resource_has_urls': bool(resource['has_urls']),
            'resource_responsive_urls': resource_url,
            'resource_nmap_information': resource['nmap_information']
        })

    ### VULNS ###
    new_vulnerabilities = vulnerabilities.find()
    vulnerabilities_list = list()
    for vuln in new_vulnerabilities:
        if not vuln['observation']:
            observation_data = {
                    'vulnerability_title': None,
                    'vulnerability_observation_title': None,
                    'vulnerability_observation_note': None,
                    'vulnerability_implication': None,
                    'vulnerability_recommendation_title': None,
                    'vulnerability_recommendation_note': None,
                    'vulnerability_severity': None
                }
        else:
            observation_data = {
                    'vulnerability_title': vuln['observation']['title'],
                    'vulnerability_observation_title': vuln['observation']['observation_title'],
                    'vulnerability_observation_note': vuln['observation']['observation_note'],
                    'vulnerability_implication': vuln['observation']['implication'],
                    'vulnerability_recommendation_title': vuln['observation']['recommendation_title'],
                    'vulnerability_recommendation_note': vuln['observation']['recommendation_note'],
                    'vulnerability_severity': vuln['observation']['severity']
                }
        vulnerabilities_list.append({
                'vulnerability_id': str(vuln['_id']),
                'vulnerability_domain': vuln['domain'],
                'vulnerability_subdomain': vuln['resource'],
                'vulnerability_vulnerability_name': vuln['vulnerability_name'],
                'vulnerability_observation': observation_data,
                'vulnerability_extra_info': vuln['extra_info'],
                'vulnerability_date_found': vuln['date_found'],
                'vulnerability_last_seen': vuln['last_seen'],
                'vulnerability_language': vuln['language'],
                'vulnerability_cvss_score': vuln['cvss_score'],
                'vulnerability_cvss3_severity': resolve_severity(vuln['cvss_score']),
                'vulnerability_vuln_type': vuln['vuln_type'],
                'vulnerability_state': vuln['state']
            })

    if ELASTIC_CLIENT is None:
        return 
    # Connect to the elastic cluster
    print('Adding resources to elasticsearch')
    for resource in resources_list:
        res = ELASTIC_CLIENT.index(index='resources',doc_type='_doc',id=resource['resource_id'],body=resource)
    print('Adding vulnerabilities to elasticsearch')
    for vuln in vulnerabilities_list:
        res = ELASTIC_CLIENT.index(index='vulnerabilities',doc_type='_doc',id=vuln['vulnerability_id'],body=vuln)

def resolve_severity(cvss_score):
    if cvss_score == 0:
        return 'Informational'
    elif 0 < cvss_score <= 3.9:
        return 'Low'
    elif 3.9 < cvss_score <= 6.9:
        return 'Medium'
    elif 6.9 < cvss_score <= 8.9:
        return 'High'
    else:
        return 'Critical'

def update_elasticsearch_logs():
    print('Synchronizing log files')
    logs_found = logs.find()
    for log in logs_found:
        log['log_id'] = str(log.pop('_id'))
        try:
            something = log['log_module_keyword']
            ELASTIC_CLIENT.index(index='log_module',doc_type='_doc',id=log['log_id'],body=log)
        except KeyError:
            pass
        try:
            something = log['log_vulnerability_module_keyword']
            ELASTIC_CLIENT.index(index='log_vuln',doc_type='_doc',id=log['log_id'],body=log)
        except KeyError:
            pass
        try:
            something = log['log_resource_module_keyword']
            ELASTIC_CLIENT.index(index='log_resource',doc_type='_doc',id=log['log_id'],body=log)
        except KeyError:
            pass


def add_vuln_to_elastic(vuln):
    if ELASTIC_CLIENT is None:
        return 
    if not vuln['observation']:
        observation_data = {
            'vulnerability_title': None,
            'vulnerability_observation_title': None,
            'vulnerability_observation_note': None,
            'vulnerability_implication': None,
            'vulnerability_recommendation_title': None,
            'vulnerability_recommendation_note': None,
            'vulnerability_severity': None
        }
    else:
        observation_data = {
            'vulnerability_title': vuln['observation']['title'],
            'vulnerability_observation_title': vuln['observation']['observation_title'],
            'vulnerability_observation_note': vuln['observation']['observation_note'],
            'vulnerability_implication': vuln['observation']['implication'],
            'vulnerability_recommendation_title': vuln['observation']['recommendation_title'],
            'vulnerability_recommendation_note': vuln['observation']['recommendation_note'],
            'vulnerability_severity': vuln['observation']['severity']
        }
    vulnerability_to_add = {
        'vulnerability_id': str(vuln['_id']),
        'vulnerability_domain': vuln['domain'],
        'vulnerability_subdomain': vuln['resource'],
        'vulnerability_vulnerability_name': vuln['vulnerability_name'],
        'vulnerability_observation': observation_data,
        'vulnerability_extra_info': vuln['extra_info'],
        'vulnerability_date_found': vuln['date_found'],
        'vulnerability_last_seen': vuln['last_seen'],
        'vulnerability_language': vuln['language'],
        'vulnerability_cvss_score': vuln['cvss_score'],
        'vulnerability_vuln_type': vuln['vuln_type'],
        'vulnerability_state': vuln['state']
    }
    res = ELASTIC_CLIENT.index(index='vulnerabilities',doc_type='_doc',id=vulnerability_to_add['vulnerability_id'],body=vulnerability_to_add)
    return

def add_resource_to_elastic(resource):
    if ELASTIC_CLIENT is None:
        return
    resource_url = None
    if resource['url'] is not None:
        for url in resource['url']:
            resource_url = url['url']
            if 'https' in url['url']:
                break

    resource_to_add = {
        'resource_id': str(resource['_id']),
        'resource_domain': resource['domain'],
        'resource_subdomain': resource['subdomain'],
        'resource_ip': resource['ip'],
        'resource_is_alive': False if resource['is_alive'] == "False" else True,
        'resource_additional_info':{
            'resource_isp': resource['additional_info']['isp'],
            'resource_asn': resource['additional_info']['asn'],
            'resource_country': resource['additional_info']['country'],
            'resource_region': resource['additional_info']['region'],
            'resource_city': resource['additional_info']['city'],
            'resource_org': resource['additional_info']['org'],
            'resource_geoloc': '0 , 0' if resource['additional_info']['geoloc'] == 'None , None' else resource['additional_info']['geoloc']
        },
        'resource_first_seen': resource['first_seen'],
        'resource_last_seen': resource['last_seen'],
        'resource_scanned': bool(resource['scanned']),
        'resource_type': resource['type'],
        'resource_priority': resource['priority'],
        'resource_exposition': resource['exposition'],
        'resource_asset_value': resource['asset_value'],
        'resource_has_urls': bool(resource['has_urls']),
        'resource_responsive_urls': resource_url,
        'resource_nmap_information': resource['nmap_information']
    }
    res = ELASTIC_CLIENT.index(index='resources',doc_type='_doc',id=resource_to_add['resource_id'],body=resource_to_add)
    return

# We log if the module starts or finishes
def add_module_status_log(info):
    log_to_add = {
        'log_module_keyword': info['module_keyword'],
        'log_module_state': info['state'],
        'log_module_domain': info['domain'],
        #Found is just used for recon modules
        'log_module_found': info['found'],
        'log_module_arguments': info['arguments'],
        'log_module_timestamp': datetime.now()
    }
    log_id = logs.insert_one(log_to_add)
    log_to_add['log_id'] = str(log_to_add.pop('_id'))
    ELASTIC_CLIENT.index(index='log_module',doc_type='_doc',id=log_to_add['log_id'],body=log_to_add)


# We log if a vuln is found
def add_found_vulnerability_log(vulnerability, vuln_obj):
    log_to_add = {
        "log_vulnerability_module_keyword": vuln_obj.module_identifier,
        "log_vulnerability_found": True,
        "log_vulnerability_id": str(vulnerability['_id']),
        "log_vulnerability_name": vulnerability['vulnerability_name'],
        "log_vulnerability_timestamp": datetime.now()
    }
    log_id = logs.insert_one(log_to_add)
    log_to_add['log_id'] = str(log_to_add.pop('_id'))
    res = ELASTIC_CLIENT.index(index='log_vuln',doc_type='_doc',id=log_to_add['log_id'],body=log_to_add)

# We log if a vuln is not found
def add_not_found_vulnerability_log(vulnerability):
    log_id = logs.insert_one({})
    #res = ELASTIC_CLIENT.index(index='log',doc_type='_doc',id=log_to_add['log_id'],body=log_to_add)

# We log if a resource is found. IT can be from a recon or a monitor
def add_resource_found_log(resource, module_keyword):
    log_to_add = {
        "log_resource_module_keyword": module_keyword,
        "log_resource_domain": resource['domain'],
        "log_resource_subdomain": resource['subdomain'],
        "log_resource_id": str(resource['_id']),
        "log_resource_timestamp": datetime.now()
    }
    log_id = logs.insert_one(log_to_add)
    log_to_add['log_id'] = str(log_to_add.pop('_id'))
    res = ELASTIC_CLIENT.index(index='log_resource',doc_type='_doc',id=log_to_add['log_id'],body=log_to_add)
    

# TODO Temporary function for result revision
def get_vulnerabilities_for_email(scan_information):
    return_list = list()
    found_vulns = vulnerabilities.find()
    for vuln in found_vulns:
            return_list.append(vuln)
    return  return_list

def get_all_resources_for_email():
    return_list = list()
    found_resources = resources.find()
    for resource in found_resources:
        res = {
            'domain': resource['domain'],
            'subdomain': resource['subdomain'],
            'url': resource['url'],
            'ip': resource['ip'],
            'isp': resource['additional_info']['isp'],
            'asn': resource['additional_info']['asn'],
            'country': resource['additional_info']['country'],
            'region': resource['additional_info']['region'],
            'city': resource['additional_info']['city'],
            'org': resource['additional_info']['org'],
            'geoloc': resource['additional_info']['geoloc'],
            'first_seen': resource['first_seen'],
            'last_seen': resource['last_seen'],
            'is_alive': resource['is_alive'],
            'has_urls': resource['has_urls'],
            'approved': resource['approved'],
            'scan_type': resource['type'],
            'priority': resource['priority'],
            'exposition': resource['exposition'],
            'asset_value': resource['asset_value']
        }
        return_list.append(res)
 
    return return_list

# TODO Temporary function for result revision
def get_resources_for_email(scan_information):
    return_list = list()
    found_resources = resources.find({'domain': scan_information['domain']})
    for resource in found_resources:
        res = {
            'domain': resource['domain'],
            'subdomain': resource['subdomain'],
            'url': resource['url'],
            'ip': resource['ip'],
            'isp': resource['additional_info']['isp'],
            'asn': resource['additional_info']['asn'],
            'country': resource['additional_info']['country'],
            'region': resource['additional_info']['region'],
            'city': resource['additional_info']['city'],
            'org': resource['additional_info']['org'],
            'geoloc': resource['additional_info']['geoloc'],
            'first_seen': resource['first_seen'],
            'last_seen': resource['last_seen'],
            'is_alive': resource['is_alive'],
            'has_urls': resource['has_urls'],
            'approved': resource['approved'],
            'scan_type': resource['type'],
            'priority': resource['priority'],
            'exposition': resource['exposition'],
            'asset_value': resource['asset_value']
        }
        return_list.append(res)
    
    return return_list
