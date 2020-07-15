from VM_OrchestratorApp import MONGO_CLIENT
from VM_Orchestrator.settings import MONGO_INFO
from VM_OrchestratorApp.src.utils import slack

from datetime import datetime

resources = MONGO_CLIENT[MONGO_INFO['DATABASE']][MONGO_INFO['RESOURCES_COLLECTION']]
observations = MONGO_CLIENT[MONGO_INFO['DATABASE']][MONGO_INFO['OBSERVATIONS_COLLECTION']]
vulnerabilities = MONGO_CLIENT[MONGO_INFO['DATABASE']][MONGO_INFO['VULNERABILITIES_COLLECTION']]
libraries_versions = MONGO_CLIENT[MONGO_INFO['DATABASE']]['libraries_versions']


def add_vulnerability(vulnerability):
    exists = vulnerabilities.find_one({'domain': vulnerability.target, 'subdomain': vulnerability.scanned_url,
                                          'vulnerability_name': vulnerability.vulnerability_name,
                                          'language': vulnerability.language})
    if exists:
        vulnerabilities.update_one({'_id': exists.get('_id')}, {'$set': {
            'extra_info': vulnerability.custom_description,
            'last_seen': vulnerability.time,
            'extra_info': vulnerability.custom_description,
            'image_string': vulnerability.image_string,
            'file_string': vulnerability.file_string
        }})
    else:
        resource = {
            'domain': vulnerability.target,
            'subdomain': vulnerability.scanned_url,
            'vulnerability_name': vulnerability.vulnerability_name,
            'observation': vulnerability.get_json_observation(),
            'extra_info': vulnerability.custom_description,
            'image_string': vulnerability.image_string,
            'file_string': vulnerability.file_string,
            'date_found': vulnerability.time,
            'last_seen': vulnerability.time,
            'language': vulnerability.language,
            'state': 'open'
        }
        vulnerabilities.insert_one(resource)
    return


# For flagging resources as "scanned"
def add_scanned_resources(urls):
    if urls['type'] == 'domain':
        for url in urls['url_to_scan']:
            resource = resources.find_one({'domain': urls['domain'], 'subdomain': url, 'scanned': False, 'type': urls['type']})
            if resource is not None:
                resources.update_one({'_id': resource.get('_id')},
                {'$set': 
                    {
                    'scanned': True
                    }})
    else:
        resource = resources.find_one({'domain': urls['domain'], 'subdomain': urls['url_to_scan'], 'scanned': False, 'type': urls['type']})
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
    subdomains = resources.find({'domain': target, 'has_urls': 'True', 'scanned': False})
    subdomain_list = list()
    for subdomain in subdomains:
        for url_with_http in subdomain['responsive_urls'].split(';'):
            if url_with_http:
                current_subdomain = {
                    'domain': subdomain['domain'],
                    'ip': subdomain['ip'],
                    'subdomain': subdomain['subdomain'],
                    'url_with_http': url_with_http
                }
                subdomain_list.append(current_subdomain)
    return subdomain_list

# Searches for vulnerability information in observations collection
def get_observation_for_object(vuln_name,language):
    finding_kb = observations.find_one({'TITLE': vuln_name, 'LANGUAGE': language})
    return finding_kb

def find_last_version_of_librarie(name):
    librarie = libraries_versions.find({'name':name})
    if librarie.count() != 0:
        return librarie[0]['version']
    else:
        return ''

# Returns a list similar to the one generated by the start csv file
def get_data_for_monitor():
    all_data = resources.find({})
    information = list()
    for data in all_data:
        information.append({
            'is_first_run': False,
            'invasive_scans': False,
            'language': 'eng',
            'type': data['type'],
            'priority': data['priority'],
            'exposition': data['exposition'],
            'domain': data['domain']
        })
    information = [dict(t) for t in {tuple(d.items()) for d in information}]

    return information

# ------------------- RECON -------------------
def add_simple_url_resource(scan_info):
    exists = resources.find_one({'domain': scan_info['domain'].split('/')[2], 'subdomain': scan_info['url_to_scan']})
    timestamp = datetime.now()
    if not exists:
        resource ={
                'domain': scan_info['domain'].split('/')[2],
                'subdomain': scan_info['domain'],
                'is_alive': True,
                'ip': None,
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
                'has_urls': False,
                'responsive_urls': ''
        }
        resources.insert_one(resource)
    else:
        resources.update_one({'_id': exists.get('_id')},
         {'$set': 
            {
            'last_seen': timestamp
            }})

def add_simple_ip_resource(scan_info):
    exists = resources.find_one({'domain': scan_info['domain'], 'subdomain': scan_info['url_to_scan']})
    timestamp = datetime.now()
    if not exists:
        resource ={
                'domain': scan_info['domain'],
                'subdomain': scan_info['domain'],
                'is_alive': True,
                'ip': scan_info['domain'],
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
                'has_urls': False,
                'responsive_urls': ''
        }
        resources.insert_one(resource)
    else:
        resources.update_one({'_id': exists.get('_id')},
         {'$set': 
            {
            'last_seen': timestamp
            }})


def add_resource(url_info, scan_info):
    exists = resources.find_one({'domain': url_info['domain'], 'subdomain': url_info['url']})
    timestamp = datetime.now()
    if not exists:
        resource ={
                'domain': url_info['domain'],
                'subdomain': url_info['url'],
                'is_alive': url_info['is_alive'],
                'ip': url_info['ip'],
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
                'priority': scan_info['priority'],
                'exposition': scan_info['exposition'],
                'has_urls': False,
                'responsive_urls': ''
        }
        if not scan_info['is_first_run']:
            slack.send_new_resource_found("New resource found! %s" % url_info['url'])
        resources.insert_one(resource)
    else:
        resources.update_one({'_id': exists.get('_id')},
         {'$set': 
            {
            'is_alive': url_info['is_alive'],
            'ip': url_info['ip'],
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


def get_alive_subdomains_from_target(target):
    subdomains = resources.find({'domain': target, 'is_alive': 'True', 'scanned': False})
    subdomain_list = list()
    for subdomain in subdomains:
        current_subdomain = {
            'domain': subdomain['domain'],
            'subdomain': subdomain['subdomain']
        }
        subdomain_list.append(current_subdomain)
    return subdomain_list

def add_urls_to_subdomain(subdomain, has_urls, url_list):
    subdomain = resources.find_one({'subdomain': subdomain})
    resources.update_one({'_id': subdomain.get('_id')}, {'$set': {
        'has_urls': str(has_urls),
        'responsive_urls': url_list}})

    return


def add_images_to_subdomain(subdomain, http_image, https_image):
    ##########33
    return
    subdomain = resources.find_one({'subdomain': subdomain})
    resources.update_one({'_id': subdomain.get('_id')}, {'$set': {
        'http_image': http_image,
        'https_image': https_image}})
    return

def update_issue_if_needed(redmine_issue):
    target = redmine_issue.custom_fields.get(2).value
    vuln_name = redmine_issue.subject
    scanned_url = redmine_issue.custom_fields.get(4).value

    vulnerability = vulnerabilities.find_one({'vulnerability_name': vuln_name,
    'domain': target, 'subdomain': scanned_url})
    status = redmine_issue.status.name
    if status == 'QA - Confirmada':
        vulnerabilities.update_one({'_id': vulnerability.get('_id')}, {'$set': {
            'state': 'confirmed' 
        }})
    elif status == 'Rechazada':
        vulnerabilities.update_one({'_id': vulnerability.get('_id')}, {'$set': {
            'state': 'rejected' 
        }})
    return

def update_elasticsearch():
    new_resources = resources.find()
    resources_list = list()
    for resource in new_resources:
        resources_list.append({
            'resource_id': str(resource['_id']),
            'resource_domain': resource['domain'],
            'resource_subdomain': resource['subdomain'],
            'resource_is_alive': bool(resource['is_alive']),
            'resource_ip': resource['ip'],
            'resource_additional_info':{
                'resource_isp': resource['additional_info']['isp'],
                'resource_asn': resource['additional_info']['asn'],
                'resource_country': resource['additional_info']['country'],
                'resource_region': resource['additional_info']['region'],
                'resource_city': resource['additional_info']['city'],
                'resource_org': resource['additional_info']['org'],
                'resource_geoloc': resource['additional_info']['geoloc']
                },
            'resource_first_seen': resource['first_seen'],
            'resource_last_seen': resource['last_seen'],
            'resource_scanned': bool(resource['scanned']),
            'resource_type': resource['type'],
            'resource_priority': resource['priority'],
            'resource_exposition': resource['exposition'],
            'resource_has_urls': resource['has_urls'],
            'resource_responsive_urls': resource['responsive_urls']
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
                'vulnerability_subdomain': vuln['subdomain'],
                'vulnerability_vulnerability_name': vuln['vulnerability_name'],
                'vulnerability_observation': observation_data,
                'vulnerability_extra_info': vuln['extra_info'],
                'vulnerability_date_found': vuln['date_found'],
                'vulnerability_last_seen': vuln['last_seen'],
                'vulnerability_language': vuln['language'],
                'vulnerability_state': vuln['state']
            })

    # Import Elasticsearch package 
    from elasticsearch import Elasticsearch 
    # Connect to the elastic cluster
    es=Elasticsearch([{'host':'localhost','port':9200}])
    print('Adding resources to elasticsearch')
    for resource in resources_list:
        res = es.index(index='test',doc_type='_doc',id=resource['resource_id'],body=resource)
    print('Adding vulnerabilities to elasticsearch')
    for vuln in vulnerabilities_list:
        res = es.index(index='test',doc_type='_doc',id=vuln['vulnerability_id'],body=vuln)


# TODO Temporary function for result revision
def get_vulnerabilities_for_email(scan_information):
    # In information we are going to have the scan type, if scan_type != domain, url_to_scan == domain
    return_list = list()
    if scan_information['type'] != 'domain':
        found_vulns = vulnerabilities.find({'domain': scan_information['domain'], 'subdomain': scan_information['domain']})
    else:
        found_vulns = vulnerabilities.find({'domain': scan_information['domain']})

    for vuln in found_vulns:
            return_list.append(vuln)

    return  return_list

# TODO Temporary function for result revision
def get_resources_for_email(scan_information):
    return_list = list()
    found_resources = resources.find({'domain': scan_information['domain']})
    for resource in found_resources:
        return_list.append(resource)
    
    return return_list