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
            'last_seen': vulnerability.time,
            'extra_info': vulnerability.custom_description,
            'image_string': vulnerability.image_string,
            'file_string': vulnerability.file_string
        }})
    else:
        resource = {
            'target_name': vulnerability.target,
            'subdomain': vulnerability.scanned_url,
            'vulnerability_name': vulnerability.vulnerability_name,
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

def add_scanned_resources(urls):
    for url in urls['url_to_scan']:
        subdomain = resources.find_one({'domain': urls['domain'], 'subdomain': url, 'scanned': False})
        resources.update_one({'_id': subdomain.get('_id')},
         {'$set': 
            {
            'scanned': True
            }})

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

def get_observation_for_object(vuln_name,language):
    finding_kb = observations.find_one({'TITLE': vuln_name, 'LANGUAGE': language})
    return finding_kb

def find_last_version_of_librarie(name):
    librarie = libraries_versions.find({'name':name})
    if librarie:
        return librarie[0]['version']
    else:
        return ''


# ------------------- RECON -------------------
def add_resource(url_info, scan_info):
    exists = resources.find_one({'domain': url_info['domain'], 'subdomain': url_info['url']})
    timestamp = datetime.now()
    if not exists:
        resource ={
                'domain': url_info['domain'],
                'subdomain': url_info['url'],
                'is_alive': url_info['is_alive'],
                'ip': url_info['ip'],
                'isp': url_info['isp'],
                'asn': url_info['asn'],
                'country': url_info['country'],
                'region': url_info['region'],
                'city': url_info['city'],
                'org': url_info['org'],
                'lat': url_info['lat'],
                'lon': url_info['lon'],
                'first_seen': timestamp,
                'last_seen': timestamp,
                'scanned': False,
        }
        if not scan_info['is_first_run']:
            slack.send_new_resource_found("New resource found! NOT first run. %s" % url_info['url'])
            print('New resource found!!\n')
            print(str(resource))
        resources.insert_one(resource)
    else:
        resources.update_one({'_id': exists.get('_id')},
         {'$set': 
            {
            'is_alive': url_info['is_alive'],
            'ip': url_info['ip'],
            'isp': url_info['isp'],
            'asn': url_info['asn'],
            'country': url_info['country'],
            'region': url_info['region'],
            'city': url_info['city'],
            'org': url_info['org'],
            'lat': url_info['lat'],
            'lon': url_info['lon'],
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
    subdomain = resources.find_one({'subdomain': subdomain})
    resources.update_one({'_id': subdomain.get('_id')}, {'$set': {
        'http_image': http_image,
        'https_image': https_image}})
    return