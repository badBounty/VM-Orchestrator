from VM_OrchestratorApp import MONGO_CLIENT
from VM_Orchestrator.settings import MONGO_INFO
from VM_OrchestratorApp.src.utils import slack

from datetime import datetime

resources = MONGO_CLIENT[MONGO_INFO['DATABASE']][MONGO_INFO['RESOURCES_COLLECTION']]
observations = MONGO_CLIENT[MONGO_INFO['DATABASE']][MONGO_INFO['OBSERVATIONS_COLLECTION']]
vulnerabilities = MONGO_CLIENT[MONGO_INFO['DATABASE']][MONGO_INFO['VULNERABILITIES_COLLECTION']]


def add_vulnerability():
    
    return

# ------------------- RECON -------------------
def add_resource(url_info, scan_info):
    exists = resources.find_one({'domain': url_info['target_name'], 'subdomain': url_info['url']})
    timestamp = datetime.now()
    if not exists:
        resource ={
                'domain': url_info['target_name'],
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
                'last_seen': timestamp
        }
        if not scan_info['is_first_run']:
            slack.send_simple_message("New resource found! NOT first run. %s" % url_info['url'])
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


def get_subdomains_from_target(target):
    subdomains = resources.find({'domain': target})
    subdomain_list = list()
    for subdomain in subdomains:
        current_subdomain = {
            'target_name': subdomain['domain'],
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