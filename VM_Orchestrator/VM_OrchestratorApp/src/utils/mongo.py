from VM_OrchestratorApp import MONGO_CLIENT
from VM_Orchestrator.settings import MONGO_INFO

resources = MONGO_CLIENT[MONGO_INFO['DATABASE']][MONGO_INFO['RESOURCES_COLLECTION']]
observations = MONGO_CLIENT[MONGO_INFO['DATABASE']][MONGO_INFO['OBSERVATIONS_COLLECTION']]
vulnerabilities = MONGO_CLIENT[MONGO_INFO['DATABASE']][MONGO_INFO['VULNERABILITIES_COLLECTION']]


def add_vulnerability():
    
    return

# ------------------- RECON -------------------
def add_resource(target_name, url):
    exists = resources.find_one({'subdomain': url})
    if not exists:
        resource = {
                'target_name': target_name,
                'subdomain': url
            }
        # if is_alive == 'True':
        # slack_sender.send_new_domain_found_message(name, ip)
        resources.insert_one(resource)
    return


def get_subdomains_from_target(target):
    subdomains = resources.find({'target_name': target})
    subdomain_list = list()
    for subdomain in subdomains:
        current_subdomain = {
            'target_name': subdomain['target_name'],
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