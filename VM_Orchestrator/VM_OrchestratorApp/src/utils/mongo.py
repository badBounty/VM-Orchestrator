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
from bson.objectid import ObjectId

domains = MONGO_CLIENT[MONGO_INFO['DATABASE']][MONGO_INFO['DOMAINS_COLLECTION']]
logs = MONGO_CLIENT[MONGO_INFO['DATABASE']][MONGO_INFO['LOGS_COLLECTION']]
libraries_versions = MONGO_CLIENT[MONGO_INFO['DATABASE']][MONGO_INFO['LIBRARIES_COLLECTION']]
observations = MONGO_CLIENT[MONGO_INFO['DATABASE']][MONGO_INFO['OBSERVATIONS_COLLECTION']]
resources = MONGO_CLIENT[MONGO_INFO['DATABASE']][MONGO_INFO['RESOURCES_COLLECTION']]
web_vulnerabilities = MONGO_CLIENT[MONGO_INFO['DATABASE']][MONGO_INFO['WEB_VULNERABILITIES_COLLECTION']]
infra_vulnerabilities = MONGO_CLIENT[MONGO_INFO['DATABASE']][MONGO_INFO['INFRA_VULNERABILITIES_COLLECTION']]
code_vulnerabilities = MONGO_CLIENT[MONGO_INFO['DATABASE']][MONGO_INFO['CODE_VULNERABILITIES_COLLECTION']]

# -------------------- VULNERABILITIES --------------------
### Handles vuln add. Vulns will go to different collections depending on its type.
### Each vuln will have its custom fields, so differenciation is needed
def add_vulnerability(vulnerability):
    # Each vuln has its fields
    if vulnerability.vuln_type == 'ip':
        return add_infra_vuln(vulnerability)
    elif vulnerability.vuln_type == 'web':
        return add_web_vuln(vulnerability)

## Uses infra_vulnerabilities collection
def add_infra_vuln(vulnerability):
    exists = infra_vulnerabilities.find_one({'domain': vulnerability.domain, 'resource': vulnerability.target,
                                          'vulnerability_name': vulnerability.vulnerability_name,
                                          'language': vulnerability.language})
    if exists:
        infra_vulnerabilities.update_one({'_id': exists.get('_id')}, {'$set': {
            'extra_info': vulnerability.custom_description,
            'last_seen': vulnerability.time,
            'image_string': vulnerability.image_string,
            'file_string': vulnerability.file_string,
            'state': 'new' if exists['state'] != 'rejected' else exists['state']
        }})
        return str(exists.get('_id'))
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
        vuln_id = infra_vulnerabilities.insert_one(resource)
        resource['_id'] = str(vuln_id.inserted_id)
        add_found_vulnerability_log(resource, vulnerability)
        add_infra_vuln_to_elastic(resource)
        return str(resource.get('_id'))

## Uses web_vulnerabilities collection
def add_web_vuln(vulnerability):
    exists = web_vulnerabilities.find_one({'domain': vulnerability.domain, 'resource': vulnerability.target,
                                          'vulnerability_name': vulnerability.vulnerability_name,
                                          'language': vulnerability.language})
    if exists:
        web_vulnerabilities.update_one({'_id': exists.get('_id')}, {'$set': {
            'extra_info': vulnerability.custom_description,
            'last_seen': vulnerability.time,
            'image_string': vulnerability.image_string,
            'file_string': vulnerability.file_string
        }})
        return str(exists.get('_id'))
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
        vuln_id = web_vulnerabilities.insert_one(resource)
        resource['_id'] = str(vuln_id.inserted_id)
        add_found_vulnerability_log(resource, vulnerability)
        add_web_vuln_to_elastic(resource)
        return str(resource.get('_id'))

'''
{
  "Title": "Unrestricted Spring's RequestMapping makes the method vulnerable to CSRF attacks", *
  "Description": "Tool title \n tool description", *
  "Component": "src/main/java/org/owasp/webwolf/FileServer.java", *
  "Line": 25, *
  "Affected_code": "string", *
  "Commit": "261283c",
 "Username": "username", *
  "Pipeline_name": "name", *
  "Language": "spa/eng",
  "Hash": "hash",
  "Severity_tool": "Severity"
}
'''
## Uses code_vulnerabilities collection
## TODO If the vuln matches completely, we update time.
## If everything but the line is the same, we check the code snippet (new data)
def add_code_vuln(vulnerability):
    timestamp = datetime.now()
    exists = code_vulnerabilities.find_one({
        'title': vulnerability['Title'],
        'description': vulnerability['Description'],
        'component': vulnerability['Component'],
        'affected_code': vulnerability['Affected_code'],
        'username': vulnerability['Username'],
        'pipeline_name': vulnerability['Pipeline_name']})
    if exists:
        code_vulnerabilities.update_one({'_id': exists.get('_id')}, {'$set': {
            'last_seen': timestamp,
            'last_commit': vulnerability['Commit'],
            'line': vulnerability['Line'],
            'hash': vulnerability['Hash']
        }})
        return str(exists.get('_id'))
    else:
        vuln_to_add = {
            'title': vulnerability['Title'],
            'description': vulnerability['Description'],
            'component': vulnerability['Component'],
            'line': vulnerability['Line'],
            'affected_code': vulnerability['Affected_code'],
            'first_commit': vulnerability['Commit'],
            'last_commit': vulnerability['Commit'],
            'username': vulnerability['Username'],
            'pipeline_name': vulnerability['Pipeline_name'],
            'language': vulnerability['Language'],
            'hash': vulnerability['Hash'],
            'severity_tool': vulnerability['Severity_tool'],
            'observation': vulnerability['observation'],
            'date_found': timestamp,
            'last_seen': timestamp,
            'cvss_score': vulnerability['cvss_score'],
            'vuln_type': vulnerability['vuln_type'],
            'state': 'new'
        }
        vuln_id = code_vulnerabilities.insert_one(vuln_to_add)
        vuln_to_add['_id'] = str(vuln_id.inserted_id)
        add_found_vulnerability_log(vuln_to_add)
        add_code_vuln_to_elastic(vuln_to_add)
        return str(vuln_to_add.get('_id'))



# -------------------- RECON AND RESOURCES METHODS --------------------
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
        add_resource_log(resource, module_keyword, 'found')
        add_resource_to_elastic(resource)
    else:
        if exists['is_alive'] and not url_info['is_alive']:
            resource = {
                '_id': exists.get('_id'),
                'domain': exists.get('domain'),
                'subdomain': exists.get('subdomain')
            }
            module_keyword = 'on_demand_recon_module' if scan_info['is_first_run'] else 'monitor_recon_module'
            add_resource_log(resource, module_keyword, 'found')
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

def add_domain(scan_info, for_recon):
    exists = domains.find_one({'domain': scan_info['domain']})
    if not exists:
        domains.insert_one({'domain': scan_info['domain'], 'for_recon':for_recon})
    else:
        domains.update_one({'_id': exists.get('_id')},
         {'$set': 
            {
                'for_recon': for_recon
            }})

# Returns a list similar to the one generated by the start csv file
def get_domains_for_monitor():
    found = domains.find()
    return_list = list()
    for domain in found:
        if domain['for_recon']:
            return_list.append({'domain': domain['domain']})
    return return_list

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



# -------------------- REDMINE --------------------
#TODO Update this for several trackers
def add_custom_redmine_issue(redmine_issue):
    #We are going to suppose the resource exists on our local database
    #We will check first and send an exception if its not found
    resource_exists = resources.find_one({'domain': redmine_issue.custom_fields.get(REDMINE_IDS['WEB_FINDING']['DOMAIN']).value,
     'subdomain': redmine_issue.custom_fields.get(REDMINE_IDS['WEB_FINDING']['RESOURCE']).value})
    if not resource_exists:
        print('Failed adding custom redmine resource. Domain %s, resource %s' % 
        (redmine_issue.custom_fields.get(REDMINE_IDS['WEB_FINDING']['DOMAIN']).value,redmine_issue.custom_fields.get(REDMINE_IDS['WEB_FINDING']['RESOURCE']).value))
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
        'domain': redmine_issue.custom_fields.get(REDMINE_IDS['WEB_FINDING']['DOMAIN']).value,
        'resource': redmine_issue.custom_fields.get(REDMINE_IDS['WEB_FINDING']['RESOURCE']).value,
        'vulnerability_name': redmine_issue.subject,
        'observation': None, # TODO we will add observation in the future
        'extra_info': redmine_issue.description,
        'image_string': None,
        'file_string': None,
        'date_found': datetime.now(),
        'last_seen': datetime.now(),
        'language': None,
        'cvss_score': redmine_issue.custom_fields.get(REDMINE_IDS['WEB_FINDING']['CVSS_SCORE']).value,
        'state': vuln_status
    }
    # TODO add redmine dropdown in which the user can choose the issue type, this will define the fields used
    #vulnerabilities.insert_one(vuln_to_add)
    return

#TODO: Update several fields
def update_issue_if_needed(redmine_issue):
    # We receive an issue, we will first check out the tracker
    if redmine_issue.tracker.id == REDMINE_IDS['WEB_FINDING']['FINDING_TRACKER']:
        # Web case
        update_web_finding(redmine_issue)
    elif redmine_issue.tracker.id == REDMINE_IDS['INFRA_FINDING']['FINDING_TRACKER']:
        #Infra case
        update_infra_finding(redmine_issue)
    elif redmine_issue.tracker.id == REDMINE_IDS['CODE_FINDING']['FINDING_TRACKER']:
        #Code case    
        update_code_finding(redmine_issue)

def update_web_finding(redmine_issue):
    cvss_score = redmine_issue.custom_fields.get(REDMINE_IDS['WEB_FINDING']['CVSS_SCORE']).value
    status_id = redmine_issue.status.id
    vulnerability = web_vulnerabilities.find_one({'_id': ObjectId(redmine_issue.custom_fields.get(REDMINE_IDS['WEB_FINDING']['IDENTIFIER']).value)})
    try:
        web_vulnerabilities.update_one({'_id': vulnerability.get('_id')}, {'$set': {
                'cvss_score': float(cvss_score) 
            }})
    except ValueError:
        pass

    if status_id == REDMINE_IDS['STATUS_SOLVED']:
        web_vulnerabilities.update_one({'_id': vulnerability.get('_id')}, {'$set': {
            'state': 'resolved' 
        }})
    elif status_id == REDMINE_IDS['STATUS_CLOSED']:
        web_vulnerabilities.update_one({'_id': vulnerability.get('_id')}, {'$set': {
            'state': 'closed' 
        }})
    elif status_id == REDMINE_IDS['STATUS_CONFIRMED']:
        web_vulnerabilities.update_one({'_id': vulnerability.get('_id')}, {'$set': {
            'state': 'confirmed' 
        }})
    elif status_id == REDMINE_IDS['STATUS_REJECTED']:
        web_vulnerabilities.update_one({'_id': vulnerability.get('_id')}, {'$set': {
            'state': 'rejected' 
        }})
    return

def update_infra_finding(redmine_issue):
    cvss_score = redmine_issue.custom_fields.get(REDMINE_IDS['INFRA_FINDING']['CVSS_SCORE']).value
    status = redmine_issue.status.name
    vulnerability = infra_vulnerabilities.find_one({'_id': ObjectId(redmine_issue.custom_fields.get(REDMINE_IDS['INFRA_FINDING']['IDENTIFIER']).value)})
    try:
        infra_vulnerabilities.update_one({'_id': vulnerability.get('_id')}, {'$set': {
                'cvss_score': float(cvss_score) 
            }})
    except ValueError:
        pass

    if status == 'Remediada':
        infra_vulnerabilities.update_one({'_id': vulnerability.get('_id')}, {'$set': {
            'state': 'resolved' 
        }})
    elif status == 'Cerrada':
        infra_vulnerabilities.update_one({'_id': vulnerability.get('_id')}, {'$set': {
            'state': 'closed' 
        }})
    elif status == 'Confirmada':
        infra_vulnerabilities.update_one({'_id': vulnerability.get('_id')}, {'$set': {
            'state': 'confirmed' 
        }})
    elif status == 'Rechazada':
        infra_vulnerabilities.update_one({'_id': vulnerability.get('_id')}, {'$set': {
            'state': 'rejected' 
        }})
    return

def update_code_finding(redmine_issue):
    cvss_score = redmine_issue.custom_fields.get(REDMINE_IDS['CODE_FINDING']['CVSS_SCORE']).value
    status = redmine_issue.status.name
    vulnerability = code_vulnerabilities.find_one({'_id': ObjectId(redmine_issue.custom_fields.get(REDMINE_IDS['CODE_FINDING']['IDENTIFIER']).value)})
    try:
        code_vulnerabilities.update_one({'_id': vulnerability.get('_id')}, {'$set': {
                'cvss_score': float(cvss_score) 
            }})
    except ValueError:
        pass

    if status == 'Remediada':
        code_vulnerabilities.update_one({'_id': vulnerability.get('_id')}, {'$set': {
            'state': 'resolved' 
        }})
    elif status == 'Cerrada':
        code_vulnerabilities.update_one({'_id': vulnerability.get('_id')}, {'$set': {
            'state': 'closed' 
        }})
    elif status == 'Confirmada':
        code_vulnerabilities.update_one({'_id': vulnerability.get('_id')}, {'$set': {
            'state': 'confirmed' 
        }})
    elif status == 'Rechazada':
        code_vulnerabilities.update_one({'_id': vulnerability.get('_id')}, {'$set': {
            'state': 'rejected' 
        }})
    return



# -------------------- ELASTICSEARCH --------------------
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
    web_vulns = web_vulnerabilities.find()
    infra_vulns = infra_vulnerabilities.find()
    code_vulns = code_vulnerabilities.find()
    
    print('Adding vulnerabilities to elasticsearch')
    #### Adding web vulns to elastic
    for vuln in web_vulns:
        add_web_vuln_to_elastic(vuln)

    #### Adding web vulns to elastic
    for vuln in infra_vulns:
        add_infra_vuln_to_elastic(vuln)

    ### Add code vulns to elastic
    for vuln in code_vulns:
        add_code_vuln_to_elastic(vuln)

    if ELASTIC_CLIENT is None:
        return 
    # Connect to the elastic cluster
    print('Adding resources to elasticsearch')
    for resource in resources_list:
        res = ELASTIC_CLIENT.index(index='resources',doc_type='_doc',id=resource['resource_id'],body=resource)

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

def add_web_vuln_to_elastic(vuln):
    if ELASTIC_CLIENT is None:
        return
    observation_data = {
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
        'vulnerability_cvss3_severity': utils.resolve_severity(vuln['cvss_score']),
        'vulnerability_vuln_type': vuln['vuln_type'],
        'vulnerability_state': vuln['state']
    }
    res = ELASTIC_CLIENT.index(index='web_vulnerabilities',doc_type='_doc',id=vulnerability_to_add['vulnerability_id'],body=vulnerability_to_add)
    return

def add_infra_vuln_to_elastic(vuln):
    if ELASTIC_CLIENT is None:
        return
    observation_data = {
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
        'vulnerability_cvss3_severity': utils.resolve_severity(vuln['cvss_score']),
        'vulnerability_vuln_type': vuln['vuln_type'],
        'vulnerability_state': vuln['state']
    }
    res = ELASTIC_CLIENT.index(index='infra_vulnerabilities',doc_type='_doc',id=vulnerability_to_add['vulnerability_id'],body=vulnerability_to_add)
    return

def add_code_vuln_to_elastic(vuln):
    if ELASTIC_CLIENT is None:
        return
    observation_data = {
        'vulnerability_observation_title': vuln['observation']['observation_title'],
        'vulnerability_observation_note': vuln['observation']['observation_note'],
        'vulnerability_implication': vuln['observation']['implication'],
        'vulnerability_recommendation_title': vuln['observation']['recommendation_title'],
        'vulnerability_recommendation_note': vuln['observation']['recommendation_note'],
        'vulnerability_severity': vuln['observation']['severity']
    } 
    vuln_to_add = {
        'vulnerability_id': str(vuln['_id']),
        'vulnerability_title': vuln['title'],
        'vulnerability_description': vuln['description'],
        'vulnerability_component': vuln['component'],
        'vulnerability_line': vuln['line'],
        'vulnerability_affected_code': vuln['affected_code'],
        'vulnerability_first_commit': vuln['first_commit'],
        'vulnerability_last_commit': vuln['last_commit'],
        'vulnerability_username': vuln['username'],
        'vulnerability_pipeline_name': vuln['pipeline_name'],
        'vulnerability_language': vuln['language'],
        'vulnerability_hash': vuln['hash'],
        'vulnerability_severity_tool': vuln['severity_tool'],
        'vulnerability_severity': vuln['observation']['severity'],
        'vulnerability_observation': observation_data,
        'vulnerability_first_seen': vuln['date_found'],
        'vulnerability_last_seen': vuln['last_seen'],
        'vulnerability_vuln_type': vuln['vuln_type'],
        'vulnerability_state': vuln['state']
    }
    res = ELASTIC_CLIENT.index(index='code_vulnerabilities',doc_type='_doc',id=vuln_to_add['vulnerability_id'],body=vuln_to_add)
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
def add_found_vulnerability_log(vulnerability, vuln_obj=None):
    module_keyword = 'code' if vuln_obj is None else vuln_obj.module_identifier
    log_to_add = {
        "log_vulnerability_module_keyword": module_keyword,
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
def add_resource_log(resource, module_keyword, state):
    log_to_add = {
        "log_resource_module_keyword": module_keyword,
        "log_resource_domain": resource['domain'],
        "log_resource_subdomain": resource['subdomain'],
        "log_resource_id": str(resource['_id']),
        "log_resource_state": state,
        "log_resource_timestamp": datetime.now()
    }
    log_id = logs.insert_one(log_to_add)
    log_to_add['log_id'] = str(log_to_add.pop('_id'))
    res = ELASTIC_CLIENT.index(index='log_resource',doc_type='_doc',id=log_to_add['log_id'],body=log_to_add)



# -------------------- GETTERS FOR SCANNERS --------------------
#Returns resolved vulnerabilities
def get_resolved_vulnerabilities():
    vulns = web_vulnerabilities.find({'state': 'resolved'})
    vulns.append(infra_vulnerabilities.find({'state': 'resolved'}))
    vulns.append(code_vulnerabilities.find({'state': 'resolved'}))
    return vulns

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

# Gets every approved resource for scanning
def get_data_for_approved_scan():
    all_data = resources.find({'approved': True, 'scanned': False})
    information = list()
    for data in all_data:
        information.append({
            'is_first_run': False,
            'language': settings['LANGUAGE'],
            'type': data['type'],
            'priority': data['priority'],
            'exposition': data['exposition'],
            'domain': data['domain']
        })
    import pandas as pd
    info_to_return = pd.DataFrame(information).drop_duplicates().to_dict('records')
    return info_to_return

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



# -------------------- VIEWS GETTERS --------------------
def get_all_code_vulnerabilities():
    return_list = list()
    found_vulns = code_vulnerabilities.find()
    for vuln in found_vulns:
        return_list.append(vuln)
    return return_list

def get_all_web_vulnerabilities():
    return_list = list()
    found_vulns = web_vulnerabilities.find()
    for vuln in found_vulns:
        return_list.append(vuln)
    return return_list

def get_all_infra_vulnerabilities():
    return_list = list()
    found_vulns = infra_vulnerabilities.find()
    for vuln in found_vulns:
        return_list.append(vuln)
    return return_list

def get_all_observations():
    return_list = list()
    found_observations = observations.find({})
    for value in found_observations:
        return_list.append(value)
    return return_list

def get_all_resources():
    return_list = list()
    found_resources = resources.find()
    for resource in found_resources:
        return_list.append(resource)
    return return_list



# -------------------- OTHER METHODS --------------------
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

# Searches for vulnerability information in observations collection
def get_observation_for_object(vuln_name,language):
    finding_kb = observations.find_one({'TITLE': vuln_name, 'LANGUAGE': language})
    return finding_kb

# Searches libraries_versions collection for latest version of libraries found
def find_last_version_of_librarie(name):
    librarie = libraries_versions.find({'name':name})
    if librarie.count() != 0:
        return librarie[0]['version']
    else:
        return ''
