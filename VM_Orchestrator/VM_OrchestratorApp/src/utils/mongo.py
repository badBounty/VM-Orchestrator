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
from bson.errors import InvalidId

domains = MONGO_CLIENT[MONGO_INFO['DATABASE_NAME']]['domains']
logs = MONGO_CLIENT[MONGO_INFO['DATABASE_NAME']]['logs']
libraries_versions = MONGO_CLIENT[MONGO_INFO['DATABASE_NAME']]['libraries_versions']
observations = MONGO_CLIENT[MONGO_INFO['DATABASE_NAME']]['observations']
resources = MONGO_CLIENT[MONGO_INFO['DATABASE_NAME']]['resources']
web_vulnerabilities = MONGO_CLIENT[MONGO_INFO['DATABASE_NAME']]['web_vulnerabilities']
infra_vulnerabilities = MONGO_CLIENT[MONGO_INFO['DATABASE_NAME']]['infra_vulnerabilities']
code_vulnerabilities = MONGO_CLIENT[MONGO_INFO['DATABASE_NAME']]['code_vulnerabilities']
bulk_code_vulnerabilities = MONGO_CLIENT[MONGO_INFO['DATABASE_NAME']]['bulk_code_vulnerabilities']

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
        'pipeline_name': vulnerability['Pipeline_name'],
        'branch': vulnerability['Branch'],
        'state': {'$ne': 'resolved'}})
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
            'branch': vulnerability['Branch'],
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

# This receives a vulnerability in code_vulnerabilities json format
def add_bulk_code_vuln(vulnerability):
    # We first search if a bulk vuln with the name exists
    exists = bulk_code_vulnerabilities.find_one({'title': vulnerability['title']})
    # If exists, we need to check if within the vulns in the bulk our ID exists
    if exists:
        # We first isolate the individual issues so we can then update the mongo object
        individual_issues = exists['individual_issues']
        # If any of the mongo ids within the bulk vuln match our current vuln
        if any(existing_vulns['_id'] == vulnerability['_id'] for existing_vulns in individual_issues):
            for i in range(len(individual_issues)):
                if individual_issues[i]['_id'] == vulnerability['_id']:
                    individual_issues[i]['last_seen'] = vulnerability['last_seen']
                    individual_issues[i]['last_commit'] = vulnerability['last_commit']
                    individual_issues[i]['line'] = vulnerability['line']
                    individual_issues[i]['state'] = vulnerability['state']
                    break
        # This means the mongo ID is NOT inside the bulk
        else:
            # Add the issue to our bulk list
            individual_issues.append({
                '_id': vulnerability['_id'],
                'component': vulnerability['component'],
                'line': vulnerability['line'],
                'affected_code': vulnerability['affected_code'],
                'first_commit': vulnerability['first_commit'],
                'last_commit': vulnerability['last_commit'],
                'username': vulnerability['username'],
                'date_found': vulnerability['date_found'],
                'last_seen': vulnerability['last_seen'],
                'state': vulnerability['state']
            })
        # We now update the bulk object
        bulk_code_vulnerabilities.update_one({'_id': exists.get('_id')}, {'$set': {
            'individual_issues': individual_issues
        }})
        # We return the modified object for redmine creation
        exists['individual_issues'] = individual_issues
        exists['_id'] = str(exists.get('_id'))
        return exists
    # This means there is no bulk issue object with the corresponding name
    else:
        individual_issues = [{
            '_id': vulnerability['_id'],
            'component': vulnerability['component'],
            'line': vulnerability['line'],
            'affected_code': vulnerability['affected_code'],
            'first_commit': vulnerability['first_commit'],
            'last_commit': vulnerability['last_commit'],
            'username': vulnerability['username'],
            'date_found': vulnerability['date_found'],
            'last_seen': vulnerability['last_seen'],
            'state': vulnerability['state']
        }]
        bulk_to_add = {
            'title': vulnerability['title'],
            'description': vulnerability['description'],
            'last_commit': vulnerability['last_commit'],
            'pipeline_name': vulnerability['pipeline_name'],
            'language':  vulnerability['language'],
            'severity_tool': vulnerability['severity_tool'],
            'observation': vulnerability['observation'],
            'last_seen': vulnerability['last_seen'],
            'cvss_score': vulnerability['cvss_score'],
            'state': 'new',
            'individual_issues': individual_issues
        }
        bulk_vuln_id = bulk_code_vulnerabilities.insert_one(bulk_to_add)
        bulk_to_add['_id'] = str(bulk_vuln_id.inserted_id)
        return bulk_to_add
    
'''
{
    "Title": "Absence of Anti-CSRF Tokens",
    "Description": "No Anti-CSRF tokens were found in a html submission form",
    "Domain": "altoromutual.com",
    "Resource": "http://altoromutual.com/",
    "Severity": "Low"
}
'''
def add_web_vuln_bis(vulnerability):
    exists = web_vulnerabilities.find_one({'domain': vulnerability['Domain'], 'resource': vulnerability['Resource'],
                                          'vulnerability_name': vulnerability['Title'],
                                          'language': settings['LANGUAGE']})
    if exists:
        web_vulnerabilities.update_one({'_id': exists.get('_id')}, {'$set': {
            'extra_info': vulnerability['Description'],
            'last_seen': datetime.now()
        }})
        return str(exists.get('_id'))
    else:
        resource = {
            'domain': vulnerability['Domain'],
            'resource': vulnerability['Resource'],
            'vulnerability_name': vulnerability['Title'],
            'observation': vulnerability['observation'],
            'extra_info': vulnerability['Description'],
            'image_string': None,
            'file_string': None,
            'date_found': datetime.now(),
            'last_seen': datetime.now(),
            'language': settings['LANGUAGE'],
            'cvss_score': vulnerability['cvss_score'],
            'vuln_type': vulnerability['vuln_type'],
            'state': 'new'
        }
        vuln_id = web_vulnerabilities.insert_one(resource)
        resource['_id'] = str(vuln_id.inserted_id)
        add_found_vulnerability_log(resource, vulnerability)
        add_web_vuln_to_elastic(resource)
        return str(resource.get('_id'))
    return



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
    # If the resource does not exist in our local database, we add it
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
        # TODO-Alert placeholder when new resource is found in monitor state
        if not scan_info['is_first_run']:
            slack.send_new_resource_found("New resource found! %s" % url_info['subdomain'], '#vm-recon-module')
        resource_id = resources.insert_one(resource)
        resource['_id'] = str(resource_id.inserted_id)
        module_keyword = 'on_demand_recon_module' if scan_info['is_first_run'] else 'monitor_recon_module'
        add_resource_log(resource, module_keyword, 'found')
        add_resource_to_elastic(resource)
    else:
        # TODO-Alert placeholder when dead existing subdomain appears as alive
        if not exists['is_alive'] and url_info['is_alive']:
            resource = {
                '_id': exists.get('_id'),
                'domain': exists.get('domain'),
                'subdomain': exists.get('subdomain')
            }
            module_keyword = 'on_demand_recon_module' if scan_info['is_first_run'] else 'monitor_recon_module'
            add_resource_log(resource, module_keyword, 'found')
        # TODO-Alert placeholder when alive subdomain changes IP address
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

def add_domain(scan_info, for_recon, for_monitor_scan):
    exists = domains.find_one({'domain': scan_info['domain']})
    if not exists:
        domains.insert_one({'domain': scan_info['domain'], 'for_recon':for_recon, 'for_vuln_monitor': for_monitor_scan})
    else:
        domains.update_one({'_id': exists.get('_id')},
         {'$set': 
            {
                'for_recon': for_recon,
                'for_vuln_monitor': for_monitor_scan
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
            'scanned': resource['scanned'],
            'approved': resource['approved'],
            'priority': resource['priority'],
            'exposition': resource['exposition'],
            'asset_value': resource['asset_value']
            }})



# -------------------- REDMINE --------------------
# Case where a new issue is added to redmine but does not appear on our local database
def add_custom_redmine_issue(redmine_issue):
    # We receive an issue, we will first check out the tracker
    if redmine_issue.tracker.id == REDMINE_IDS['WEB_FINDING']['FINDING_TRACKER']:
        # Web case
        add_custom_web_issue(redmine_issue)
    elif redmine_issue.tracker.id == REDMINE_IDS['INFRA_FINDING']['FINDING_TRACKER']:
        #Infra case
        add_custom_infra_issue(redmine_issue)
    elif redmine_issue.tracker.id == REDMINE_IDS['CODE_FINDING']['FINDING_TRACKER']:
        #Code case    
        add_custom_code_issue(redmine_issue)
    return

def add_custom_web_issue(redmine_issue):
    #We are going to suppose the resource exists on our local database
    #We will check first and send an exception if its not found
    
    #resource_exists = resources.find_one({'domain': redmine_issue.custom_fields.get(REDMINE_IDS['WEB_FINDING']['DOMAIN']).value,
    # 'subdomain': redmine_issue.custom_fields.get(REDMINE_IDS['WEB_FINDING']['RESOURCE']).value})
    #if not resource_exists:
    #    print('Failed adding custom redmine resource. Domain %s, resource %s' % 
    #    (redmine_issue.custom_fields.get(REDMINE_IDS['WEB_FINDING']['DOMAIN']).value,redmine_issue.custom_fields.get(REDMINE_IDS['WEB_FINDING']['RESOURCE']).value))
    #    return

    vuln_to_add = {
        'domain': redmine_issue.custom_fields.get(REDMINE_IDS['WEB_FINDING']['DOMAIN']).value,
        'resource': redmine_issue.custom_fields.get(REDMINE_IDS['WEB_FINDING']['RESOURCE']).value,
        'vulnerability_name': redmine_issue.subject,
        'observation': {
            'title': redmine_issue.subject,
            'observation_title': redmine_issue.custom_fields.get(REDMINE_IDS['WEB_FINDING']['KB_DESCRIPTION']).value,
            'observation_note': redmine_issue.custom_fields.get(REDMINE_IDS['WEB_FINDING']['KB_DESCRIPTION_NOTES']).value,
            'implication': redmine_issue.custom_fields.get(REDMINE_IDS['WEB_FINDING']['KB_IMPLICATION']).value,
            'recommendation_title': redmine_issue.custom_fields.get(REDMINE_IDS['WEB_FINDING']['KB_RECOMMENDATION']).value,
            'recommendation_note': redmine_issue.custom_fields.get(REDMINE_IDS['WEB_FINDING']['KB_RECOMMENDATION_NOTES']).value,
            'severity': redmine_issue.priority.name.upper()
        },
        'extra_info': redmine_issue.description,
        'image_string': None,
        'file_string': None,
        'date_found': datetime.now(),
        'last_seen': datetime.now(),
        'language': settings['LANGUAGE'],
        'cvss_score': float(redmine_issue.custom_fields.get(REDMINE_IDS['WEB_FINDING']['CVSS_SCORE']).value),
        'vuln_type': 'web',
        'state': 'new'
    }
    vuln_id = web_vulnerabilities.insert_one(vuln_to_add)
    vuln_to_add['_id'] = str(vuln_id.inserted_id)
    add_web_vuln_to_elastic(vuln_to_add)
    redmine.update_id_for_custom_issue(redmine_issue.id, REDMINE_IDS['WEB_FINDING']['IDENTIFIER'], vuln_to_add['_id'])
    return

def add_custom_infra_issue(redmine_issue):
    #We are going to suppose the resource exists on our local database
    #We will check first and send an exception if its not found
    
    #resource_exists = resources.find_one({'domain': redmine_issue.custom_fields.get(REDMINE_IDS['INFRA_FINDING']['DOMAIN']).value,
    # 'subdomain': redmine_issue.custom_fields.get(REDMINE_IDS['INFRA_FINDING']['RESOURCE']).value})
    #if not resource_exists:
    #    print('Failed adding custom redmine resource. Domain %s, resource %s' % 
    #    (redmine_issue.custom_fields.get(REDMINE_IDS['INFRA_FINDING']['DOMAIN']).value,redmine_issue.custom_fields.get(REDMINE_IDS['INFRA_FINDING']['RESOURCE']).value))
    #    return

    vuln_to_add = {
        'domain': redmine_issue.custom_fields.get(REDMINE_IDS['INFRA_FINDING']['DOMAIN']).value,
        'resource': redmine_issue.custom_fields.get(REDMINE_IDS['INFRA_FINDING']['RESOURCE']).value,
        'vulnerability_name': redmine_issue.subject,
        'observation': {
            'title': redmine_issue.subject,
            'observation_title': redmine_issue.custom_fields.get(REDMINE_IDS['INFRA_FINDING']['KB_DESCRIPTION']).value,
            'observation_note': redmine_issue.custom_fields.get(REDMINE_IDS['INFRA_FINDING']['KB_DESCRIPTION_NOTES']).value,
            'implication': redmine_issue.custom_fields.get(REDMINE_IDS['INFRA_FINDING']['KB_IMPLICATION']).value,
            'recommendation_title': redmine_issue.custom_fields.get(REDMINE_IDS['INFRA_FINDING']['KB_RECOMMENDATION']).value,
            'recommendation_note': redmine_issue.custom_fields.get(REDMINE_IDS['INFRA_FINDING']['KB_RECOMMENDATION_NOTES']).value,
            'severity': redmine_issue.priority.name.upper()
        },
        'extra_info': redmine_issue.description,
        'image_string': None,
        'file_string': None,
        'date_found': datetime.now(),
        'last_seen': datetime.now(),
        'language': settings['LANGUAGE'],
        'cvss_score': float(redmine_issue.custom_fields.get(REDMINE_IDS['INFRA_FINDING']['CVSS_SCORE']).value),
        'vuln_type': 'ip',
        'state': 'new'
    }
    vuln_id = infra_vulnerabilities.insert_one(vuln_to_add)
    vuln_to_add['_id'] = str(vuln_id.inserted_id)
    add_infra_vuln_to_elastic(vuln_to_add)
    redmine.update_id_for_custom_issue(redmine_issue.id, REDMINE_IDS['INFRA_FINDING']['IDENTIFIER'], vuln_to_add['_id'])

def add_custom_code_issue(redmine_issue):
    vuln_to_add = {
            'title': redmine_issue.subject,
            'description': redmine_issue.description,
            'component': redmine_issue.custom_fields.get(REDMINE_IDS['CODE_FINDING']["COMPONENT"]).value,
            'line': redmine_issue.custom_fields.get(REDMINE_IDS['CODE_FINDING']["LINE"]).value,
            'affected_code': redmine_issue.custom_fields.get(REDMINE_IDS['CODE_FINDING']["AFFECTED_CODE"]).value,
            'first_commit': redmine_issue.custom_fields.get(REDMINE_IDS['CODE_FINDING']["FIRST_COMMIT"]).value,
            'last_commit': redmine_issue.custom_fields.get(REDMINE_IDS['CODE_FINDING']["LAST_COMMIT"]).value,
            'username': redmine_issue.custom_fields.get(REDMINE_IDS['CODE_FINDING']["USERNAME"]).value,
            'pipeline_name': redmine_issue.custom_fields.get(REDMINE_IDS['CODE_FINDING']["PIPELINE_NAME"]).value,
            'language': settings['LANGUAGE'],
            'hash': None,
            'severity_tool': redmine_issue.custom_fields.get(REDMINE_IDS['CODE_FINDING']["TOOL_SEVERITY"]).value,
            'observation': {
                'title': redmine_issue.subject,
                'observation_title': redmine_issue.custom_fields.get(REDMINE_IDS['CODE_FINDING']['KB_DESCRIPTION']).value,
                'observation_note': redmine_issue.custom_fields.get(REDMINE_IDS['CODE_FINDING']['KB_DESCRIPTION_NOTES']).value,
                'implication': redmine_issue.custom_fields.get(REDMINE_IDS['CODE_FINDING']['KB_IMPLICATION']).value,
                'recommendation_title': redmine_issue.custom_fields.get(REDMINE_IDS['CODE_FINDING']['KB_RECOMMENDATION']).value,
                'recommendation_note': redmine_issue.custom_fields.get(REDMINE_IDS['CODE_FINDING']['KB_RECOMMENDATION_NOTES']).value,
                'severity': redmine_issue.priority.name.upper()
            },
            'date_found': datetime.now(),
            'last_seen': datetime.now(),
            'cvss_score': redmine_issue.custom_fields.get(REDMINE_IDS['CODE_FINDING']['CVSS_SCORE']).value,
            'vuln_type': 'code',
            'state': 'new'
        }
    vuln_id = code_vulnerabilities.insert_one(vuln_to_add)
    vuln_to_add['_id'] = str(vuln_id.inserted_id)
    add_code_vuln_to_elastic(vuln_to_add)
    redmine.update_id_for_custom_issue(redmine_issue.id, REDMINE_IDS['CODE_FINDING']['IDENTIFIER'], vuln_to_add['_id'])

    return

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
    # We update everything except the domain and resource.
    # First we get every information from the redmine issue
    new_vuln_name = redmine_issue.subject
    new_description = redmine_issue.description
    new_kb_description = redmine_issue.custom_fields.get(REDMINE_IDS['WEB_FINDING']['KB_DESCRIPTION']).value
    new_kb_description_notes = redmine_issue.custom_fields.get(REDMINE_IDS['WEB_FINDING']['KB_DESCRIPTION_NOTES']).value
    new_kb_implication = redmine_issue.custom_fields.get(REDMINE_IDS['WEB_FINDING']['KB_IMPLICATION']).value
    new_kb_recommendation = redmine_issue.custom_fields.get(REDMINE_IDS['WEB_FINDING']['KB_RECOMMENDATION']).value
    new_kb_recommendation_notes = redmine_issue.custom_fields.get(REDMINE_IDS['WEB_FINDING']['KB_RECOMMENDATION_NOTES']).value
    new_kb_severity = redmine_issue.priority.name.upper()
    cvss_score = redmine_issue.custom_fields.get(REDMINE_IDS['WEB_FINDING']['CVSS_SCORE']).value
    status_id = redmine_issue.status.id
    
    try: 
        vulnerability = web_vulnerabilities.find_one({'_id': ObjectId(redmine_issue.custom_fields.get(REDMINE_IDS['WEB_FINDING']['IDENTIFIER']).value)})
        # This is the case where the vuln does not exist in our database
        # Just in case the person enters a valid ID by chance
        if not vulnerability:
            print('Adding custom web vulnerability')
            add_custom_web_issue(redmine_issue)
            return
    # Invalid id exception
    except InvalidId:
        print('Adding custom web vulnerability')
        add_custom_web_issue(redmine_issue)
        return
    
    # Re doing observation based on the previous one
    new_observation = vulnerability['observation']
    new_observation['observation_title'] =  new_kb_description
    new_observation['observation_note'] = new_kb_description_notes
    new_observation['implication'] = new_kb_implication
    new_observation['recommendation_title'] = new_kb_recommendation
    new_observation['recommendation_note'] = new_kb_recommendation_notes
    new_observation['severity'] = new_kb_severity
    
    try:
        web_vulnerabilities.update_one({'_id': vulnerability.get('_id')}, {'$set': {
                'cvss_score': float(cvss_score),
                'observation': new_observation,
                'vulnerability_name': new_vuln_name,
                'extra_info': new_description
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
    # We update everything except the domain and resource.
    # First we get every information from the redmine issue
    new_vuln_name = redmine_issue.subject
    new_description = redmine_issue.description
    new_kb_description = redmine_issue.custom_fields.get(REDMINE_IDS['INFRA_FINDING']['KB_DESCRIPTION']).value
    new_kb_description_notes = redmine_issue.custom_fields.get(REDMINE_IDS['INFRA_FINDING']['KB_DESCRIPTION_NOTES']).value
    new_kb_implication = redmine_issue.custom_fields.get(REDMINE_IDS['INFRA_FINDING']['KB_IMPLICATION']).value
    new_kb_recommendation = redmine_issue.custom_fields.get(REDMINE_IDS['INFRA_FINDING']['KB_RECOMMENDATION']).value
    new_kb_recommendation_notes = redmine_issue.custom_fields.get(REDMINE_IDS['INFRA_FINDING']['KB_RECOMMENDATION_NOTES']).value
    new_kb_severity = redmine_issue.priority.name.upper()
    cvss_score = redmine_issue.custom_fields.get(REDMINE_IDS['INFRA_FINDING']['CVSS_SCORE']).value
    status_id = redmine_issue.status.id

    try:
        vulnerability = infra_vulnerabilities.find_one({'_id': ObjectId(redmine_issue.custom_fields.get(REDMINE_IDS['INFRA_FINDING']['IDENTIFIER']).value)})
        # This is the case where the vuln does not exist in our database
        # Just in case the person enters a valid ID by chance
        if not vulnerability:
            print('Adding custom infra vulnerability')
            add_custom_infra_issue(redmine_issue)
            return
    # Invalid id exception
    except InvalidId:
        print('Adding custom infra vulnerability')
        add_custom_infra_issue(redmine_issue)
        return

    # Re doing observation based on the previous one
    new_observation = vulnerability['observation']
    new_observation['observation_title'] =  new_kb_description
    new_observation['observation_note'] = new_kb_description_notes
    new_observation['implication'] = new_kb_implication
    new_observation['recommendation_title'] = new_kb_recommendation
    new_observation['recommendation_note'] = new_kb_recommendation_notes
    new_observation['severity'] = new_kb_severity

    try:
        infra_vulnerabilities.update_one({'_id': vulnerability.get('_id')}, {'$set': {
                'cvss_score': float(cvss_score),
                'observation': new_observation,
                'vulnerability_name': new_vuln_name,
                'extra_info': new_description
            }})
    except ValueError:
        pass

    if status_id == REDMINE_IDS['STATUS_SOLVED']:
        infra_vulnerabilities.update_one({'_id': vulnerability.get('_id')}, {'$set': {
            'state': 'resolved' 
        }})
    elif status_id == REDMINE_IDS['STATUS_CLOSED']:
        infra_vulnerabilities.update_one({'_id': vulnerability.get('_id')}, {'$set': {
            'state': 'closed' 
        }})
    elif status_id == REDMINE_IDS['STATUS_CONFIRMED']:
        infra_vulnerabilities.update_one({'_id': vulnerability.get('_id')}, {'$set': {
            'state': 'confirmed' 
        }})
    elif status_id == REDMINE_IDS['STATUS_REJECTED']:
        infra_vulnerabilities.update_one({'_id': vulnerability.get('_id')}, {'$set': {
            'state': 'rejected' 
        }})
    return

def update_code_finding(redmine_issue):
    # We update everything except the domain and resource.
    # First we get every information from the redmine issue
    new_vuln_name = redmine_issue.subject
    new_description = redmine_issue.description
    new_kb_description = redmine_issue.custom_fields.get(REDMINE_IDS['CODE_FINDING']['KB_DESCRIPTION']).value
    new_kb_description_notes = redmine_issue.custom_fields.get(REDMINE_IDS['CODE_FINDING']['KB_DESCRIPTION_NOTES']).value
    new_kb_implication = redmine_issue.custom_fields.get(REDMINE_IDS['CODE_FINDING']['KB_IMPLICATION']).value
    new_kb_recommendation = redmine_issue.custom_fields.get(REDMINE_IDS['CODE_FINDING']['KB_RECOMMENDATION']).value
    new_kb_recommendation_notes = redmine_issue.custom_fields.get(REDMINE_IDS['CODE_FINDING']['KB_RECOMMENDATION_NOTES']).value
    new_kb_severity = redmine_issue.priority.name.upper()
    cvss_score = redmine_issue.custom_fields.get(REDMINE_IDS['CODE_FINDING']['CVSS_SCORE']).value
    status_id = redmine_issue.status.id

    #Custom fields specific to code findings
    new_component = redmine_issue.custom_fields.get(REDMINE_IDS['CODE_FINDING']["COMPONENT"]).value
    new_line = redmine_issue.custom_fields.get(REDMINE_IDS['CODE_FINDING']["LINE"]).value
    new_affected_code = redmine_issue.custom_fields.get(REDMINE_IDS['CODE_FINDING']["AFFECTED_CODE"]).value
    new_first_commit = redmine_issue.custom_fields.get(REDMINE_IDS['CODE_FINDING']["FIRST_COMMIT"]).value
    new_last_commit = redmine_issue.custom_fields.get(REDMINE_IDS['CODE_FINDING']["LAST_COMMIT"]).value
    new_username = redmine_issue.custom_fields.get(REDMINE_IDS['CODE_FINDING']["USERNAME"]).value
    new_pipeline_name = redmine_issue.custom_fields.get(REDMINE_IDS['CODE_FINDING']["PIPELINE_NAME"]).value
    new_tool_severity = redmine_issue.custom_fields.get(REDMINE_IDS['CODE_FINDING']["TOOL_SEVERITY"]).value

    try:
        vulnerability = code_vulnerabilities.find_one({'_id': ObjectId(redmine_issue.custom_fields.get(REDMINE_IDS['CODE_FINDING']['IDENTIFIER']).value)})
        # This is the case where the vuln does not exist in our database
        # Just in case the person enters a valid ID by chance
        if not vulnerability:
            print('Adding custom code vulnerability')
            add_custom_code_issue(redmine_issue)
            return
    # Invalid id exception
    except InvalidId:
        print('Adding custom code vulnerability')
        add_custom_code_issue(redmine_issue)
        return

    # Re doing observation based on the previous one
    new_observation = vulnerability['observation']
    new_observation['observation_title'] =  new_kb_description
    new_observation['observation_note'] = new_kb_description_notes
    new_observation['implication'] = new_kb_implication
    new_observation['recommendation_title'] = new_kb_recommendation
    new_observation['recommendation_note'] = new_kb_recommendation_notes
    new_observation['severity'] = new_kb_severity

    try:
        code_vulnerabilities.update_one({'_id': vulnerability.get('_id')}, {'$set': {
                'cvss_score': float(cvss_score),
                'observation': new_observation,
                'title': new_vuln_name,
                'description': new_description,
                'component': new_component,
                'line': new_line,
                'affected_code': new_affected_code,
                'first_commit': new_first_commit,
                'last_commit': new_last_commit,
                'username': new_username,
                'pipeline_name': new_pipeline_name,
                'severity_tool': new_tool_severity
            }})
    except ValueError:
        pass

    if status_id == REDMINE_IDS['STATUS_SOLVED']:
        code_vulnerabilities.update_one({'_id': vulnerability.get('_id')}, {'$set': {
            'state': 'resolved' 
        }})
    elif status_id == REDMINE_IDS['STATUS_CLOSED']:
        code_vulnerabilities.update_one({'_id': vulnerability.get('_id')}, {'$set': {
            'state': 'closed' 
        }})
    elif status_id == REDMINE_IDS['STATUS_CONFIRMED']:
        code_vulnerabilities.update_one({'_id': vulnerability.get('_id')}, {'$set': {
            'state': 'confirmed' 
        }})
    elif status_id == REDMINE_IDS['STATUS_REJECTED']:
        code_vulnerabilities.update_one({'_id': vulnerability.get('_id')}, {'$set': {
            'state': 'rejected' 
        }})
    elif status_id == REDMINE_IDS['STATUS_NEW_VERIFY']:
        code_vulnerabilities.update_one({'_id': vulnerability.get('_id')}, {'$set': {
            'state': 'new-verify' 
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
    if ELASTIC_CLIENT is None:
        return
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
    if not vuln['observation']:
        observation_data = {
        'vulnerability_observation_title': '<TO DEFINE>',
        'vulnerability_observation_note': '<TO DEFINE>',
        'vulnerability_implication': '<TO DEFINE>',
        'vulnerability_recommendation_title': '<TO DEFINE>',
        'vulnerability_recommendation_note': '<TO DEFINE>',
        'vulnerability_severity': '<TO DEFINE>'
        }
    else:
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

    if not vuln['observation']:
        observation_data = {
        'vulnerability_observation_title': '<TO DEFINE>',
        'vulnerability_observation_note': '<TO DEFINE>',
        'vulnerability_implication': '<TO DEFINE>',
        'vulnerability_recommendation_title': '<TO DEFINE>',
        'vulnerability_recommendation_note': '<TO DEFINE>',
        'vulnerability_severity': '<TO DEFINE>'
        }
    else:
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
        'vulnerability_branch': vuln['branch'],
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
    if ELASTIC_CLIENT is None:
        return
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
# TODO-Alert placeholder when a vulnerability is found
# We can check here if the vuln comes from monitor or manual scans
def add_found_vulnerability_log(vulnerability, vuln_obj=None):
    if ELASTIC_CLIENT is None:
        return
    module_keyword = 'code' if vuln_obj is None else vuln_obj.module_identifier
    vuln_name = vulnerability['title'] if vuln_obj is None else vulnerability['vulnerability_name']
    log_to_add = {
        "log_vulnerability_module_keyword": module_keyword,
        "log_vulnerability_found": True,
        "log_vulnerability_id": str(vulnerability['_id']),
        "log_vulnerability_name": vuln_name,
        "log_vulnerability_timestamp": datetime.now()
    }
    log_id = logs.insert_one(log_to_add)
    log_to_add['log_id'] = str(log_to_add.pop('_id'))
    res = ELASTIC_CLIENT.index(index='log_vuln',doc_type='_doc',id=log_to_add['log_id'],body=log_to_add)

# We log if a vuln is not found
def add_not_found_vulnerability_log(vulnerability):
    if ELASTIC_CLIENT is None:
        return
    log_id = logs.insert_one({})
    #res = ELASTIC_CLIENT.index(index='log',doc_type='_doc',id=log_to_add['log_id'],body=log_to_add)

# We log if a resource is found. IT can be from a recon or a monitor
def add_resource_log(resource, module_keyword, state):
    if ELASTIC_CLIENT is None:
        return
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
    vulns = []
    vulns.extend(list(web_vulnerabilities.find({'state': 'resolved'})))
    vulns.extend(list(infra_vulnerabilities.find({'state': 'resolved'})))
    vulns.extend(list(code_vulnerabilities.find({'state': 'resolved'})))
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

def get_all_observations(normalize_id = False):
    return_list = list()
    found_observations = observations.find({})
    for value in found_observations:
        if normalize_id:
            value['id'] = value.pop('_id')
        return_list.append(value)
    return return_list

def get_all_resources():
    return_list = list()
    found_resources = resources.find()
    for resource in found_resources:
        return_list.append(resource)
    return return_list

def get_specific_observation(mongo_id):
    return observations.find_one({'_id': ObjectId(mongo_id)})

def get_domains():
    return_list = list()
    found_domains = domains.find()
    for domain in found_domains:
        return_list.append(domain)
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

def update_observation(new_observation, mongo_observation):
    observations.update_one({'_id': mongo_observation.get('_id')}, {'$set': {
            'OBSERVATION': {
                'TITLE': new_observation['description'],
                'NOTE': new_observation['description_note']
            },
            'IMPLICATION': new_observation['implication'],
            'RECOMMENDATION': {
                'TITLE': new_observation['recommendation'],
                'URLS': new_observation['recommendation_note']
            },
            'SEVERITY': new_observation['severity']
        }})
    return
