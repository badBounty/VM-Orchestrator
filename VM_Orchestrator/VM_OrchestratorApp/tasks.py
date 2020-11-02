# pylint: disable=import-error
from celery import shared_task, chain, chord
from celery.task import periodic_task
from celery.schedules import crontab

from datetime import datetime, date
import pandas as pd
import copy
import os

from VM_OrchestratorApp.src.recon import initial_recon, aquatone, httprobe
from VM_OrchestratorApp.src.utils import email_handler
from VM_OrchestratorApp.src.scanning import header_scan, http_method_scan, ssl_tls_scan,\
    cors_scan, ffuf, libraries_scan, bucket_finder, token_scan, css_scan,\
    firebase_scan, nmap_script_scan,nmap_script_baseline, host_header_attack, \
    iis_shortname_scanner, burp_scan, nessus_scan, acunetix_scan
from VM_Orchestrator.settings import settings
from VM_OrchestratorApp.src.utils import mongo, slack, redmine
from VM_OrchestratorApp.src import constants



# -------------------- RECON -------------------- #
@shared_task
def subdomain_recon_task(scan_info):
    initial_recon.run_recon(scan_info)
    return

@shared_task
def resolver_recon_task(scan_info):
    subdomains = mongo.get_alive_subdomains_for_resolve(scan_info['domain'])
    if len(subdomains) == 0:
        return
    aquatone.start_aquatone(subdomains, scan_info)
    httprobe.start_httprobe(subdomains, scan_info)
    return



# -------------------- SCANNING TASKS -------------------- #
@shared_task
def run_specific_module(scan_information):
    print("run_spec...")
    scan_information['scan_type'] = 'target'
    scan_information['language'] = settings['LANGUAGE']
    scan_information['invasive_scans'] = True
    # We need to choose which module to run
    function_to_run = module_name_switcher(scan_information['module_identifier'])
    function_to_run(scan_information)
    return

def module_name_switcher(module_name): # Si hay varios para un identifier poner uno solo (ejemplo "SSL_TLS_CIPHERS")
    switcher = {
        constants.INVALID_VALUE_ON_HEADER['module_identifier']: header_scan_task,
        constants.HOST_HEADER_ATTACK['module_identifier']: host_header_attack_scan, 
        constants.UNSECURE_METHOD['module_identifier']: http_method_scan_task, 
        constants.SSL_TLS_CIPHERS['module_identifier']: ssl_tls_scan_task, 
        constants.OUTDATED_3RD_LIBRARIES['module_identifier']: libraries_scan_task, 
        constants.CORS['module_identifier']: cors_scan_task, 
        constants.ENDPOINT['module_identifier']: ffuf_task, 
        constants.BUCKET['module_identifier']: bucket_finder_task, 
        constants.TOKEN_SENSITIVE_INFO['module_identifier']: token_scan_task, 
        constants.CSS_INJECTION['module_identifier']: css_scan_task, 
        constants.OPEN_FIREBASE['module_identifier']: firebase_scan_task, 
        constants.IIS_SHORTNAME_MICROSOFT['module_identifier']: iis_shortname_scan_task,
        constants.HTTP_PASSWD_NMAP['module_identifier']: nmap_script_scan_task,
        constants.PLAINTEXT_COMUNICATION['module_identifier']: nmap_script_baseline_task,
        constants.BURP_SCAN['module_identifier']: burp_scan_task,
        constants.NESSUS_SCAN['module_identifier']: nessus_scan_task,
        constants.ACUNETIX_SCAN['module_identifier']: acunetix_scan_task
    }
    return switcher.get(module_name)

@shared_task
def header_scan_task(scan_information):
    if scan_information['scan_type'] == 'single':
        header_scan.handle_single(scan_information)
    elif scan_information['scan_type'] == 'target':
        header_scan.handle_target(scan_information)

@shared_task
def http_method_scan_task(scan_information):
    if scan_information['scan_type'] == 'single':
        http_method_scan.handle_single(scan_information)
    elif scan_information['scan_type'] == 'target':
        http_method_scan.handle_target(scan_information)

@shared_task
def cors_scan_task(scan_information):
    if scan_information['scan_type'] == 'single':
        cors_scan.handle_single(scan_information)
    elif scan_information['scan_type'] == 'target':
        cors_scan.handle_target(scan_information)

@shared_task
def libraries_scan_task(scan_information):
    if scan_information['scan_type'] == 'single':
        libraries_scan.handle_single(scan_information)
    elif scan_information['scan_type'] == 'target':
        libraries_scan.handle_target(scan_information)

@shared_task
def ssl_tls_scan_task(scan_information):
    if scan_information['scan_type'] == 'single':
        ssl_tls_scan.handle_single(scan_information)
    elif scan_information['scan_type'] == 'target':
        ssl_tls_scan.handle_target(scan_information)

@shared_task
def ffuf_task(scan_information):
    if scan_information['scan_type'] == 'single':
        ffuf.handle_single(scan_information)
    elif scan_information['scan_type'] == 'target':
        ffuf.handle_target(scan_information)

@shared_task
def nmap_script_scan_task(scan_information):
    if scan_information['scan_type'] == 'single':
        nmap_script_scan.handle_single(scan_information)
    elif scan_information['scan_type'] == 'target':
        nmap_script_scan.handle_target(scan_information)

@shared_task
def nmap_script_baseline_task(scan_information):
    if scan_information['scan_type'] == 'single':
        nmap_script_baseline.handle_single(scan_information)
    elif scan_information['scan_type'] == 'target':
        nmap_script_baseline.handle_target(scan_information)
        
@shared_task
def iis_shortname_scan_task(scan_information):
    if scan_information['scan_type'] == 'single':
        iis_shortname_scanner.handle_single(scan_information)
    elif scan_information['scan_type'] == 'target':
        iis_shortname_scanner.handle_target(scan_information)

@shared_task
def bucket_finder_task(scan_information):
    if scan_information['scan_type'] == 'single':
        bucket_finder.handle_single(scan_information)
    elif scan_information['scan_type'] == 'target':
        bucket_finder.handle_target(scan_information)

@shared_task
def token_scan_task(scan_information):
    if scan_information['scan_type'] == 'single':
        token_scan.handle_single(scan_information)
    elif scan_information['scan_type'] == 'target':
        token_scan.handle_target(scan_information)

@shared_task
def css_scan_task(scan_information):
    if scan_information['scan_type'] == 'single':
        css_scan.handle_single(scan_information)
    elif scan_information['scan_type'] == 'target':
        css_scan.handle_target(scan_information)

@shared_task
def firebase_scan_task(scan_information):
    if scan_information['scan_type'] == 'single':
        firebase_scan.handle_single(scan_information)
    elif scan_information['scan_type'] == 'target':
        firebase_scan.handle_target(scan_information)

@shared_task
def host_header_attack_scan(scan_information):
    if scan_information['scan_type'] == 'single':
        host_header_attack.handle_single(scan_information)
    elif scan_information['scan_type'] == 'target':
        host_header_attack.handle_target(scan_information)

@shared_task
def burp_scan_task(scan_information):
    if scan_information['scan_type'] == 'single':
        burp_scan.handle_single(scan_information)
    elif scan_information['scan_type'] == 'target':
        burp_scan.handle_target(scan_information)

@shared_task
def nessus_scan_task(scan_information):
    if scan_information['scan_type'] == 'single':
        nessus_scan.handle_single(scan_information)
    elif scan_information['scan_type'] == 'target':
        nessus_scan.handle_target(scan_information)

@shared_task
def acunetix_scan_task(scan_information):
    if scan_information['scan_type'] == 'single':
        acunetix_scan.handle_single(scan_information)
    elif scan_information['scan_type'] == 'target':
        acunetix_scan.handle_target(scan_information)



# -------------------- PREDEFINED TASKS -------------------- #
@shared_task
def run_recon(scan_information):
    slack.send_notification_to_channel('Starting recon against %s' % scan_information['domain'], '#vm-recon-module')
    mongo.add_module_status_log({
        'module_keyword': "recon_module",
        'state': "start",
        'domain': scan_information['domain'], #En los casos de start/stop de genericos, va None
        'found': None,
        'arguments': scan_information
    })

    #We add the domain to our domain database
    mongo.add_domain(scan_information, True)
    # Scanning for subdomains
    subdomain_recon_task(scan_information)
    # We resolve to get http/https urls
    resolver_recon_task(scan_information)

    mongo.add_module_status_log({
        'module_keyword': "recon_module",
        'state': "start",
        'domain': scan_information['domain'], #En los casos de start/stop de genericos, va None
        'found': None,
        'arguments': scan_information
    })
    recon_finished(scan_information)
    return

@shared_task
def run_web_scanners(scan_information):
    # Deep copy just in case
    web_information = copy.deepcopy(scan_information)

    if web_information['type'] == 'domain':
        web_information['scan_type'] = 'target'
        web_information['target'] = web_information['domain']
        subdomains_http = mongo.get_responsive_http_resources(web_information['domain'])
        only_urls = list()
        for subdomain in subdomains_http:
            only_urls.append(subdomain['url'])
        web_information['target'] = only_urls

    # Chain is defined
    # We flag the scanned resources as 'scanned'
    execution_chord =chord(
        [
            # Fast_scans
            header_scan_task.s(web_information).set(queue='fast_queue'),
            http_method_scan_task.s(web_information).set(queue='fast_queue'),
            libraries_scan_task.s(web_information).set(queue='fast_queue'),
            ffuf_task.s(web_information).set(queue='fast_queue'),
            iis_shortname_scan_task.s(web_information).set(queue='fast_queue'),
            bucket_finder_task.s(web_information).set(queue='fast_queue'),
            token_scan_task.s(web_information).set(queue='fast_queue'),
            css_scan_task.s(web_information).set(queue='fast_queue'),
            firebase_scan_task.s(web_information).set(queue='fast_queue'),
            host_header_attack_scan.s(web_information).set(queue='fast_queue'),
            # Slow_scans
            cors_scan_task.s(web_information).set(queue='slow_queue'),
            ssl_tls_scan_task.s(web_information).set(queue='slow_queue'),
            acunetix_scan_task.s(web_information).set(queue='acunetix_queue'),
            burp_scan_task.s(web_information).set(queue='burp_queue')
        ],
        body=web_security_scan_finished.s().set(queue='fast_queue'),
        immutable=True)
    execution_chord.apply_async(queue='fast_queue', interval=60)
    return

@shared_task
def run_ip_scans(scan_information):
    # Deepcopy just in case
    ip_information = copy.deepcopy(scan_information)
    
    if ip_information['type'] == 'domain':
        ip_information['scan_type'] = 'target'
        ip_information['target'] = ip_information['domain']
        subdomains_plain = mongo.get_alive_subdomains_from_target(ip_information['domain'])
        only_subdomains = list()
        for subdomain in subdomains_plain:
            only_subdomains.append(subdomain['subdomain'])
        ip_information['target'] = only_subdomains

    # We will flag the resource as scanned here, mainly because all alive resources will reach this point
    execution_chord = chord(
        [
            nmap_script_baseline_task.s(ip_information).set(queue='slow_queue'),
            nmap_script_scan_task.s(ip_information).set(queue='slow_queue'),
            nessus_scan_task.s(ip_information).set(queue='slow_queue')
        ],
        body=ip_security_scan_finished.s(ip_information).set(queue='fast_queue'),
        immutable=True)
    execution_chord.apply_async(queue='fast_queue', interval=60)
    return

@shared_task
def approve_resources(information):
    print('Handling uploaded file...')
    mongo.approve_resources(information)

@shared_task
def add_scanned_resources(scan_info):
    #Here we flag the resource as 'scanned'
    if scan_info['type'] == 'domain':
        scan_info['scan_type'] = 'target'
        subdomains_plain = mongo.get_alive_subdomains_from_target(scan_info['domain'])
        only_subdomains = list()
        for subdomain in subdomains_plain:
            only_subdomains.append(subdomain['subdomain'])
        scan_info['target'] = only_subdomains
    else:
        scan_info['scan_type'] = 'single'
        scan_info['target'] = scan_info['resource']

    mongo.add_scanned_resources(scan_info)
    return

@shared_task
def add_code_vuln(data):
    # We add some extra info, this will probably come in the request in the future
    data['vuln_type'] = 'code'
    data['observation'] = {
            'title': None,
            'observation_title': None,
            'observation_note': None,
            'implication': None,
            'recommendation_title': None,
            'recommendation_note': None,
            'severity': data['Severity_tool']
    }
    data['cvss_score'] = 0
    data['_id'] = mongo.add_code_vuln(data)
    redmine.create_new_code_issue(data)
    return



# -------------------- TASK CALLBACKS -------------------- #
@shared_task
def on_demand_scan_finished(results, information):
    add_scanned_resources(information)
    slack.send_notification_to_channel('_ On demand scan against %s finished! _' % information['resource'], '#vm-ondemand')
    return

@shared_task
def web_security_scan_finished(results):
    print('Web security scan finished!')
    return

@shared_task
def ip_security_scan_finished(results, info):
    print('IP security scan finished!')
    return

@shared_task
def recon_finished(scan_information):
    slack.send_notification_to_channel('_ Recon against %s finished _' % scan_information['domain'], '#vm-recon-module')
    print('Recon finished!')
    return


# ------ PERIODIC TASKS ------ #
# We monitor assets on our domain database
@periodic_task(run_every=crontab(hour=settings['PROJECT']['RECON_START_HOUR'], minute=settings['PROJECT']['RECON_START_MINUTE']),
queue='slow_queue', options={'queue': 'slow_queue'})
def project_monitor_task():
    monitor_data = mongo.get_domains_for_monitor()
    mongo.add_module_status_log({
        'module_keyword': "monitor_recon_module",
        'state': "start",
        'domain': None, #En los casos de start/stop de genericos, va None
        'found': None,
        'arguments': monitor_data
    })
    print(monitor_data)
    slack.send_notification_to_channel('Starting monitor against %s' % str(monitor_data), '#vm-monitor')
    for data in monitor_data:
        scan_info = data
        scan_info['is_first_run'] = False
        scan_info['email'] = None
        scan_info['type'] = 'domain'
        if scan_info['type'] == 'domain':
            run_recon.apply_async(args=[scan_info], queue='fast_queue')
    return

@periodic_task(run_every=crontab(hour=settings['PROJECT']['SCAN_START_HOUR'], minute=settings['PROJECT']['SCAN_START_MINUTE']),
queue='slow_queue', options={'queue': 'slow_queue'})
def start_scan_on_approved_resources():
    slack.send_notification_to_channel('_ Starting scan against approved resources _', '#vm-ondemand')
    resources = mongo.get_data_for_approved_scan()
    print(resources)
    for resource in resources:
        scan_info = resource
        scan_info['email'] = None
        scan_info['nessus_scan'] = settings['PROJECT']['ACTIVATE_NESSUS']
        scan_info['acunetix_scan'] = settings['PROJECT']['ACTIVATE_ACUNETIX']
        scan_info['burp_scan'] = settings['PROJECT']['ACTIVATE_BURP']
        scan_info['invasive_scans'] = settings['PROJECT']['ACTIVATE_INVASIVE_SCANS']
        mongo.add_module_status_log({
            'module_keyword': "general_vuln_module",
            'state': "start",
            'domain': scan_info['domain'], #En los casos de start/stop de genericos, va None
            'found': None,
            'arguments': scan_info
        })
        if scan_info['type'] == 'domain':
            execution_chord= chord(
                    [
                        run_web_scanners.si(scan_info).set(queue='fast_queue'),
                        run_ip_scans.si(scan_info).set(queue='slow_queue')
                    ],
                    body=on_demand_scan_finished.s(scan_info).set(queue='fast_queue'),
                    immutable = True
                )
            execution_chord.apply_async(queue='fast_queue', interval=300)
        elif scan_info['type'] == 'ip':
            execution_chord = chord(
                    [
                        run_ip_scans.si(scan_info).set(queue='slow_queue')
                    ],
                    body=on_demand_scan_finished.s(scan_info).set(queue='fast_queue'),
                    immutable = True
                )
            execution_chord.apply_async(queue='fast_queue', interval=300)
        elif scan_info['type'] == 'url':
            execution_chord = chord(
                    [
                        run_web_scanners.si(scan_info).set(queue='fast_queue'),
                        run_ip_scans.si(scan_info).set(queue='slow_queue')
                    ],
                    body=on_demand_scan_finished.s(scan_info).set(queue='fast_queue'),
                    immutable = True
                )
            execution_chord.apply_async(queue='fast_queue', interval=300)
    return

@periodic_task(run_every=crontab(hour=0, minute=0),
queue='slow_queue', options={'queue': 'slow_queue'})
def monitor_resolved_issues():
    #We first get our local vuln list from constants.
    nmap_scripts_vulns = [constants.OUTDATED_SOFTWARE_NMAP, constants.HTTP_PASSWD_NMAP, constants.WEB_VERSIONS_NMAP, 
    constants.ANON_ACCESS_FTP, constants.CRED_ACCESS_FTP, constants.DEFAULT_CREDS, constants.POSSIBLE_ERROR_PAGES]

    nmap_baseline_vulns = [constants.PLAINTEXT_COMUNICATION, constants.UNNECESSARY_SERVICES]

    valid_web_vulns = [constants.INVALID_VALUE_ON_HEADER, constants.HEADER_NOT_FOUND, constants.HOST_HEADER_ATTACK, 
    constants.UNSECURE_METHOD, constants.SSL_TLS_CIPHERS, constants.SSL_TLS_CERTIFICATE, constants.OUTDATED_3RD_LIBRARIES, constants.CORS, constants.ENDPOINT, 
    constants.BUCKET, constants.TOKEN_SENSITIVE_INFO, constants.CSS_INJECTION, constants.OPEN_FIREBASE, 
    constants.IIS_SHORTNAME_MICROSOFT]
    # We now get all the vulns that are resolved
    resolved_vulns = mongo.get_resolved_vulnerabilities()
    # We need to filter out vulnerabilities that come from the same tool. This way we wont run the same scan twice
    # we will create a sort of "queue" for the scans
    scan_queue = list()
    for vulnerability in resolved_vulns:
        # Only a target and domain is needed.
        if 'NESSUS' in vulnerability['vulnerability_name']:
            scan_to_add = {
                'domain': vulnerability['domain'],
                'resource': vulnerability['resource'],
                'function': nessus_scan_task
            }
            if scan_to_add not in scan_queue:
                scan_queue.append(scan_to_add)
        elif 'BURP' in vulnerability['vulnerability_name']:
            scan_to_add = {
                'domain': vulnerability['domain'],
                'resource': vulnerability['resource'],
                'function': burp_scan_task
            }
            if scan_to_add not in scan_queue:
                scan_queue.append(scan_to_add)
        elif 'ACUNETIX' in vulnerability['vulnerability_name']:
            scan_to_add = {
                'domain': vulnerability['domain'],
                'resource': vulnerability['resource'],
                'function': acunetix_scan_task
            }
            if scan_to_add not in scan_queue:
                scan_queue.append(scan_to_add)
        # Check the vuln name with nmap lists for nmap scans
        for nmap_script_vuln in nmap_scripts_vulns:
            if (vulnerability['vulnerability_name'] == nmap_script_vuln['english_name']) or (vulnerability['vulnerability_name'] == nmap_script_vuln['spanish_name']):
                scan_to_add = {
                    'domain': vulnerability['domain'],
                    'resource': vulnerability['resource'],
                    'function': nmap_script_scan_task
                }
                if scan_to_add not in scan_queue:
                    scan_queue.append(scan_to_add)
                else:
                    # This means at least one vuln coming from nmap scripts was found, so we need to re run the scan
                    break
        for nmap_baseline_vuln in nmap_baseline_vulns:
            if (vulnerability['vulnerability_name'] == nmap_baseline_vuln['english_name']) or (vulnerability['vulnerability_name'] == nmap_baseline_vuln['spanish_name']):
                scan_to_add = {
                    'domain': vulnerability['domain'],
                    'resource': vulnerability['resource'],
                    'function': nmap_script_baseline_task
                }
                if scan_to_add not in scan_queue:
                    scan_queue.append(scan_to_add)
                else:
                    # This means at least one vuln coming from nmap scripts was found, so we need to re run the scan
                    break
        for web_vuln in valid_web_vulns:
            if (vulnerability['vulnerability_name'] == web_vuln['english_name']) or (vulnerability['vulnerability_name'] == web_vuln['spanish_name']):
                scan_to_add = {
                        'domain': vulnerability['domain'],
                        'resource': vulnerability['resource'],
                        'function': task_name_switcher(vulnerability['vulnerability_name'])
                    }
                # It should never happen that the same vulnerability repeats itself on our database
                scan_queue.append(scan_to_add)
    
    # We now have a list of scans we need to execute
    # a json will be created and the scan will start
    # this will replicate the json needed for a traditional scan
    for scan in scan_queue:
        scan_info = {
            'scan_type': 'target',
            'target': scan['resource'],
            'domain': scan['domain']
        }
        scan['task'].apply_async(args=[scan_info], queue='fast_queue')
    return

def task_name_switcher(vulnerability_name):
    switcher = {
        constants.INVALID_VALUE_ON_HEADER['english_name']: header_scan_task, 
        constants.HEADER_NOT_FOUND['english_name']: header_scan_task, 
        constants.HOST_HEADER_ATTACK['english_name']: host_header_attack_scan, 
        constants.UNSECURE_METHOD['english_name']: http_method_scan_task, 
        constants.SSL_TLS_CIPHERS['english_name']: ssl_tls_scan_task, 
        constants.OUTDATED_3RD_LIBRARIES['english_name']: libraries_scan_task, 
        constants.CORS['english_name']: cors_scan_task, 
        constants.ENDPOINT['english_name']: ffuf_task, 
        constants.BUCKET['english_name']: bucket_finder_task, 
        constants.TOKEN_SENSITIVE_INFO['english_name']: token_scan_task, 
        constants.CSS_INJECTION['english_name']: css_scan_task, 
        constants.OPEN_FIREBASE['english_name']: firebase_scan_task, 
        constants.IIS_SHORTNAME_MICROSOFT['english_name']: iis_shortname_scan_task,
        #
        constants.INVALID_VALUE_ON_HEADER['spanish_name']: header_scan_task, 
        constants.HEADER_NOT_FOUND['spanish_name']: header_scan_task, 
        constants.HOST_HEADER_ATTACK['spanish_name']: host_header_attack_scan, 
        constants.UNSECURE_METHOD['spanish_name']: http_method_scan_task, 
        constants.SSL_TLS_CIPHERS['spanish_name']: ssl_tls_scan_task, 
        constants.OUTDATED_3RD_LIBRARIES['spanish_name']: libraries_scan_task, 
        constants.CORS['spanish_name']: cors_scan_task, 
        constants.ENDPOINT['spanish_name']: ffuf_task, 
        constants.BUCKET['spanish_name']: bucket_finder_task, 
        constants.TOKEN_SENSITIVE_INFO['spanish_name']: token_scan_task, 
        constants.CSS_INJECTION['spanish_name']: css_scan_task, 
        constants.OPEN_FIREBASE['spanish_name']: firebase_scan_task, 
        constants.IIS_SHORTNAME_MICROSOFT['spanish_name']: iis_shortname_scan_task
    }
    return switcher.get(vulnerability_name)

@periodic_task(run_every=crontab(hour=0, minute=0), 
queue='slow_queue', options={'queue': 'slow_queue'})
@shared_task
def check_redmine_for_updates():
    print('Synchronizing redmine')
    issues = redmine.get_issues_from_project()
    for issue in issues:
        mongo.update_issue_if_needed(issue)
    return

@periodic_task(run_every=crontab(minute='0', hour='*/12'),
queue='fast_queue', options={'queue':'slow_queue'})
@shared_task
def update_elasticsearch():
    mongo.update_elasticsearch()

# This was created for reseting elasticsearch logs database
@shared_task
def update_elasticsearch_logs():
    mongo.update_elasticsearch_logs()

# TODO-Alert placeholder for checking if a subdomain and or vuln has not been seen in some time
# Only vulns that are being scanned by the monitor task will be removed if not seen in a while
# This will become a periodic task
@shared_task
def check_for_alive_database_resources():
    return

# TODO-Alert placeholder for running very light scans in a monitor way
# This will become a periodic task
@shared_task
def vulnerability_monitor_task():
    return