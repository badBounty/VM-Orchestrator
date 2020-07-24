# pylint: disable=import-error
from celery import shared_task, chain, chord
from celery.task import periodic_task
from celery.schedules import crontab

from datetime import datetime, date
import pandas as pd
import copy
import os

from VM_OrchestratorApp.src.recon import initial_recon, aquatone
from VM_OrchestratorApp.src.scanning import header_scan, http_method_scan, ssl_tls_scan,\
    cors_scan, ffuf, libraries_scan, bucket_finder, token_scan, css_scan,\
    firebase_scan, nmap_script_scan,nmap_script_baseline, host_header_attack, \
    iis_shortname_scanner, burp_scan, nessus_scan, acunetix_scan
from VM_Orchestrator.settings import settings
from VM_OrchestratorApp.src.utils import mongo, slack, redmine

# ------ RECON ------ #
@shared_task
def subdomain_recon_task(scan_info):
    initial_recon.run_recon(scan_info)
    return

@shared_task
def resolver_recon_task(scan_info):
    subdomains = mongo.get_alive_subdomains_from_target(scan_info['domain'])
    aquatone.start_aquatone(subdomains, scan_info)
    return

# ------ SCANNING TASKS ------ #
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

# ------ PREDEFINED TASKS ------ #
@shared_task
def run_recon(scan_information):
    slack.send_notification_to_channel('Starting recon against %s' % scan_information['domain'], '#vm-recon-module')
    subdomain_recon_task(scan_information)
    resolver_recon_task(scan_information)
    recon_finished(scan_information)
    return

### WEB SCANS ###
@shared_task
def run_web_scanners(scan_information):
    # Deep copy just in case
    web_information = copy.deepcopy(scan_information)

    if web_information['type'] == 'domain':
        web_information['scan_type'] = 'target'
        subdomains_http = mongo.get_responsive_http_resources(web_information['domain'])
        only_urls = list()
        for subdomain in subdomains_http:
            only_urls.append(subdomain['url_with_http'])
        web_information['url_to_scan'] = only_urls
    # Single url case
    else:
        web_information['scan_type'] = 'single'
        web_information['url_to_scan'] = web_information['domain']
        web_information['domain'] = web_information['domain'].split('/')[2]
        mongo.add_simple_url_resource(web_information)

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

### IP SCANS ###
@shared_task
def run_ip_scans(scan_information):
    # Deepcopy just in case
    ip_information = copy.deepcopy(scan_information)
    
    if ip_information['type'] == 'domain':
        ip_information['scan_type'] = 'target'
        subdomains_plain = mongo.get_alive_subdomains_from_target(ip_information['domain'])
        only_subdomains = list()
        for subdomain in subdomains_plain:
            only_subdomains.append(subdomain['subdomain'])
        ip_information['url_to_scan'] = only_subdomains
    else:
        ip_information['scan_type'] = 'single'
        if ip_information['type'] == 'ip':
            ip_information['url_to_scan'] = ip_information['domain']
            mongo.add_simple_ip_resource(ip_information)
        else:
            #We can scan an url for IP things, we just use the hostname, resource will be added before
            ip_information['url_to_scan'] = ip_information['domain'].split('/')[2]

    # We will flag the resource as scanned here, mainly because all alive resources will reach this point
    execution_chord = chord(
        [
            nmap_script_baseline_task.s(ip_information).set(queue='slow_queue'),
            nmap_script_scan_task.s(ip_information).set(queue='slow_queue'),
            nessus_scan_task.s(ip_information).set(queue='slow_queue'),
            add_scanned_resources.s(ip_information).set(queue='fast_queue')
        ],
        body=ip_security_scan_finished.s().set(queue='fast_queue'),
        immutable=True)
    execution_chord.apply_async(queue='fast_queue', interval=60)
    return

# ------ END ALERTS ------ #
@shared_task
def on_demand_scan_finished(results, information):
    if information['email'] is None:
        print('On demand scan finished!')
        return
    # TODO REMOVE Send email with scan results
    mongo.update_elasticsearch()
    vulnerabilities = mongo.get_vulnerabilities_for_email(information)
    df = pd.DataFrame(vulnerabilities)
    if df.empty:
        print('No vulns found! Canceling email')
        return
    from VM_OrchestratorApp.src.utils import email_handler
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    df.to_csv(ROOT_DIR + '/output.csv', index=False, columns=['domain', 'subdomain', 'vulnerability_name', 'extra_info',
    'date_found', 'last_seen', 'language', 'state'])
    email_handler.send_email(ROOT_DIR+'/output.csv', information['email'], "CSV with vulnerabilities attached to email",
    "Orchestrator: Vulnerabilities found!")
    try:
        os.remove(ROOT_DIR + '/output.csv')
    except FileNotFoundError:
        print('ERROR:Output for on demand scan was not found')
        pass
    slack.send_notification_to_channel('_ On demand scan against %s finished! _' % information['domain'], '#vm-ondemand')
    print('On demand scan finished!')
    return

@shared_task
def web_security_scan_finished(results):
    print('Web security scan finished!')
    return

@shared_task
def ip_security_scan_finished(results):
    print('IP security scan finished!')
    return

@shared_task
def recon_finished(scan_information):
    if scan_information['email'] is None:
        print('Recon finished!')
        return
    # TODO REMOVE Send email with scan results
    resources = mongo.get_resources_for_email(scan_information)
    df = pd.DataFrame(resources)
    if df.empty:
        print('No resources found! Canceling email')
        return
    from VM_OrchestratorApp.src.utils import email_handler
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    df.to_csv(ROOT_DIR + '/output.csv', index=False, columns=['domain', 'subdomain', 'is_alive', 'ip',
    'has_urls', 'responsive_urls', 'first_seen', 'last_seen', 'scanned', 'type', 'priority', 'exposition'])
    email_handler.send_email(ROOT_DIR+'/output.csv', scan_information['email'], "CSV with resources attached to email",
    "Orchestrator: Resources found!")
    try:
        os.remove(ROOT_DIR + '/output.csv')
    except FileNotFoundError:
        print('ERROR Output file for resources was not found')
        pass
    slack.send_notification_to_channel('_ Recon against %s finished _' % scan_information['domain'], '#vm-recon-module')
    print('Recon finished!')
    return

# ------ MONITOR TOOLS ------ #
@shared_task
def add_scanned_resources(resource_list):
    mongo.add_scanned_resources(resource_list)
    return

# ------ PERIODIC TASKS ------ #
#@periodic_task(run_every=crontab(day_of_month=settings['PROJECT']['START_DATE'].day, month_of_year=settings['PROJECT']['START_DATE'].month),
#queue='slow_queue', options={'queue': 'slow_queue'})
#@periodic_task(run_every=crontab(hour=12, minute=12),
#queue='slow_queue', options={'queue': 'slow_queue'})
def project_start_task():
    today_date = datetime.combine(date.today(), datetime.min.time())
    # This will make it so the tasks only runs once in the program existence
    if(today_date.year != settings['PROJECT']['START_DATE'].year):
       return
       
    df = pd.read_csv(settings['PROJECT']['START_FILE'])
    input_data = df.to_dict('records')

    for data in input_data:
        scan_info = {
        'is_first_run': True,
        'invasive_scans': False,
        'nessus_scan': False,
        'acunetix_scan': False,
        'language': 'eng'
        }
        scan_info['type'] = data['Type']
        scan_info['priority'] = data['Priority']
        scan_info['exposition'] = data['Exposition']
        scan_info['domain'] = data['Resource']

        if scan_info['type'] == 'domain':
            run_recon(scan_info)
            run_web_scanners(scan_info)
            run_ip_scans(scan_info)
        elif scan_info['type'] == 'ip':
            run_ip_scans(scan_info)
        elif scan_info['type'] == 'url':
            run_web_scanners(scan_info)
            run_ip_scans(scan_info)

    return


#@periodic_task(run_every=crontab(hour=settings['PROJECT']['HOUR'], minute=settings['PROJECT']['MINUTE'], day_of_week=settings['PROJECT']['DAY_OF_WEEK']))
#@periodic_task(run_every=crontab(hour=4, minute=0),
#queue='slow_queue', options={'queue': 'slow_queue'})
def project_monitor_task():
    
    # We first check if the project has started, we return if not
    today_date = datetime.combine(date.today(), datetime.min.time())
    if today_date < settings['PROJECT']['START_DATE']:
        return
    
    # The idea is similar to the project start, we just need to ge the same information from our database.

    monitor_data = mongo.get_data_for_monitor()

    for data in monitor_data:
        scan_info = data
        scan_info['email'] = None
        scan_info['nessus_scan'] = False
        scan_info['acunetix_scan'] = False
        slack.send_notification_to_channel('Starting monitor against %s' % scan_info['domain'], '#vm-monitor')
        if scan_info['type'] == 'domain':
            run_recon(scan_info)
            run_web_scanners(scan_info)
            run_ip_scans(scan_info)
        elif scan_info['type'] == 'ip':
            run_ip_scans(scan_info)
        elif scan_info['type'] == 'url':
            #TODO This will be fixed with the name rework
            scan_info['domain'] = scan_info['url_to_scan']
            run_web_scanners(scan_info)
            run_ip_scans(scan_info)
    
    return

#@periodic_task(run_every=crontab(hour=0, minute=0),
#queue='slow_queue', options={'queue': 'slow_queue'})
def check_redmine_for_updates():
    issues = redmine.get_issues_from_project()
    for issue in issues:
        mongo.update_issue_if_needed(issue)
    return

@periodic_task(run_every=crontab(minute='*/15'),
queue='fast_queue', options={'queue':'slow_queue'})
def update_elasticsearch():
    mongo.update_elasticsearch()