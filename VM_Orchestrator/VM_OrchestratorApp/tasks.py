from celery import shared_task, chain, chord
from celery.task import periodic_task
from celery.schedules import crontab

from datetime import datetime, date
import copy

from VM_OrchestratorApp.src.recon import initial_recon, aquatone
from VM_OrchestratorApp.src.scanning import header_scan, http_method_scan, ssl_tls_scan,\
    cors_scan, ffuf, libraries_scan, bucket_finder, token_scan, css_scan,\
    firebase_scan, nmap_script_scan,nmap_script_baseline, host_header_attack,iis_shortname_scanner, burp_scan
from VM_Orchestrator.settings import settings
from VM_OrchestratorApp.src.utils import mongo, slack

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
def security_scan_finished():
    print('Security scan finished!')

# ------ MONITOR TOOLS ------ #
@shared_task
def add_scanned_resources(list):
    mongo.add_scanned_resources(list)
    return

# ------ PERIODIC TASKS ------ #
#@periodic_task(run_every=crontab(day_of_month=settings['PROJECT']['START_DATE'].day, month_of_year=settings['PROJECT']['START_DATE'].month),
#queue='slow_queue', options={'queue': 'slow_queue'})
@periodic_task(run_every=crontab(hour=17, minute=30),
queue='slow_queue', options={'queue': 'slow_queue'})
def project_start_task():
    today_date = datetime.combine(date.today(), datetime.min.time())
    # This will make it so the tasks only runs once in the program existence
    if(today_date.year != settings['PROJECT']['START_DATE'].year):
       return
    
    # We will use tesla for this test run
    information = {
        'domain': 'tesla.com',
        'is_first_run': True,
        'scan_type': 'target',
        'invasive_scans': False,
        'language': 'eng'
    }
    slack.send_project_start_recon_start_notification()
    # Recon is ran agains the target/s. If new subdomains are found, they will be flagged as 'scanned': 'false'
    subdomain_recon_task(information)
    resolver_recon_task(information)

    # Deep copy just in case
    web_information = copy.deepcopy(information)
    ip_information = copy.deepcopy(information)

    # We will divide the cases in web and just ip
    # This is the web case
    subdomains_http = mongo.get_responsive_http_resources(information['domain'])
    only_urls = list()
    for subdomain in subdomains_http:
        only_urls.append(subdomain['url_with_http'])
    web_information['url_to_scan'] = only_urls

    #subdomains_http C subdomains_plain
    # Ip case
    subdomains_plain = mongo.get_alive_subdomains_from_target(information['domain'])
    only_subdomains = list()
    for subdomain in subdomains_plain:
        only_subdomains.append(subdomain['subdomain'])
    ip_information['url_to_scan'] = only_subdomains

    slack.send_project_start_scan_start_notification()
    # Chain is defined
    # We flag the scanned resources as 'scanned'
    execution_chain = chain(
        chord(
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
            #burp_scan_task.s(web_information).set(queue='slow_queue'),
            # Notice we send ip information to this scans
            nmap_script_baseline_task.s(ip_information).set(queue='slow_queue'),
            nmap_script_scan_task.s(ip_information).set(queue='slow_queue'),
            add_scanned_resources.s(ip_information).set(queue='fast_queue')
        ],
        body=security_scan_finished.si(),
        immutable=True)
        )()
    return


#@periodic_task(run_every=crontab(hour=settings['PROJECT']['HOUR'], minute=settings['PROJECT']['MINUTE'], day_of_week=settings['PROJECT']['DAY_OF_WEEK']))
@periodic_task(run_every=crontab(hour=18, minute=10),
queue='slow_queue', options={'queue': 'slow_queue'})
def project_monitor_task():
    
    # We first check if the project has started, we return if not
    today_date = datetime.combine(date.today(), datetime.min.time())
    if today_date < settings['PROJECT']['START_DATE']:
        return
    
    # We will use tesla for this test run
    information = {
        'domain': 'tesla.com',
        'is_first_run': False,
        'scan_type': 'target',
        'invasive_scans': False,
        'language': 'eng'
    }
    slack.send_monitor_recon_start_notification()
    # Recon is ran agains the target/s. If new subdomains are found, they will be flagged as 'scanned': 'false'
    subdomain_recon_task(information)
    resolver_recon_task(information)

    # Deep copy just in case
    web_information = copy.deepcopy(information)
    ip_information = copy.deepcopy(information)

    # We will divide the cases in web and just ip
    # This is the web case
    subdomains_http = mongo.get_responsive_http_resources(information['domain'])
    only_urls = list()
    for subdomain in subdomains_http:
        only_urls.append(subdomain['url_with_http'])
    web_information['url_to_scan'] = only_urls

    #subdomains_http C subdomains_plain
    # Ip case
    subdomains_plain = mongo.get_alive_subdomains_from_target(information['domain'])
    only_subdomains = list()
    for subdomain in subdomains_plain:
        only_subdomains.append(subdomain['subdomain'])
    ip_information['url_to_scan'] = only_subdomains

    slack.send_monitor_scan_start_notification()
    # Chain is defined
    # We flag the scanned resources as 'scanned'
    execution_chain = chain(
        chord(
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
            #burp_scan_task.s(web_information).set(queue='slow_queue'),
            # Notice we send ip information to this scans
            nmap_script_baseline_task.s(ip_information).set(queue='slow_queue'),
            nmap_script_scan_task.s(ip_information).set(queue='slow_queue'),
            add_scanned_resources.s(ip_information).set(queue='fast_queue')
        ],
        body=security_scan_finished.si(),
        immutable=True),
        add_scanned_resources.si(ip_information).set(queue='fast_queue')
        )()
    return