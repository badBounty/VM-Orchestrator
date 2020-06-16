import VM_OrchestratorApp.tasks as tasks
from VM_OrchestratorApp.src.utils import slack, mongo
import VM_OrchestratorApp.tasks as tasks

from celery import chain, chord
import copy

"""
{
    'domain': 'tesla.com'
}
"""
def recon_task_manager(information):
    slack.send_recon_start_notification(information)

    information['is_first_run'] = True
    execution_chain = chain(
        tasks.subdomain_recon_task.si(information).set(queue='slow_queue'),
        tasks.resolver_recon_task.si(information).set(queue='slow_queue')
    )
    execution_chain.apply_async(queue='fast_queue', interval=300)

    return


def test_vuln_scan(information):

    web_information = copy.deepcopy(information)
    ip_information = copy.deepcopy(information)

    subdomains_http = mongo.get_responsive_http_resources(information['domain'])
    only_urls = list()
    for subdomain in subdomains_http:
        only_urls.append(subdomain['url_with_http'])
    web_information['url_to_scan'] = only_urls

    #subdomains_http C subdomains_plain
    subdomains_plain = mongo.get_alive_subdomains_from_target(information['domain'])
    only_subdomains = list()
    for subdomain in subdomains_plain:
        only_subdomains.append(subdomain['subdomain'])
    ip_information['url_to_scan'] = only_subdomains
    print(ip_information)

    # Run the scan
    execution_chain = chain(
        chord(
        [
            # Fast_scans
            tasks.header_scan_task.s(web_information).set(queue='fast_queue'),
            #tasks.http_method_scan_task.s(web_information).set(queue='fast_queue'),
            #tasks.libraries_scan_task.s(web_information).set(queue='fast_queue'),
            #tasks.ffuf_task.s(web_information).set(queue='fast_queue'),
            #tasks.iis_shortname_scan_task.s(web_information).set(queue='fast_queue'),
            #tasks.bucket_finder_task.s(web_information).set(queue='fast_queue'),
            #tasks.token_scan_task.s(web_information).set(queue='fast_queue'),
            #tasks.css_scan_task.s(web_information).set(queue='fast_queue'),
            #tasks.firebase_scan_task.s(web_information).set(queue='fast_queue'),
            #tasks.host_header_attack_scan.s(web_information).set(queue='fast_queue'),
            # Slow_scans
            #tasks.cors_scan_task.s(web_information).set(queue='slow_queue'),
            #tasks.ssl_tls_scan_task.s(web_information).set(queue='slow_queue'),
            #tasks.nmap_script_baseline_task.s(ip_information).set(queue='slow_queue'),
            #tasks.nmap_script_scan_task.s(web_information).set(queue='slow_queue'),
            #tasks.burp_scan_task.s(web_information).set(queue='slow_queue'),
        ],
        body=tasks.security_scan_finished.si(),
        immutable=True),
        tasks.add_scanned_resources.si(ip_information).set(queue='fast_queue')
        )
    execution_chain.apply_async(queue='fast_queue', interval=100)
    return