# pylint: disable=import-error
import VM_OrchestratorApp.tasks as tasks
from VM_OrchestratorApp.src.utils import slack, mongo
import VM_OrchestratorApp.tasks as tasks

from celery import chain, chord

import copy
import pandas as pd
import os
from VM_Orchestrator.settings import settings

def recon_against_target(information):
    information['is_first_run'] = True
    information['type'] = 'domain'

    slack.send_notification_to_channel('_ Starting recon only scan against %s _' % str(information['domain']), '#vm-ondemand')
    mongo.add_module_status_log({
        'module_keyword': "on_demand_recon_module",
        'state': "start",
        'domain': None, #En los casos de start/stop de genericos, va None
        'found': None,
        'arguments': information
    })
    
    for domain in information['domain']:
        current_scan_info = copy.deepcopy(information)
        current_scan_info['domain'] = domain
        execution_chain = chain(
            tasks.run_recon.si(current_scan_info).set(queue='slow_queue')
        )
        execution_chain.apply_async(queue='fast_queue', interval=300)

def handle_uploaded_file(f):
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    OUTPUT_DIR = ROOT_DIR+'/scanning/tools_output/output.csv'
    with open(OUTPUT_DIR, 'wb+') as destination:
        for chunk in f.chunks():
            destination.write(chunk)

    data = pd.read_csv(OUTPUT_DIR)
    data['priority'] = data['priority'].fillna(0)
    data['exposition'] = data['exposition'].fillna(0)
    data['asset_value'] = data['asset_value'].fillna(0)

    resources_list = list()
    for index, row in data.iterrows():
        res = {
            'domain': row['domain'],
            'subdomain': row['subdomain'],
            'url': row['url'],
            'ip': row['ip'],
            'isp': row['isp'],
            'asn': row['asn'],
            'country': row['country'],
            'region': row['region'],
            'city': row['city'],
            'org': row['org'],
            'geoloc': row['geoloc'],
            'first_seen': row['first_seen'],
            'last_seen': row['last_seen'],
            'is_alive': row['is_alive'],
            'has_urls': row['has_urls'],
            'approved': row['approved'],
            'scanned': row['scanned'],
            'type': row['type'],
            'priority': row['priority'],
            'exposition': row['exposition'],
            'asset_value': row['asset_value']
            }
        resources_list.append(res)
    data = {'data': resources_list}
    approve_resources(data)
    os.remove(OUTPUT_DIR)
    

def approve_resources(information):
    execution_chain = chain(
        tasks.approve_resources.si(information).set(queue='fast_queue')
    )
    execution_chain.apply_async(queue='fast_queue', interval=300)
    return

def force_update_elasticsearch():
    slack.send_notification_to_channel('_ Forcing update on elasticsearch... _', '#vm-ondemand')
    execution_chain = chain(
        tasks.update_elasticsearch.si().set(queue='fast_queue')
    )
    execution_chain.apply_async(queue='fast_queue', interval=300)

def force_update_elasticsearch_logs():
    slack.send_notification_to_channel('_ Forcing update on elasticsearch... _', '#vm-ondemand')
    execution_chain = chain(
        tasks.update_elasticsearch_logs.si().set(queue='fast_queue')
    )
    execution_chain.apply_async(queue='fast_queue', interval=300)

def add_code_vuln(data):
    execution_chain = chain(
        tasks.add_code_vuln.si(data).set(queue='fast_queue')
    )
    execution_chain.apply_async(queue='fast_queue', interval=300)

def rcv_code_vuln_state(data):
    execution_chain = chain(
        tasks.rcv_code_vuln_state.si(data).set(queue='fast_queue')
    )
    execution_chain.apply_async(queue='fast_queue', interval=300)

def force_redmine_sync():
    slack.send_notification_to_channel('_ Forcing redmine sync... _', '#vm-ondemand')
    execution_chain = chain(
        tasks.check_redmine_for_updates.si().set(queue='fast_queue')
    )
    execution_chain.apply_async(queue='fast_queue', interval=300)

def run_specific_module(information):
    print("before run_specific_module")
    execution_chain = chain(
        tasks.run_specific_module.si(information).set(queue='fast_queue')
    )
    execution_chain.apply_async(queue='fast_queue', interval=300)

def on_demand_scan(information):

    information['is_first_run'] = True
    information['language'] = settings['LANGUAGE']

    # The "Information" argument on chord body is temporary

    if information['type'] == 'domain':
        slack.send_notification_to_channel('_ Starting on demand scan of type domain against %s _' % information['domain'], '#vm-ondemand')
        execution_chain = chain(
            tasks.run_recon.si(information).set(queue='slow_queue'),
            chord(
                [
                    tasks.run_web_scanners.si(information).set(queue='fast_queue'),
                    tasks.run_ip_scans.si(information).set(queue='slow_queue')
                ],
                body=tasks.on_demand_scan_finished.s(information).set(queue='fast_queue'),
                immutable = True
            )
        )
        execution_chain.apply_async(queue='fast_queue', interval=300)
    elif information['type'] == 'ip':
        slack.send_notification_to_channel('_ Starting on demand scan of type ip against %s _' % information['target'], '#vm-ondemand')
        execution_chord = chord(
                [
                    tasks.run_ip_scans.si(information).set(queue='slow_queue')
                ],
                body=tasks.on_demand_scan_finished.s(information).set(queue='fast_queue'),
                immutable = True
            )
        execution_chord.apply_async(queue='fast_queue', interval=300)
    elif information['type'] == 'url':
        slack.send_notification_to_channel('_ Starting on demand scan of type url against %s _' % information['target'], '#vm-ondemand')
        execution_chord = chord(
                [
                    tasks.run_web_scanners.si(information).set(queue='fast_queue'),
                    tasks.run_ip_scans.si(information).set(queue='slow_queue')
                ],
                body=tasks.on_demand_scan_finished.s(information).set(queue='fast_queue'),
                immutable = True
            )
        execution_chord.apply_async(queue='fast_queue', interval=300)