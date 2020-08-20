# pylint: disable=import-error
import VM_OrchestratorApp.tasks as tasks
from VM_OrchestratorApp.src.utils import slack, mongo
import VM_OrchestratorApp.tasks as tasks

from celery import chain, chord

import copy
import pandas as pd
from VM_Orchestrator.settings import settings

def get_resources_from_target(information):
    execution_chain = chain(
        tasks.send_email_with_all_resources.si(information).set(queue='slow_queue')
    )
    execution_chain.apply_async(queue='fast_queue', interval=300)

def recon_against_target(information):
    information['is_first_run'] = True
    information['type'] = 'domain'

    slack.send_notification_to_channel('_ Starting recon only scan against %s _' % str(information['domain']), '#vm-ondemand')
    for domain in information['domain']:
        current_scan_info = copy.deepcopy(information)
        current_scan_info['domain'] = domain
        execution_chain = chain(
            tasks.run_recon.si(current_scan_info).set(queue='slow_queue')
        )
        execution_chain.apply_async(queue='fast_queue', interval=300)

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

def force_redmine_sync():
    slack.send_notification_to_channel('_ Forcing redmine sync... _', '#vm-ondemand')
    execution_chain = chain(
        tasks.check_redmine_for_updates.si().set(queue='fast_queue')
    )
    execution_chain.apply_async(queue='fast_queue', interval=300)

def add_mongo_vulns_to_redmine():
    execution_chain = chain(
        tasks.add_mongo_vulns_to_redmine.si().set(queue='fast_queue')
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
        slack.send_notification_to_channel('_ Starting on demand scan of type ip against %s _' % information['resource'], '#vm-ondemand')
        execution_chord = chord(
                [
                    tasks.run_ip_scans.si(information).set(queue='slow_queue')
                ],
                body=tasks.on_demand_scan_finished.s(information).set(queue='fast_queue'),
                immutable = True
            )
        execution_chord.apply_async(queue='fast_queue', interval=300)
    elif information['type'] == 'url':
        slack.send_notification_to_channel('_ Starting on demand scan of type url against %s _' % information['resource'], '#vm-ondemand')
        execution_chord = chord(
                [
                    tasks.run_web_scanners.si(information).set(queue='fast_queue'),
                    tasks.run_ip_scans.si(information).set(queue='slow_queue')
                ],
                body=tasks.on_demand_scan_finished.s(information).set(queue='fast_queue'),
                immutable = True
            )
        execution_chord.apply_async(queue='fast_queue', interval=300)