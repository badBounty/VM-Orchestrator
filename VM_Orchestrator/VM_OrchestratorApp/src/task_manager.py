import VM_OrchestratorApp.tasks as tasks
from VM_OrchestratorApp.src.utils import slack, mongo
import VM_OrchestratorApp.tasks as tasks

from celery import chain, chord
import copy

import pandas as pd
from VM_Orchestrator.settings import settings

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
    execution_chain.apply_async(queue='fast_queue')

    return


'''
information={
    'invasive_scans': True/False
    'nessus_scan' : True/False
    'type': 'domain' (Recon and scan)
            'ip'    (Single ip, will only run scan. This can also be a subdomain)
            'url'   (Single url, will only run scan (Must contain http/https))
    'priority': 'Asset priority'
    'exposition': 0 or 200
    'resource': either the domain, ip or url
}
'''
def on_demand_scan(information):

    information['is_first_run'] = False
    information['language'] = 'eng'

    if information['type'] == 'domain':
        execution_chain = chain(
            tasks.run_recon.si(information).set(queue='slow_queue'),
            chord(
                [
                    tasks.run_web_scanners.si(information).set(queue='fast_queue'),
                    tasks.run_ip_scans.si(information).set(queue='slow_queue')
                ],
                body=tasks.on_demand_scan_finished.s().set(queue='fast_queue'),
                immutable = True
            )
        )
        execution_chain.apply_async(queue='fast_queue', interval=60)
    elif information['type'] == 'ip':
        execution_chord = chord(
                [
                    tasks.run_ip_scans.si(information).set(queue='slow_queue')
                ],
                body=tasks.on_demand_scan_finished.s().set(queue='fast_queue'),
                immutable = True
            )
        execution_chord.apply_async(queue='fast_queue', interval=60)
    elif information['type'] == 'url':
        execution_chord = chord(
                [
                    tasks.run_web_scanners.si(information).set(queue='fast_queue'),
                    tasks.run_ip_scans.si(information).set(queue='slow_queue')
                ],
                body=tasks.on_demand_scan_finished.s().set(queue='fast_queue'),
                immutable = True
            )
        execution_chord.apply_async(queue='fast_queue', interval=60)