# pylint: disable=import-error
import VM_OrchestratorApp.tasks as tasks
from VM_OrchestratorApp.src.utils import slack, mongo
import VM_OrchestratorApp.tasks as tasks

from celery import chain, chord

import copy
import pandas as pd
from VM_Orchestrator.settings import settings

def on_demand_scan(information):

    information['is_first_run'] = False
    information['language'] = 'eng'

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
        slack.send_notification_to_channel('_ Starting on demand scan of type ip against %s _' % information['domain'], '#vm-ondemand')
        execution_chord = chord(
                [
                    tasks.run_ip_scans.si(information).set(queue='slow_queue')
                ],
                body=tasks.on_demand_scan_finished.s(information).set(queue='fast_queue'),
                immutable = True
            )
        execution_chord.apply_async(queue='fast_queue', interval=300)
    elif information['type'] == 'url':
        slack.send_notification_to_channel('_ Starting on demand scan of type url against %s _' % information['domain'], '#vm-ondemand')
        execution_chord = chord(
                [
                    tasks.run_web_scanners.si(information).set(queue='fast_queue'),
                    tasks.run_ip_scans.si(information).set(queue='slow_queue')
                ],
                body=tasks.on_demand_scan_finished.s(information).set(queue='fast_queue'),
                immutable = True
            )
        execution_chord.apply_async(queue='fast_queue', interval=300)