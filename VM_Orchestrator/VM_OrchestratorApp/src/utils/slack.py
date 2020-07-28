# pylint: disable=import-error
from VM_Orchestrator.settings import settings
from VM_OrchestratorApp import INTERNAL_SLACK_WEB_CLIENT

def send_notification_to_channel(message, channel):
    if INTERNAL_SLACK_WEB_CLIENT is not None:
        try:
            INTERNAL_SLACK_WEB_CLIENT.chat_postMessage(channel=channel, text=message)
        except Exception as e:
            print("Slack error" + str(e))
            
def send_module_start_notification_to_channel(scan_info, module_name, channel):
    if scan_info['scan_type'] == 'target':
        message = "_ %s started against target: %s. %d alive resources found _" \
        % (module_name, scan_info['domain'], len(scan_info['target']))
    else:
        message = "_ %s started against %s _" % (module_name, scan_info['domain'])

    if INTERNAL_SLACK_WEB_CLIENT is not None:
        try:
            INTERNAL_SLACK_WEB_CLIENT.chat_postMessage(channel=channel, text=message)
        except Exception as e:
            print("Slack error" + str(e))

def send_module_end_notification_to_channel(scan_info, module_name, channel):
    if scan_info['scan_type'] == 'target':
        message = "_ %s finished against target: %s. %d alive resources were found _" \
        % (module_name, scan_info['domain'], len(scan_info['target']))
    else:
        message = "_ %s finished against %s _" % (module_name, scan_info['domain'])

    if INTERNAL_SLACK_WEB_CLIENT is not None:
        try:
            INTERNAL_SLACK_WEB_CLIENT.chat_postMessage(channel=channel, text=message)
        except Exception as e:
            print("Slack error" + str(e))

def send_error_to_channel(message, channel):
    if INTERNAL_SLACK_WEB_CLIENT is not None:
        try:
            INTERNAL_SLACK_WEB_CLIENT.chat_postMessage(channel=channel, text='*Error found*\n'+'* '+message+' *')
        except Exception as e:
            print("Slack error" + str(e))

def send_vuln_to_channel(vulnerability, channel):
    if INTERNAL_SLACK_WEB_CLIENT is not None:
        try:
            message = 'Found vulnerability \" %s \" at %s from resource %s. \n %s' % \
            (vulnerability.vulnerability_name, vulnerability.target, vulnerability.domain, vulnerability.custom_description)
            INTERNAL_SLACK_WEB_CLIENT.chat_postMessage(channel=channel, text=message)
        except Exception as e:
            print("Slack error" + str(e))

def send_new_resource_found(msg, channel):
    from VM_OrchestratorApp.src.recon.initial_recon import 
    if INTERNAL_SLACK_WEB_CLIENT is not None:
        try:
            INTERNAL_SLACK_WEB_CLIENT.chat_postMessage(channel=channel, text=str(msg))
        except Exception as e:
            print("Slack error" + str(e))