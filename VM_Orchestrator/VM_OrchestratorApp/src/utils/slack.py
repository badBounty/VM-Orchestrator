from VM_Orchestrator.settings import settings
from VM_OrchestratorApp import INTERNAL_SLACK_WEB_CLIENT, EXTERNAL_SLACK_WEB_CLIENT

def send_simple_message(message):
    if INTERNAL_SLACK_WEB_CLIENT is not None:
        INTERNAL_SLACK_WEB_CLIENT.chat_postMessage(channel=settings['SLACK']['INTERNAL_SLACK_CHANNEL'], text=str(message))
       
def send_vulnerability(vulnerability):
    return
    if INTERNAL_SLACK_WEB_CLIENT is not None:
        message = 'Found vulnerability %s at %s from resource %s. \n %s' % \
         (vulnerability.vulnerability_name, vulnerability.scanned_url, vulnerability.target, vulnerability.custom_description)
        INTERNAL_SLACK_WEB_CLIENT.chat_postMessage(channel=settings['SLACK']['INTERNAL_SLACK_CHANNEL'], text=str(message))
        
def send_new_resource_found(msg):
    if INTERNAL_SLACK_WEB_CLIENT is not None:
        INTERNAL_SLACK_WEB_CLIENT.chat_postMessage(channel=settings['SLACK']['INTERNAL_SLACK_CHANNEL'], text=str(msg))
    if EXTERNAL_SLACK_WEB_CLIENT is not None:
        EXTERNAL_SLACK_WEB_CLIENT.chat_postMessage(channel=settings['SLACK']['EXTERNAL_SLACK_CHANNEL'], text=str(msg))

# Information will contain something along the lines of {'resource': domain_name, 'type': 'domain'}
# Can also be something like {'resource': '127.0.0.1', 'type': 'ip'}
def send_recon_start_notification(information):
    if INTERNAL_SLACK_WEB_CLIENT is not None:
        INTERNAL_SLACK_WEB_CLIENT.chat_postMessage(channel=settings['SLACK']['INTERNAL_SLACK_CHANNEL'], text="Recon started against %s!" % information['domain'])
    if EXTERNAL_SLACK_WEB_CLIENT is not None:
        EXTERNAL_SLACK_WEB_CLIENT.chat_postMessage(channel=settings['SLACK']['EXTERNAL_SLACK_CHANNEL'], text="Recon started against %s!" % information['domain'])


# The idea here is to send something the client can verify
def send_recon_end_notification():
    if INTERNAL_SLACK_WEB_CLIENT is not None:
        INTERNAL_SLACK_WEB_CLIENT.chat_postMessage(channel=settings['SLACK']['INTERNAL_SLACK_CHANNEL'], text="Recon ended!")
    if EXTERNAL_SLACK_WEB_CLIENT is not None:
        EXTERNAL_SLACK_WEB_CLIENT.chat_postMessage(channel=settings['SLACK']['EXTERNAL_SLACK_CHANNEL'], text="Recon ended!")


def send_monitor_recon_start_notification():
    if INTERNAL_SLACK_WEB_CLIENT is not None:
        INTERNAL_SLACK_WEB_CLIENT.chat_postMessage(channel=settings['SLACK']['INTERNAL_SLACK_CHANNEL'], text="Monitor recon started!")
    
def send_monitor_scan_start_notification():
    if INTERNAL_SLACK_WEB_CLIENT is not None:
        INTERNAL_SLACK_WEB_CLIENT.chat_postMessage(channel=settings['SLACK']['INTERNAL_SLACK_CHANNEL'], text="Monitor scan started!")


def send_project_start_recon_start_notification():
    if INTERNAL_SLACK_WEB_CLIENT is not None:
        INTERNAL_SLACK_WEB_CLIENT.chat_postMessage(channel=settings['SLACK']['INTERNAL_SLACK_CHANNEL'], text="Project started, executing recon...")
    
def send_project_start_scan_start_notification():
    if INTERNAL_SLACK_WEB_CLIENT is not None:
        INTERNAL_SLACK_WEB_CLIENT.chat_postMessage(channel=settings['SLACK']['INTERNAL_SLACK_CHANNEL'], text="Starting vuln scan against found resources")