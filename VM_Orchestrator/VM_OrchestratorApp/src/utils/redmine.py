# pylint: disable=import-error
from VM_Orchestrator.settings import settings, redmine_client
from VM_Orchestrator.settings import REDMINE_IDS

import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_issues_from_project():
    if redmine_client is None:
        return []
    return redmine_client.issue.filter(project_id=settings['REDMINE']['project_name'])

def issue_already_exists(vuln):
    issues = redmine_client.issue.filter(project_id=settings['REDMINE']['project_name'])
    for issue in issues:
        if(vuln.vulnerability_name == issue.subject and
            vuln.domain == issue.custom_fields.get(REDMINE_IDS['DOMAIN']).value and
            vuln.target == issue.custom_fields.get(REDMINE_IDS['RESOURCE']).value):
            # This means the issue already exists in redmine. We will update the description and last seen
            # If the status of the issue is set as resolved, we will also send an alert and change the status
            if issue.status.name == 'Remediada':
                #TODO ALERT, Remove status id hardcode!!!!!!!
                #TODO make function that checks if found vuln is flagged as rejected locally
                redmine_client.issue.update(issue.id, description=vuln.custom_description,status_id=14,
                custom_fields=[{'id': REDMINE_IDS['DOMAIN'], 'value': vuln.domain},
                {'id': REDMINE_IDS['RESOURCE'], 'value': vuln.target},
                {'id': REDMINE_IDS['LAST_SEEN'], 'value': str(vuln.time.strftime("%Y-%m-%d"))}])
                return True
            redmine_client.issue.update(issue.id, description=vuln.custom_description,
            custom_fields=[{'id': REDMINE_IDS['DOMAIN'], 'value': vuln.domain},
            {'id': REDMINE_IDS['RESOURCE'], 'value': vuln.target},
            {'id': REDMINE_IDS['LAST_SEEN'], 'value': str(vuln.time.strftime("%Y-%m-%d"))}])
            return True
    return False

def create_new_issue(vuln):
    if redmine_client is None:
        return
    if issue_already_exists(vuln):
        return
    issue = redmine_client.issue.new()
    issue.project_id = settings['REDMINE']['project_name']
    issue.subject = vuln.vulnerability_name
    issue.tracker_id = REDMINE_IDS['FINDING_TRACKER']
    issue.description = vuln.custom_description
    issue.status_id = vuln.status
    issue.priority_id = vuln.resolve_priority()
    issue.assigned_to_id = REDMINE_IDS['ASSIGNED_USER']
    issue.watcher_user_ids = REDMINE_IDS['WATCHERS']
    issue.custom_fields= [{'id': REDMINE_IDS['DOMAIN'], 'value': vuln.domain},
     {'id': REDMINE_IDS['RESOURCE'], 'value': vuln.target},
    {'id': REDMINE_IDS['DATE_FOUND'], 'value': str(vuln.time.strftime("%Y-%m-%d"))},
    {'id': REDMINE_IDS['LAST_SEEN'], 'value': str(vuln.time.strftime("%Y-%m-%d"))},
    {'id': REDMINE_IDS['CVSS_SCORE'], 'value': vuln.cvss}]
    if vuln.attachment_path is not None:
        issue.uploads = [{'path': vuln.attachment_path,
                          'filename': vuln.attachment_name}]
    try:
        issue.save()
    except Exception as e:
        print("Redmine error" + str(e))
        pass
