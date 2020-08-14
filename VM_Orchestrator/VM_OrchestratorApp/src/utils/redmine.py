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
            vuln.domain == issue.custom_fields.get(REDMINE_IDS['WEB_FINDING']['DOMAIN']).value and
            vuln.target == issue.custom_fields.get(REDMINE_IDS['WEB_FINDING']['RESOURCE']).value):
            # This means the issue already exists in redmine. We will update the description and last seen
            redmine_client.issue.update(issue.id, description=vuln.custom_description,
            custom_fields=[{'id': REDMINE_IDS['WEB_FINDING']['DOMAIN'], 'value': vuln.domain},
            {'id': REDMINE_IDS['WEB_FINDING']['RESOURCE'], 'value': vuln.target},
            {'id': REDMINE_IDS['WEB_FINDING']['LAST_SEEN'], 'value': str(vuln.time.strftime("%Y-%m-%d"))}])
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
    issue.tracker_id = REDMINE_IDS['WEB_FINDING']['FINDING_TRACKER']
    issue.description = vuln.custom_description
    issue.status_id = vuln.status
    issue.priority_id = vuln.resolve_priority()
    issue.assigned_to_id = REDMINE_IDS['ASSIGNED_USER']
    issue.watcher_user_ids = REDMINE_IDS['WATCHERS']
    issue.custom_fields= [{'id': REDMINE_IDS['WEB_FINDING']['DOMAIN'], 'value': vuln.domain},
     {'id': REDMINE_IDS['WEB_FINDING']['RESOURCE'], 'value': vuln.target},
    {'id': REDMINE_IDS['WEB_FINDING']['DATE_FOUND'], 'value': str(vuln.time.strftime("%Y-%m-%d"))},
    {'id': REDMINE_IDS['WEB_FINDING']['LAST_SEEN'], 'value': str(vuln.time.strftime("%Y-%m-%d"))},
    {'id': REDMINE_IDS['WEB_FINDING']['CVSS_SCORE'], 'value': vuln.cvss}]
    if vuln.attachment_path is not None:
        issue.uploads = [{'path': vuln.attachment_path,
                          'filename': vuln.attachment_name}]
    try:
        issue.save()
    except Exception as e:
        print("Redmine error" + str(e))
        pass

# This should not be used
def force_add_vulnerability(vuln):
    severity_dict = {'INFORMATIONAL': REDMINE_IDS['SEVERITY']['INFORMATIONAL'],
     'LOW': REDMINE_IDS['SEVERITY']['LOW'], 'MEDIUM': REDMINE_IDS['SEVERITY']['MEDIUM'],
      'HIGH': REDMINE_IDS['SEVERITY']['HIGH'], 'CRITICAL': REDMINE_IDS['SEVERITY']['CRITICAL']}
    if redmine_client is None:
        return
    issue = redmine_client.issue.new()
    issue.project_id = settings['REDMINE']['project_name']
    issue.subject = vuln['vulnerability_name']
    issue.tracker_id = REDMINE_IDS['WEB_FINDING']['FINDING_TRACKER']
    issue.description = vuln['extra_info']
    issue.status_id = REDMINE_IDS['STATUS_NEW']
    try:
        issue.priority_id = severity_dict[vuln['observation']['severity']]
    except (KeyError,AttributeError):
        issue.priority_id = REDMINE_IDS['SEVERITY']['MEDIUM']

    issue.assigned_to_id = REDMINE_IDS['ASSIGNED_USER']
    issue.watcher_user_ids = REDMINE_IDS['WATCHERS']
    issue.custom_fields= [{'id': REDMINE_IDS['WEB_FINDING']['DOMAIN'], 'value': vuln['domain']},
     {'id': REDMINE_IDS['WEB_FINDING']['RESOURCE'], 'value': vuln['resource']},
    {'id': REDMINE_IDS['WEB_FINDING']['DATE_FOUND'], 'value': str(vuln['date_found'].strftime("%Y-%m-%d"))},
    {'id': REDMINE_IDS['WEB_FINDING']['LAST_SEEN'], 'value': str(vuln['last_seen'].strftime("%Y-%m-%d"))},
    {'id': REDMINE_IDS['WEB_FINDING']['CVSS_SCORE'], 'value': vuln['cvss_score']}]
    try:
        issue.save()
    except Exception as e:
        print("Redmine error" + str(e))
        pass
