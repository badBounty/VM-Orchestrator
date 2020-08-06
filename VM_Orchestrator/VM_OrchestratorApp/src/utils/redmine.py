# pylint: disable=import-error
from VM_Orchestrator.settings import settings, redmine_client
from VM_Orchestrator.settings import REDMINE_IDS

import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_issues_from_project():
    if redmine_client is None:
        return []
    return redmine_client.issue.filter(project_id=settings['REDMINE']['project_name'])

def issue_already_exists(vulnerability):
    issues = redmine_client.issue.filter(project_id=settings['REDMINE']['project_name'])
    for issue in issues:
        if(vulnerability.vulnerability_name == issue.subject and
            vulnerability.domain == issue.custom_fields.get(REDMINE_IDS['RESOURCE']).value and
            vulnerability.target == issue.custom_fields.get(REDMINE_IDS['SUB_RESOURCE']).value):
            # This means the issue already exists in redmine. We will update the description and last seen
            redmine_client.issue.update(issue.id, description=vulnerability.custom_description,
            custom_fields=[{'id': REDMINE_IDS['RESOURCE'], 'value': vulnerability.domain},
            {'id': REDMINE_IDS['SUB_RESOURCE'], 'value': vulnerability.target},
            {'id': REDMINE_IDS['LAST_SEEN'], 'value': str(vulnerability.time.strftime("%Y-%m-%d"))}])
            return True
    return False

def create_new_issue(vulnerability):
    if redmine_client is None:
        return
    if issue_already_exists(vulnerability):
        return
    issue = redmine_client.issue.new()
    issue.project_id = settings['REDMINE']['project_name']
    issue.subject = vulnerability.vulnerability_name
    issue.tracker_id = REDMINE_IDS['FINDING_TRACKER']
    issue.description = vulnerability.custom_description
    issue.status_id = vulnerability.status
    issue.priority_id = vulnerability.resolve_priority()
    issue.assigned_to_id = REDMINE_IDS['ASSIGNED_USER']
    issue.watcher_user_ids = REDMINE_IDS['WATCHERS']
    issue.custom_fields= [{'id': REDMINE_IDS['RESOURCE'], 'value': vulnerability.domain},
     {'id': REDMINE_IDS['SUB_RESOURCE'], 'value': vulnerability.target},
    {'id': REDMINE_IDS['DATE_FOUND'], 'value': str(vulnerability.time.strftime("%Y-%m-%d"))},
    {'id': REDMINE_IDS['LAST_SEEN'], 'value': str(vulnerability.time.strftime("%Y-%m-%d"))},
    {'id': REDMINE_IDS['CVSS_SCORE'], 'value': vulnerability.cvss}]
    if vulnerability.attachment_path is not None:
        issue.uploads = [{'path': vulnerability.attachment_path,
                          'filename': vulnerability.attachment_name}]
    try:
        issue.save()
    except Exception as e:
        print("Redmine error" + str(e))
        pass