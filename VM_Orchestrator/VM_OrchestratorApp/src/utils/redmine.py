# pylint: disable=import-error
from VM_Orchestrator.settings import settings, redmine_client

import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_issues_from_project():
    if redmine_client is None:
        return None
    return redmine_client.issue.filter(project_id=settings['REDMINE']['project_name'])

def issue_already_exists(vulnerability):
    issues = redmine_client.issue.filter(project_id=settings['REDMINE']['project_name'])
    for issue in issues:
        if(vulnerability.vulnerability_name == issue.subject and
            vulnerability.target == issue.custom_fields.get(1).value and
            vulnerability.scanned_url == issue.custom_fields.get(2).value):
            # This means the issue already exists in redmine. We will update the description and last seen
            redmine_client.issue.update(issue.id, description=vulnerability.custom_description,
            custom_fields=[{'id': 1, 'value': vulnerability.domain},
            {'id': 2, 'value': vulnerability.target},
            {'id':9, 'value': str(vulnerability.time.strftime("%Y-%m-%d"))}])
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
    issue.tracker_id = 4
    issue.description = vulnerability.custom_description
    issue.status_id = vulnerability.status
    issue.priority_id = vulnerability.resolve_priority()
    issue.assigned_to_id = 5
    issue.watcher_user_ids = [5]
    # [1]: Resource
    # [2]: Sub_resource
    # [8]: Date Found
    # [9]: Last seen
    issue.custom_fields= [{'id': 1, 'value': vulnerability.domain},
     {'id': 2, 'value': vulnerability.target},
    {'id':8, 'value': str(vulnerability.time.strftime("%Y-%m-%d"))},
    {'id':9, 'value': str(vulnerability.time.strftime("%Y-%m-%d"))}]
    if vulnerability.attachment_path is not None:
        issue.uploads = [{'path': vulnerability.attachment_path,
                          'filename': vulnerability.attachment_name}]
    try:
        issue.save()
    except Exception as e:
        print("Redmine error" + str(e))
        pass