# pylint: disable=import-error
from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponseRedirect
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

import VM_OrchestratorApp.tasks as tasks
import VM_OrchestratorApp.src.utils.mongo as mongo
import VM_OrchestratorApp.forms as available_forms

from VM_Orchestrator.settings import settings

from celery import chain
import json
from datetime import datetime, date

import VM_OrchestratorApp.src.task_manager as manager
from VM_OrchestratorApp.src.utils import utils

import VM_OrchestratorApp.tasks as tasks

### VIEWS ###
def index(request):
    return render(request, 'base.html')

def test_html(request):
    return render(request, 'testbase.html')

def current_resources(request):
    resources = mongo.get_all_resources()
    if request.method == 'POST':
        response = utils.get_resources_csv_file(resources)
        return response
    return render(request, 'database_resources.html', {'object_list': resources})

def new_resource(request):
    return JsonResponse({'order': 'new_resource. TODO'})

def approve_resources_beta(request):
    if request.method == 'POST':
        form = available_forms.ApproverForm(request.POST, request.FILES)
        if form.is_valid():
            manager.handle_uploaded_file(request.FILES['file'])
            return HttpResponseRedirect('/')
    else:
        form = available_forms.ApproverForm()
    return render(request, 'approve.html', {'form': form})

def current_observations(request):
    resources = mongo.get_all_observations(True)
    if request.method == 'POST':
        response = utils.get_observations_csv_file(resources)
        return response
    return render(request, 'observations.html', {'object_list': resources})

def specific_observation(request, mongo_id):
    resource = mongo.get_specific_observation(mongo_id)
    if request.method == 'POST':
        form = available_forms.ObservationForm(request.POST)
        if form.is_valid():
            mongo.update_observation(form.cleaned_data, resource)
            return redirect('/current_observations/')
    form = available_forms.ObservationForm()
    form.populate(resource)
    return render(request, 'specific_observation.html', {'form': form})
    
# Testing
def domains(request):
    resources = mongo.get_domains()
    return render(request, 'domains.html', {'object_list': resources})


def current_vulnerabilities(request):
    return render(request, 'vulns_type.html')

def web_vulnerabilities(request):
    resources = mongo.get_all_web_vulnerabilities()
    if request.method == 'POST':
        response = utils.get_web_vulnerabilities_csv_file(resources)
        return response
    return render(request, 'Vulnerabilities/web_vulns.html', {'object_list': resources})

def infra_vulnerabilities(request):
    resources = mongo.get_all_infra_vulnerabilities()
    if request.method == 'POST':
        response = utils.get_infra_vulnerabilities_csv_file(resources)
        return response
    return render(request, 'Vulnerabilities/infra_vulns.html', {'object_list': resources})
    
def code_vulnerabilities(request):
    resources = mongo.get_all_code_vulnerabilities()
    if request.method == 'POST':
        response = utils.get_code_vulnerabilities_csv_file(resources)
        return response
    return render(request, 'Vulnerabilities/code_vulns.html', {'object_list': resources})

def new_vulnerability(request):
    return JsonResponse({'order': 'new_vulnerability. TODO'})

'''
{
    "domain": example.com,
    "email": "example@example.com"
}
'''

@csrf_exempt
def run_recon_against_target(request):
    if request.method == 'POST':
        json_data = json.loads(request.body)
        manager.recon_against_target(json_data)
        message = 'Recon started against %s' % json_data['domain']
        return JsonResponse({'INFO': message})
    return JsonResponse({'ERROR': 'Post is required'})

@csrf_exempt
def approve_resources(request):
    if request.method == 'POST':
        json_data = json.loads(request.body)
        manager.approve_resources(json_data)
        return JsonResponse({'INFO': 'ACCEPTED'})
    return JsonResponse({'ERROR': 'Post is required'})

@csrf_exempt
def force_update_elasticsearch(request):
    if request.method == 'POST':
        manager.force_update_elasticsearch()
        return JsonResponse({'INFO': 'Updating elasticsearch'})
    return JsonResponse({'ERROR': 'Post is required'})

@csrf_exempt
def force_update_elasticsearch_logs(request):
    if request.method == 'POST':
        manager.force_update_elasticsearch_logs()
        return JsonResponse({'INFO': 'Updating elasticsearch logs'})
    return JsonResponse({'ERROR': 'Post is required'})

@csrf_exempt
def force_redmine_sync(request):
    if request.method == 'POST':
        manager.force_redmine_sync()
        return JsonResponse({'INFO': 'Synchronizing redmine'})
    return JsonResponse({'ERROR': 'Post is required'})

'''
{
  "Title": "Unrestricted Spring's RequestMapping makes the method vulnerable to CSRF attacks",
  "Description": "Tool title \n tool description",
  "Component": "src/main/java/org/owasp/webwolf/FileServer.java",
  "Line": 25,
  "Affected_code": "string",
  "Commit": "261283c",
 "Username": "username",
  "Pipeline_name": "name",
  "Language": "spa/eng",
  "Hash": "hash",
  "Severity_tool": "Severity"
}
'''

@csrf_exempt
def add_code_vuln(request):
    if request.method == 'POST':
        json_data = json.loads(request.body, strict=False)
        manager.add_code_vuln(json_data)
        return JsonResponse({'INFO': 'Adding code vuln', 'VULN': json_data})
    return JsonResponse({'ERROR': 'Post is required'})

@csrf_exempt
def add_web_vuln(request):
    if request.method == 'POST':
        json_data = json.loads(request.body)
        manager.add_web_vuln(json_data)
        return JsonResponse({'INFO': 'Adding web vuln', 'VULN': json_data})
    return JsonResponse({'ERROR': 'Post is required'})

@csrf_exempt
def rcv_code_vuln_state(request):
    if request.method == 'POST':
        json_data = json.loads(request.body)
        manager.rcv_code_vuln_state(json_data)
        return JsonResponse({'INFO': 'Processing vuln state', 'State': json_data})
    return JsonResponse({'ERROR': 'Post is required'})


### ON DEMAND SCAN APPROVED REQUESTS ###
'''
{
    "domain": "example.com",
    "target": ["https://example.com"] ["127.0.0.1"],
    "module_identifier": "header_module"
}
'''
# Scan to run only one module
@csrf_exempt
def run_specific_module(request):
    if request.method == 'POST':
        json_data = json.loads(request.body)
        manager.run_specific_module(json_data)
        return JsonResponse({'INFO': 'Running module %s against %s from domain %s' % (json_data['module_identifier'], json_data['target'], json_data['domain'])})
    return JsonResponse({'ERROR': 'Post is required'})
'''
Will run web and ip scans against https://example.com
{
    "domain": "example.com",
    "resource": "https://example.com/",
    "invasive_scans": false,
    "nessus_scan": false,
    "acunetix_scan": false,
    "type": "url",
    "priority": 1,
    "exposition": 0,
    "email": "example@example.com"
}
Will run ip scans against 127.0.0.1, if port 80 or 443 is open, web scans will be run
{
    "domain": "example.com",
    "resource": "127.0.0.1",
    "invasive_scans": false,
    "nessus_scan": false,
    "acunetix_scan": false,
    "type": "ip",
    "priority": 1,
    "exposition": 0,
    "email": "example@example.com"
}
Will run recon agains domain example.com, each of the subdomains found will be
subjected to web and ip scans if they are alive
{
    "domain": "example.com",
    "resource": "",
    "invasive_scans": false,
    "nessus_scan": false,
    "acunetix_scan": false,
    "type": "domain",
    "priority": 1,
    "exposition": 0,
    "email": "example@example.com"
}
'''

@csrf_exempt
def on_demand_scan(request):
    if request.method == 'POST':
        received_json_data=json.loads(request.body)
        if received_json_data['domain'] == "":
            return JsonResponse({'ERROR': 'Please provide a domain for tracking'})
        manager.on_demand_scan(received_json_data)
    return JsonResponse({'data':'Hi'})
