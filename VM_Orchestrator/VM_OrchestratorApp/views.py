# pylint: disable=import-error
from django.shortcuts import render
from django.http import JsonResponse, HttpResponseRedirect
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

import VM_OrchestratorApp.tasks as tasks
import VM_OrchestratorApp.src.utils.mongo as mongo

from VM_Orchestrator.settings import settings

from celery import chain
import json
from datetime import datetime, date

import VM_OrchestratorApp.src.task_manager as manager

import VM_OrchestratorApp.tasks as tasks

### VIEWS ###
def index(request):
    return render(request, 'base.html')

def activos(request):
    return render(request, 'activos.html')

def vulns(request):
    return render(request, 'vulns.html')

def test_html(request):
    return render(request, 'testbase.html')
#
def current_resources(request):
    return JsonResponse({'order': 'current_resources. TODO'})
def new_resource(request):
    return JsonResponse({'order': 'new_resource. TODO'})
def current_vulnerabilities(request):
    return JsonResponse({'order': 'current_vulnerabilities. TODO'})
def new_vulnerability(request):
    return JsonResponse({'order': 'new_vulnerability. TODO'})

### WARNING. ONLY TO BE USED IF MONGO CONTAINS NON-SCANNABLE VULNS
## This will not check if vulns already exist, it is a way of starting out a project
@csrf_exempt
def add_mongo_vulns_to_redmine(request):
    if request.method == 'POST':
        manager.add_mongo_vulns_to_redmine()
        return JsonResponse({'INFO': 'Forcing redmine update'})
    return JsonResponse({'ERROR': 'Post is required'})
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
def get_all_resources(request):
    if request.method == 'POST':
        json_data = json.loads(request.body)
        manager.get_resources_from_target(json_data)
        message = 'Resources will be sent to %s shortly' % (json_data['email'])
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
def force_redmine_sync(request):
    if request.method == 'POST':
        manager.force_redmine_sync()
        return JsonResponse({'INFO': 'Synchronizing redmine'})
    return JsonResponse({'ERROR': 'Post is required'})

### ON DEMAND SCAN APPROVED REQUESTS ###
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
