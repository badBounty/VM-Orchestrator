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

# Create your views here.
def index(request):
    return render(request, 'base.html')

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
def get_resources_from_target(request):
    if request.method == 'POST':
        json_data = json.loads(request.body)
        manager.get_resources_from_target(json_data)
        message = 'Resources from target %s will be sent to %s shortly' % (json_data['domain'], json_data['email'])
        return JsonResponse({'INFO': message})
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
