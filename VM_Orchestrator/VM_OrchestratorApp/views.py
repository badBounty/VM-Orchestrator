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
    "domain": "example.com",
    "resource": "https://example.com/",
    "invasive_scans": false,
    "nessus_scan": false,
    "acunetix_scan": false,
    "type": "url",
    "priority": 1,
    "exposition": 0,
    "email": "mananderson@deloitte.com"
}
{
    "domain": "example.com",
    "resource": "127.0.0.1",
    "invasive_scans": false,
    "nessus_scan": false,
    "acunetix_scan": false,
    "type": "ip",
    "priority": 1,
    "exposition": 0,
    "email": "mananderson@deloitte.com"
}
{
    "domain": "example.com",
    "resource": "",
    "invasive_scans": false,
    "nessus_scan": false,
    "acunetix_scan": false,
    "type": "domain",
    "priority": 1,
    "exposition": 0,
    "email": "mananderson@deloitte.com"
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
