from django.shortcuts import render
from django.http import JsonResponse

import VM_OrchestratorApp.tasks as tasks
import VM_OrchestratorApp.src.utils.mongo as mongo

from VM_Orchestrator.settings import settings

from celery import chain
from datetime import datetime, date

import VM_OrchestratorApp.src.task_manager as manager

# Create your views here.
def index(request):
    return render(request, 'base.html')

def project_start(request):
    info_to_send = {
        'domain': 'tesla.com',
        'is_first_run': False,
        'scan_type': 'target',
        'invasive_scans': False,
        'language': 'eng'
    }
    #manager.recon_task_manager(info_to_send)
    manager.test_vuln_scan(info_to_send)
    return JsonResponse({'data':'Hi'})
