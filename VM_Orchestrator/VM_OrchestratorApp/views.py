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
        'target_name': 'tesla.com'
    }
    manager.recon_task_manager(info_to_send)
    return JsonResponse({'data':'Hi'})
