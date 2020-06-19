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

# Create your views here.
def index(request):
    return render(request, 'base.html')

@csrf_exempt
def on_demand_scan(request):
    if request.method == 'POST':
        received_json_data=json.loads(request.body)
        print(received_json_data)
        manager.on_demand_scan(received_json_data)
    return JsonResponse({'data':'Hi'})
