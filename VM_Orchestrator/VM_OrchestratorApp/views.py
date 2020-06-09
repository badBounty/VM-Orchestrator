from django.shortcuts import render
from django.http import JsonResponse

import VM_OrchestratorApp.tasks as tasks
import VM_OrchestratorApp.src.utils.mongo as mongo

# Create your views here.
def index(request):
    return render(request, 'base.html')

def test(request):
    #tasks.test_task.apply_async(queue='fast_queue')
    #mongo.add_resource()
    return JsonResponse({'data': 'Hi'})
