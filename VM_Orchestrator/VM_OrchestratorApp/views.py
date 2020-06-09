from django.shortcuts import render
from django.http import JsonResponse

import VM_OrchestratorApp.tasks as tasks
import VM_OrchestratorApp.src.utils.mongo as mongo

from celery import chain

# Create your views here.
def index(request):
    return render(request, 'base.html')

def test(request):
    execution_chain = chain(
        #tasks.subdomain_recon_task.si('tesla.com').set(queue='slow_queue'),
        tasks.resolver_recon_task.si('tesla.com').set(queue='slow_queue')
    )
    #tasks.subdomain_recon_task.apply_async(args=['tesla.com'], queue='slow_queue')
    #tasks.resolver_recon_task.apply_async(args=['tesla.com'], queue='slow_queue')
    execution_chain.apply_async(queue='fast_queue', interval=300)
    return JsonResponse({'data': 'Hi'})
