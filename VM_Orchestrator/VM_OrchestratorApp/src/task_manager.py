import VM_OrchestratorApp.tasks as tasks
from VM_OrchestratorApp.src.utils import slack

from celery import chain

"""
{
    'target_name': 'tesla.com'
}
"""
def recon_task_manager(information):
    slack.send_simple_message("Started first run agains %s" % information['target_name'])
    information['is_first_run'] = True
    execution_chain = chain(
        tasks.subdomain_recon_task.si(information).set(queue='slow_queue'),
        tasks.resolver_recon_task.si(information).set(queue='slow_queue')
    )
    execution_chain.apply_async(queue='fast_queue', interval=300)
    return