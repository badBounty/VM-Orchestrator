from celery import shared_task
from VM_OrchestratorApp.src.recon import initial_recon, aquatone

import VM_OrchestratorApp.src.utils.mongo as mongo

# ------------ #
@shared_task
def test_task():
    print('This is a test')
    return

@shared_task
def subdomain_recon_task(target):
    initial_recon.run_recon(target)
    return

@shared_task
def resolver_recon_task(target):
    subdomains = mongo.get_subdomains_from_target(target)
    aquatone.start_aquatone(subdomains)
    return